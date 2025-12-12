from __future__ import annotations

import gzip
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
from sqlmodel import Session

from clanker.config import settings
from clanker.core.agent_vuln_logic import service_rule_cpe_templates
from clanker.core.cpe import CpeGuess, CpeInferenceEngine, get_cpe_engine
from clanker.core.types import ServiceObservation
from clanker.db.models import Finding

logger = logging.getLogger(__name__)
_NVD_LAST_REQUEST: List[float] = []


@dataclass
class NvdCacheEntry:
    cve_id: str
    cvss_v31_base: Optional[float]
    cvss_vector: Optional[str]
    references: List[str]
    fetched_at: datetime
    source: str = "nvd"
    kev: bool = False
    epss: Optional[float] = None


class NvdCache:
    def __init__(self, cache_dir: Path, ttl_hours: int = 24) -> None:
        self.cache_dir = cache_dir
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace("/", "_")
        return self.cache_dir / f"{safe}.json"

    def read(self, key: str, allow_expired: bool = False) -> Optional[Dict[str, Any]]:
        p = self._path(key)
        if not p.exists():
            return None
        try:
            raw = json.loads(p.read_text())
        except Exception:
            return None
        ts = raw.get("_cached_at") or raw.get("last_enriched_at")
        if ts and not allow_expired:
            try:
                if datetime.fromisoformat(ts) < datetime.now(timezone.utc) - self.ttl:
                    return None
            except Exception:
                return None
        return raw

    def write(self, key: str, data: Dict[str, Any]) -> None:
        p = self._path(key)
        payload = dict(data)
        payload.setdefault("_cached_at", datetime.now(timezone.utc).isoformat())
        try:
            p.write_text(json.dumps(payload))
        except Exception:
            pass

    def write_entry(self, cve_id: str, entry: NvdCacheEntry) -> None:
        self.write(
            f"cve-{cve_id}",
            {
                "cve_id": entry.cve_id,
                "cvss_v31_base": entry.cvss_v31_base,
                "cvss_vector": entry.cvss_vector,
                "references": entry.references,
                "last_enriched_at": entry.fetched_at.isoformat(),
                "source": entry.source,
                "kev": bool(entry.kev),
                "epss": entry.epss,
            },
        )

    def read_entry(self, cve_id: str) -> Optional[NvdCacheEntry]:
        data = self.read(f"cve-{cve_id}")
        if not data:
            return None
        try:
            fetched_at_raw = data.get("_cached_at") or data.get("last_enriched_at")
            fetched_at = datetime.fromisoformat(fetched_at_raw) if fetched_at_raw else datetime.now(timezone.utc)
        except Exception:
            fetched_at = datetime.now(timezone.utc)
        references = data.get("references") or data.get("references_json") or []
        if isinstance(references, str):
            try:
                references = json.loads(references)
            except Exception:
                references = [references]
        references = [ref for ref in references if isinstance(ref, str)]
        return NvdCacheEntry(
            cve_id=data.get("cve_id") or cve_id,
            cvss_v31_base=data.get("cvss_v31_base"),
            cvss_vector=data.get("cvss_vector"),
            references=references,
            fetched_at=fetched_at,
            source=data.get("source") or "nvd",
            kev=bool(data.get("kev")),
            epss=data.get("epss"),
        )


def _respect_min_interval(last_request: List[float], min_interval: float = 0.6) -> None:
    now = time.time()
    if not last_request:
        last_request.append(now)
        return
    delta = now - last_request[-1]
    if delta < min_interval:
        time.sleep(min_interval - delta)
    last_request.append(time.time())
    if len(last_request) > 10:
        del last_request[:-3]


def fetch_nvd_cve(
    cache: NvdCache, cve_id: str, min_interval: Optional[float] = None, force_refresh: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Fetch a single CVE from the NVD 2.0 API with local caching.
    """
    cache_key = f"cve-detail-{cve_id}"
    cached = None if force_refresh else cache.read(cache_key)
    if cached:
        return cached

    headers = {"User-Agent": "clanker/0.2"}
    url = f"{settings.nvd_cve_api_base.rstrip('/')}/{cve_id}"
    last_request = _NVD_LAST_REQUEST
    try:
        _respect_min_interval(last_request, min_interval or settings.nvd_api_min_interval_seconds)
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                return None
            data = resp.json()
            data["_cached_at"] = datetime.now(timezone.utc).isoformat()
            cache.write(cache_key, data)
            return data
    except Exception:
        return None


def fetch_nvd_recent_feed(cache: NvdCache, min_interval: float = 0.6, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
    cache_key = "recent_feed"
    cached = None if force_refresh else cache.read(cache_key)
    if cached:
        return cached

    headers = {"User-Agent": "clanker/0.2"}
    url = settings.nvd_recent_feed_url
    last_request = _NVD_LAST_REQUEST
    try:
        _respect_min_interval(last_request, min_interval)
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                return None
            content = resp.content
            if url.endswith(".gz"):
                try:
                    content = gzip.decompress(content)
                except Exception:
                    return None
            data = json.loads(content.decode("utf-8"))
            data["_cached_at"] = datetime.now(timezone.utc).isoformat()
            cache.write(cache_key, data)
            return data
    except Exception:
        return None


def _extract_cvss_and_refs_from_feed(feed: Dict[str, Any]) -> Dict[str, Tuple[Optional[float], Optional[str], List[str]]]:
    results: Dict[str, Tuple[Optional[float], Optional[str], List[str]]] = {}
    items = feed.get("CVE_Items") or feed.get("cveItems") or []
    for item in items:
        meta = item.get("cve", {}).get("CVE_data_meta", {})
        cve_id = meta.get("ID") or meta.get("id")
        if not cve_id:
            continue
        metrics = item.get("impact", {}) or item.get("metrics", {})
        score = None
        vector = None
        if "baseMetricV3" in metrics:
            cvss = metrics.get("baseMetricV3", {}).get("cvssV3", {})
            score = cvss.get("baseScore")
            vector = cvss.get("vectorString")
        else:
            m31 = metrics.get("cvssMetricV31") if isinstance(metrics, dict) else None
            if m31 and isinstance(m31, list) and m31:
                cvd = m31[0].get("cvssData", {})
                score = cvd.get("baseScore")
                vector = cvd.get("vectorString")
        refs: List[str] = []
        refs_obj = item.get("cve", {}).get("references", {}).get("reference_data", [])
        for r in refs_obj:
            url = r.get("url")
            if url and url not in refs:
                refs.append(url)
            if len(refs) >= settings.nvd_max_reference_urls:
                break
        results[cve_id] = (score, vector, refs)
    return results


def _extract_cvss_and_refs_from_cve_detail(
    cve_detail: Dict[str, Any]
) -> Dict[str, Tuple[Optional[float], Optional[str], List[str]]]:
    """
    Parse the NVD 2.0 per-CVE response into a simplified mapping.
    """
    results: Dict[str, Tuple[Optional[float], Optional[str], List[str]]] = {}
    vulns = cve_detail.get("vulnerabilities") or cve_detail.get("Vulnerabilities") or []
    for item in vulns:
        cve_obj = item.get("cve") or {}
        cve_id = cve_obj.get("id") or cve_obj.get("CVE_data_meta", {}).get("ID")
        if not cve_id:
            continue
        metrics_obj = cve_obj.get("metrics") or {}
        score = None
        vector = None
        if "cvssMetricV31" in metrics_obj:
            m31 = metrics_obj.get("cvssMetricV31") or []
            if m31:
                cvd = m31[0].get("cvssData", {})
                score = cvd.get("baseScore")
                vector = cvd.get("vectorString")
        elif "cvssMetricV3" in metrics_obj:
            m3 = metrics_obj.get("cvssMetricV3") or []
            if m3:
                cvd = m3[0].get("cvssData", {})
                score = cvd.get("baseScore")
                vector = cvd.get("vectorString")

        refs: List[str] = []
        refs_obj = cve_obj.get("references") or []
        for ref in refs_obj:
            url = ref.get("url") if isinstance(ref, dict) else None
            if url and url not in refs:
                refs.append(url)
            if len(refs) >= settings.nvd_max_reference_urls:
                break
        results[cve_id] = (score, vector, refs)
    return results


def _deserialize_cve_list(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    parsed: List[str] = []
    seen: set[str] = set()
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for s in data:
                if isinstance(s, str):
                    key = s.upper()
                    if key not in seen:
                        seen.add(key)
                        parsed.append(s)
    except Exception:
        if isinstance(raw, str) and "CVE-" in raw.upper():
            return [raw]
        return parsed
    return parsed


def _observation_from_finding(finding: Finding) -> ServiceObservation:
    fingerprint = None
    evidence = None
    version_confidence = None
    if finding.fingerprint:
        try:
            fingerprint = json.loads(finding.fingerprint)
        except Exception:
            fingerprint = None
    if finding.evidence:
        try:
            evidence = json.loads(finding.evidence)
        except Exception:
            evidence = None
    if isinstance(fingerprint, dict):
        try:
            version_confidence = float(fingerprint.get("version_confidence"))
        except Exception:
            version_confidence = None
    return ServiceObservation(
        asset_id=finding.asset_id or 0,
        host_address=finding.host_address,
        host_os_name=finding.host_os_name,
        host_os_accuracy=finding.host_os_accuracy,
        host_vendor=finding.host_vendor,
        traceroute_summary=finding.traceroute_summary,
        host_report=finding.host_report,
        port=finding.port or 0,
        protocol=finding.protocol or "tcp",
        service_name=finding.service_name,
        service_version=finding.service_version,
        product=finding.service_name,
        version_confidence=version_confidence,
        fingerprint=fingerprint,
        evidence=evidence,
        evidence_summary=finding.evidence_summary,
    )


def _cache_feed_metrics(cache: NvdCache, metrics: Dict[str, Tuple[Optional[float], Optional[str], List[str]]]) -> None:
    now = datetime.now(timezone.utc)
    for cve_id, (score, vector, refs) in metrics.items():
        cache.write_entry(
            cve_id,
            NvdCacheEntry(
                cve_id=cve_id,
                cvss_v31_base=score,
                cvss_vector=vector,
                references=[ref for ref in refs if isinstance(ref, str)],
                fetched_at=now,
            ),
        )


def _merge_metric_entries(entries: List[NvdCacheEntry]) -> Tuple[Optional[float], Optional[str], List[str], str]:
    best_score: Optional[float] = None
    best_vector: Optional[str] = None
    refs: List[str] = []
    source = "nvd"
    for entry in entries:
        for ref in entry.references:
            if ref not in refs:
                refs.append(ref)
        if entry.cvss_v31_base is not None and (best_score is None or entry.cvss_v31_base > best_score):
            best_score = float(entry.cvss_v31_base)
            best_vector = entry.cvss_vector
            source = entry.source
    if len(refs) > settings.nvd_max_reference_urls:
        refs = refs[: settings.nvd_max_reference_urls]
    return best_score, best_vector, refs, source


def sync_nvd_cache(force_refresh: bool = False) -> int:
    """
    Fetch the recent NVD feed and persist CVSS/reference data to the local cache directory.
    Returns the number of CVEs cached.
    """
    cache = NvdCache(settings.nvd_cache_dir, ttl_hours=settings.nvd_cache_ttl_hours)
    feed = fetch_nvd_recent_feed(cache, force_refresh=force_refresh)
    if not feed:
        return 0
    metrics = _extract_cvss_and_refs_from_feed(feed)
    _cache_feed_metrics(cache, metrics)
    return len(metrics)


def enrich_from_feed(
    session: Session,
    findings: Iterable[Finding],
    observations: Optional[Dict[int, ServiceObservation]] = None,
    force_refresh_cache: bool = False,
) -> None:
    cache = NvdCache(settings.nvd_cache_dir, ttl_hours=settings.nvd_cache_ttl_hours)
    feed = fetch_nvd_recent_feed(cache, force_refresh=force_refresh_cache)
    metrics = _extract_cvss_and_refs_from_feed(feed) if feed else {}
    if metrics:
        _cache_feed_metrics(cache, metrics)
    cpe_engine = get_cpe_engine(settings.cpe_map_path, rule_templates=service_rule_cpe_templates())
    now_iso = datetime.now(timezone.utc).isoformat()
    metrics_entries: Dict[str, NvdCacheEntry] = {}
    for cve_id, data in metrics.items():
        metrics_entries[cve_id] = NvdCacheEntry(
            cve_id=cve_id,
            cvss_v31_base=data[0],
            cvss_vector=data[1],
            references=data[2],
            fetched_at=datetime.now(timezone.utc),
            source="nvd",
        )

    for finding in findings:
        cves = _deserialize_cve_list(finding.cve_ids)
        metric_candidates: List[NvdCacheEntry] = []
        for cve in cves:
            if cve in metrics_entries:
                metric_candidates.append(metrics_entries[cve])
                continue
            cached = cache.read_entry(cve)
            if cached:
                metric_candidates.append(cached)
            # Fall back to per-CVE API if cache/feed miss
            has_entry_for_cve = any(entry.cve_id == cve for entry in metric_candidates)
            if not has_entry_for_cve:
                detail = fetch_nvd_cve(cache, cve, force_refresh=force_refresh_cache)
                if detail:
                    extracted = _extract_cvss_and_refs_from_cve_detail(detail).get(cve)
                    if extracted:
                        entry = NvdCacheEntry(
                            cve_id=cve,
                            cvss_v31_base=extracted[0],
                            cvss_vector=extracted[1],
                            references=extracted[2],
                            fetched_at=datetime.now(timezone.utc),
                            source="nvd-api",
                        )
                        cache.write_entry(cve, entry)
                        metric_candidates.append(entry)

        best_score, best_vector, refs_accum, source = _merge_metric_entries(metric_candidates)
        obs = (observations or {}).get(finding.id or -1) if observations else None
        if not obs:
            obs = _observation_from_finding(finding)
        cpe_guess = cpe_engine.infer(obs) if obs else None

        if best_score is None and not refs_accum and not cpe_guess:
            continue
        refs_json = json.dumps(refs_accum) if refs_accum else None
        session.exec(
            text(
                """
                INSERT INTO finding_enrichment (finding_id, cpe, cpe_confidence, cvss_v31_base, cvss_vector, references_json, last_enriched_at, source)
                VALUES (:fid, :cpe, :cpe_conf, :score, :vector, :refs, :updated, :source)
                ON CONFLICT(finding_id) DO UPDATE SET
                  cpe=excluded.cpe,
                  cpe_confidence=excluded.cpe_confidence,
                  cvss_v31_base=excluded.cvss_v31_base,
                  cvss_vector=excluded.cvss_vector,
                  references_json=excluded.references_json,
                  last_enriched_at=excluded.last_enriched_at,
                  source=excluded.source
                """
            ).bindparams(
                fid=finding.id,
                cpe=cpe_guess.value if cpe_guess else None,
                cpe_conf=cpe_guess.confidence if cpe_guess else None,
                score=float(best_score) if best_score is not None else None,
                vector=best_vector,
                refs=refs_json,
                updated=now_iso,
                source=source or "nvd",
            )
        )


def enrich_cpe_only(session: Session, findings: Iterable[Finding], observations: Dict[int, ServiceObservation]) -> None:
    cpe_engine = get_cpe_engine(settings.cpe_map_path, rule_templates=service_rule_cpe_templates())
    now_iso = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        obs = observations.get(finding.id or -1)
        if not obs:
            continue
        cpe_guess = cpe_engine.infer(obs)
        if not cpe_guess:
            continue
        session.exec(
            text(
                """
                INSERT INTO finding_enrichment (finding_id, cpe, cpe_confidence, last_enriched_at, source)
                VALUES (:fid, :cpe, :conf, :updated, :source)
                ON CONFLICT(finding_id) DO UPDATE SET
                  cpe=excluded.cpe,
                  cpe_confidence=excluded.cpe_confidence,
                  last_enriched_at=excluded.last_enriched_at,
                  source=excluded.source
                """
            ).bindparams(
                fid=finding.id,
                cpe=cpe_guess.value,
                conf=cpe_guess.confidence,
                updated=now_iso,
                source=cpe_guess.source,
            )
        )


__all__ = [
    "NvdCache",
    "NvdCacheEntry",
    "enrich_from_feed",
    "enrich_cpe_only",
    "fetch_nvd_cve",
    "sync_nvd_cache",
    "CpeGuess",
    "CpeInferenceEngine",
    "get_cpe_engine",
]
