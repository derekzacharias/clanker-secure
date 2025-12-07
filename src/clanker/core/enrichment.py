from __future__ import annotations

import gzip
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
from sqlmodel import Session

from clanker.config import settings
from clanker.core.types import ServiceObservation
from clanker.db.models import Finding


@dataclass
class NvdCacheEntry:
    cve_id: str
    cvss_v31_base: Optional[float]
    cvss_vector: Optional[str]
    references: List[str]
    last_enriched_at: datetime
    source: str = "nvd"


class NvdCache:
    def __init__(self, cache_dir: Path, ttl_hours: int = 24) -> None:
        self.cache_dir = cache_dir
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace("/", "_")
        return self.cache_dir / f"{safe}.json"

    def read(self, key: str) -> Optional[Dict[str, Any]]:
        p = self._path(key)
        if not p.exists():
            return None
        try:
            raw = json.loads(p.read_text())
        except Exception:
            return None
        ts = raw.get("last_enriched_at")
        if ts:
            try:
                if datetime.fromisoformat(ts) < datetime.now(timezone.utc) - self.ttl:
                    return None
            except Exception:
                return None
        return raw

    def write(self, key: str, data: Dict[str, Any]) -> None:
        p = self._path(key)
        try:
            p.write_text(json.dumps(data))
        except Exception:
            pass


def _load_cpe_map(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    try:
        with path.open() as fh:
            data = json.load(fh)
            return {k.lower(): v for k, v in data.items() if isinstance(v, str)}
    except Exception:
        return {}


def infer_cpe(observation: ServiceObservation, cpe_map: Dict[str, str]) -> Optional[str]:
    name = (observation.service_name or "").lower()
    version = (observation.service_version or "").lower() or "*"
    vendor = (observation.host_vendor or "").lower()

    if name in cpe_map:
        return cpe_map[name].format(version=version or "*", product=name)
    if vendor and name:
        return f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*"
    if name:
        return f"cpe:2.3:a:{name}:{name}:{version}:*:*:*:*:*:*:*"
    return None


def _respect_min_interval(last_request: List[float], min_interval: float = 0.6) -> None:
    now = time.time()
    if not last_request:
        last_request.append(now)
        return
    delta = now - last_request[-1]
    if delta < min_interval:
        time.sleep(min_interval - delta)
    last_request.append(time.time())


def fetch_nvd_recent_feed(cache: NvdCache, min_interval: float = 0.6) -> Optional[Dict[str, Any]]:
    cache_key = "recent_feed"
    cached = cache.read(cache_key)
    if cached:
        return cached

    headers = {"User-Agent": "clanker/0.2"}
    url = settings.nvd_recent_feed_url
    last_request: List[float] = []
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
        results[cve_id] = (score, vector, refs)
    return results


def _deserialize_cve_list(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [s for s in data if isinstance(s, str)]
    except Exception:
        return []
    return []


def enrich_from_feed(session: Session, findings: Iterable[Finding]) -> None:
    cache = NvdCache(settings.nvd_cache_dir, ttl_hours=settings.nvd_cache_ttl_hours)
    feed = fetch_nvd_recent_feed(cache)
    if not feed:
        return
    metrics = _extract_cvss_and_refs_from_feed(feed)
    now_iso = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        cves = _deserialize_cve_list(finding.cve_ids)
        if not cves:
            continue
        refs_accum: List[str] = []
        best_score: Optional[float] = None
        best_vector: Optional[str] = None
        for cve in cves:
            if cve not in metrics:
                continue
            score, vector, refs = metrics[cve]
            if refs:
                for r in refs:
                    if r not in refs_accum:
                        refs_accum.append(r)
            if score is not None and (best_score is None or score > best_score):
                best_score, best_vector = score, vector
        if best_score is None and not refs_accum:
            continue
        refs_json = json.dumps(refs_accum) if refs_accum else None
        session.exec(
            """
            INSERT INTO finding_enrichment (finding_id, cpe, cvss_v31_base, cvss_vector, references_json, last_enriched_at, source)
            VALUES (:fid, NULL, :score, :vector, :refs, :updated, 'nvd')
            ON CONFLICT(finding_id) DO UPDATE SET
              cvss_v31_base=excluded.cvss_v31_base,
              cvss_vector=excluded.cvss_vector,
              references_json=excluded.references_json,
              last_enriched_at=excluded.last_enriched_at,
              source=excluded.source
            """,
            {
                "fid": finding.id,
                "score": float(best_score) if best_score is not None else None,
                "vector": best_vector,
                "refs": refs_json,
                "updated": now_iso,
            },
        )


def enrich_cpe_only(session: Session, findings: Iterable[Finding], observations: Dict[int, ServiceObservation]) -> None:
    cpe_map = _load_cpe_map(settings.cpe_map_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        obs = observations.get(finding.id or -1)
        if not obs:
            continue
        cpe = infer_cpe(obs, cpe_map)
        if not cpe:
            continue
        session.exec(
            """
            INSERT INTO finding_enrichment (finding_id, cpe, last_enriched_at, source)
            VALUES (:fid, :cpe, :updated, 'cpe-inference')
            ON CONFLICT(finding_id) DO UPDATE SET
              cpe=excluded.cpe,
              last_enriched_at=excluded.last_enriched_at,
              source=excluded.source
            """,
            {"fid": finding.id, "cpe": cpe, "updated": now_iso},
        )


__all__ = [
    "NvdCache",
    "NvdCacheEntry",
    "enrich_from_feed",
    "enrich_cpe_only",
    "infer_cpe",
]
