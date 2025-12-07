from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
import random
from sqlmodel import Session

from clanker.db.models import Finding
from sqlalchemy import text


CACHE_DIR = Path(os.getenv("CLANKER_NVD_CACHE_DIR", "./scan_artifacts/nvd_cache"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

NVD_API_BASE = os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cache_path_for_cve(cve_id: str) -> Path:
    safe = cve_id.replace("/", "_")
    return CACHE_DIR / f"{safe}.json"


def _read_cache(cve_id: str) -> Optional[Dict[str, Any]]:
    p = _cache_path_for_cve(cve_id)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def _write_cache(cve_id: str, data: Dict[str, Any]) -> None:
    p = _cache_path_for_cve(cve_id)
    try:
        p.write_text(json.dumps(data))
    except Exception:
        pass


_LAST_REQUEST_AT: Optional[float] = None


def _respect_min_interval(min_interval: float = 0.6) -> None:
    global _LAST_REQUEST_AT  # noqa: PLW0603
    now = time.time()
    if _LAST_REQUEST_AT is None:
        _LAST_REQUEST_AT = now
        return
    delta = now - _LAST_REQUEST_AT
    if delta < min_interval:
        time.sleep(min_interval - delta)
    _LAST_REQUEST_AT = time.time()


def fetch_nvd_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    cached = _read_cache(cve_id)
    if cached is not None:
        return cached

    headers = {"User-Agent": "clanker/0.2"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    url = f"{NVD_API_BASE}?cveId={cve_id}"
    # Exponential backoff with jitter and polite min-interval throttling
    base_delay = 0.5
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            _respect_min_interval(0.6)
            with httpx.Client(timeout=20) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    _write_cache(cve_id, data)
                    _respect_min_interval(0.6)
                    return data
                if resp.status_code in (403, 429, 503, 500):
                    # exponential backoff with jitter
                    delay = base_delay * (2 ** attempt) + random.uniform(0, 0.25)
                    time.sleep(min(delay, 10))
                    continue
                # other errors: do not cache, but break
                break
        except Exception:
            delay = base_delay * (2 ** attempt) + random.uniform(0, 0.25)
            time.sleep(min(delay, 5))
    return None


def extract_cvss_v31(data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    try:
        cves = data.get("vulnerabilities") or data.get("vulnerabilities", [])
        if not cves:
            cves = data.get("cveItems")  # older format guard
        if not cves:
            return None, None
        item = cves[0]
        metrics = (
            item.get("cve", {}).get("metrics")
            or item.get("cve", {}).get("metrics", {})
            or item.get("cve", {})
        )
        # v3.1 path (common)
        m31 = metrics.get("cvssMetricV31") if isinstance(metrics, dict) else None
        if m31 and isinstance(m31, list) and m31:
            cvd = m31[0].get("cvssData", {})
            return cvd.get("baseScore"), cvd.get("vectorString")
        # v3.0 fallback
        m30 = metrics.get("cvssMetricV30") if isinstance(metrics, dict) else None
        if m30 and isinstance(m30, list) and m30:
            cvd = m30[0].get("cvssData", {})
            return cvd.get("baseScore"), cvd.get("vectorString")
    except Exception:
        return None, None
    return None, None


def extract_references(data: Dict[str, Any], limit: int = 6) -> List[str]:
    refs: List[str] = []
    try:
        cves = data.get("vulnerabilities") or data.get("vulnerabilities", [])
        if not cves:
            cves = data.get("cveItems")
        if not cves:
            return []
        item = cves[0]
        refs_arr = (
            item.get("cve", {})
            .get("references", {})
            .get("referenceData", [])
            or item.get("cve", {})
            .get("references", [])
        )
        for r in refs_arr:
            url = r.get("url")
            if url and url not in refs:
                refs.append(url)
            if len(refs) >= limit:
                break
    except Exception:
        return []
    return refs


def infer_cpe(f: Finding) -> Optional[str]:
    name = (f.service_name or "").lower()
    ver = (f.service_version or "").lower()
    vendor = (f.host_vendor or "").lower()
    # naive guesses for common services; expandable via mapping file later
    if "openssh" in name:
        return f"cpe:2.3:a:openbsd:openssh:{ver or '*'}:*:*:*:*:*:*:*"
    if "nginx" in name:
        return f"cpe:2.3:a:nginx:nginx:{ver or '*'}:*:*:*:*:*:*:*"
    if "httpd" in name or "apache" in name:
        return f"cpe:2.3:a:apache:http_server:{ver or '*'}:*:*:*:*:*:*:*"
    if "mysql" in name:
        return f"cpe:2.3:a:mysql:mysql:{ver or '*'}:*:*:*:*:*:*:*"
    if vendor and name:
        return f"cpe:2.3:a:{vendor}:{name}:{ver or '*'}:*:*:*:*:*:*:*"
    return None


def enrich_finding(session: Session, finding: Finding) -> bool:
    # Determine CVEs to look up
    cve_ids: List[str] = []
    if finding.cve_ids:
        try:
            arr = json.loads(finding.cve_ids)
            if isinstance(arr, list):
                cve_ids = [s for s in arr if isinstance(s, str)]
        except Exception:
            pass

    best_score: Optional[float] = None
    best_vector: Optional[str] = None
    refs_accum: List[str] = []

    for cve in cve_ids:
        data = fetch_nvd_cve(cve)
        if not data:
            continue
        score, vec = extract_cvss_v31(data)
        refs = extract_references(data, limit=6)
        if refs:
            for r in refs:
                if r not in refs_accum:
                    refs_accum.append(r)
        if score is not None and (best_score is None or score > best_score):
            best_score, best_vector = score, vec

    cpe = infer_cpe(finding)

    # Upsert into enrichment table
    refs_json = json.dumps(refs_accum) if refs_accum else None
    now_iso = _now_iso()
    stmt = text(
        "INSERT INTO finding_enrichment (finding_id, cpe, cvss_v31_base, cvss_vector, references_json, last_enriched_at, source)\n"
        "VALUES (:finding_id, :cpe, :score, :vector, :refs, :updated, 'nvd')\n"
        "ON CONFLICT(finding_id) DO UPDATE SET\n"
        "  cpe=excluded.cpe,\n"
        "  cvss_v31_base=excluded.cvss_v31_base,\n"
        "  cvss_vector=excluded.cvss_vector,\n"
        "  references_json=excluded.references_json,\n"
        "  last_enriched_at=excluded.last_enriched_at,\n"
        "  source=excluded.source"
    )
    session.exec(
        stmt,
        {
            "finding_id": finding.id,
            "cpe": cpe,
            "score": float(best_score) if best_score is not None else None,
            "vector": best_vector,
            "refs": refs_json,
            "updated": now_iso,
        },
    )
    return True

def get_enrichment(session: Session, finding_id: int) -> Optional[Dict[str, Any]]:
    row = session.exec(text("SELECT * FROM finding_enrichment WHERE finding_id = :fid"), {"fid": finding_id}).mappings().first()
    if not row:
        return None
    return dict(row)
