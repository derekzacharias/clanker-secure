from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple


EvidenceItem = Dict[str, Any]
STRONG_SOURCES = {"nvd", "vendor", "oval", "kev"}
STRUCTURED_TYPES = {
    "tls_certificate",
    "http_response",
    "mysql_handshake",
    "ssh_banner",
    "rdp_negotiation",
    "smb_banner",
    "snmp_probe",
    "agent_fact",
}


def _confidence_from_item(item: EvidenceItem) -> float:
    value = item.get("confidence")
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    return 0.5  # default midpoint when unspecified


def _source_weight(source: str) -> int:
    src = source.lower()
    if src in STRONG_SOURCES:
        return 3
    if src in {"scan", "rule_engine"}:
        return 2
    return 1


def _key_for_item(item: EvidenceItem) -> Tuple[str, str, str]:
    etype = str(item.get("type") or "").strip().lower()
    summary = str(item.get("summary") or "").strip().lower()
    data = item.get("data")
    data_preview = ""
    if data:
        try:
            data_preview = json.dumps(data, sort_keys=True)[:80]
        except Exception:
            data_preview = str(data)[:80]
    return (etype, summary, data_preview)


def dedupe_evidence(items: Iterable[EvidenceItem]) -> List[EvidenceItem]:
    kept: dict[Tuple[str, str, str], EvidenceItem] = {}
    order: List[Tuple[str, str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        key = _key_for_item(item)
        conf = _confidence_from_item(item)
        source = str(item.get("source") or "")
        if key not in kept:
            kept[key] = item
            order.append(key)
            continue
        existing = kept[key]
        existing_conf = _confidence_from_item(existing)
        if conf > existing_conf or _source_weight(source) > _source_weight(str(existing.get("source") or "")):
            kept[key] = item
    return [kept[k] for k in order]


def grade_evidence(items: Iterable[EvidenceItem]) -> str:
    """
    Grading heuristic:
    - high: strong source (NVD/vendor/OVAL/KEV) or confidence >= 0.85, or structured protocol evidence with confidence >= 0.65
    - medium: at least one item with confidence >= 0.5 or two or more evidence items
    - low: otherwise
    """
    items_list = [item for item in items if isinstance(item, dict)]
    if not items_list:
        return "low"
    has_medium = False
    for item in items_list:
        source = str(item.get("source") or "").lower()
        conf = _confidence_from_item(item)
        if source in STRONG_SOURCES or conf >= 0.85:
            return "high"
        if item.get("type") in STRUCTURED_TYPES and conf >= 0.65:
            return "high"
        if conf >= 0.5:
            has_medium = True
    if has_medium or len(items_list) >= 2:
        return "medium"
    return "low"


def build_why_trace(
    rule_id: str | None,
    summary: str | None,
    source: str | None = None,
    context: Optional[Dict[str, Any]] = None,
) -> str:
    parts: List[str] = []
    if rule_id:
        parts.append(f"Matched rule {rule_id}")
    if summary:
        parts.append(summary)
    if source:
        parts.append(f"source={source}")
    if context:
        port = context.get("port")
        protocol = context.get("protocol")
        svc = context.get("service_name")
        version = context.get("service_version")
        version_confidence = context.get("version_confidence")
        detail_bits = []
        if svc:
            detail_bits.append(str(svc))
        if port or protocol:
            detail_bits.append(f"{protocol or 'tcp'}/{port}" if port else str(protocol))
        if version:
            detail_bits.append(f"version={version}")
        if version_confidence is not None:
            detail_bits.append(f"vconf={version_confidence:.2f}")
        if detail_bits:
            parts.append("context=" + " ".join(detail_bits))
    return " | ".join(parts) if parts else "evidence-evaluated"


__all__ = ["dedupe_evidence", "grade_evidence", "build_why_trace"]
