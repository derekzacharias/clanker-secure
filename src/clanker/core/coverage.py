from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from clanker.config import settings
from clanker.core.types import ServiceObservation


def record_rule_gap(observation: ServiceObservation, reason: str, path: Optional[Path] = None) -> None:
    destination = path or settings.rule_gap_path
    if not destination:
        return
    payload = {
        "host": observation.host_address,
        "port": observation.port,
        "protocol": observation.protocol,
        "service_name": observation.service_name,
        "service_version": observation.service_version,
        "fingerprint": observation.fingerprint,
        "evidence_summary": observation.evidence_summary,
        "reason": reason,
    }
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def load_rule_gaps(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    destination = path or settings.rule_gap_path
    if not destination.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with destination.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def summarize_rule_gaps(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    summary: Dict[Tuple[str, int | None, str], Dict[str, Any]] = {}
    for entry in entries:
        protocol = (entry.get("protocol") or "unknown").lower()
        port = entry.get("port")
        service_name = entry.get("service_name") or "unknown"
        key = (protocol, port, service_name)
        bucket = summary.setdefault(
            key,
            {
                "protocol": protocol,
                "port": port,
                "service_name": service_name,
                "count": 0,
                "examples": [],
            },
        )
        bucket["count"] += 1
        if len(bucket["examples"]) < 3:
            bucket["examples"].append(
                {
                    "host": entry.get("host"),
                    "service_version": entry.get("service_version"),
                    "fingerprint": entry.get("fingerprint"),
                    "reason": entry.get("reason"),
                    "evidence_summary": entry.get("evidence_summary"),
                }
            )
    return sorted(summary.values(), key=lambda item: item["count"], reverse=True)


def stub_rule_from_gap(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": "RULE-NEW-000",
        "match": {
            "port": entry.get("port"),
            "service_name": entry.get("service_name"),
            "version_contains": None,
        },
        "cve": [],
        "severity": "informational",
        "description": f"Stub for {entry.get('service_name') or 'unknown'} on port {entry.get('port')}",
    }
