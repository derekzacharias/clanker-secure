from __future__ import annotations

import json
from typing import Iterable, List

from sqlmodel import Session

from clanker.core.rule_engine import Rule, evaluate_rules, load_rules
from clanker.core.types import ServiceObservation
from clanker.db.models import Finding


def build_findings(
    session: Session,
    scan_id: int,
    asset_id: int,
    observations: Iterable[ServiceObservation],
    rules: List[Rule] | None = None,
) -> List[Finding]:
    rules = rules or load_rules()
    persisted: List[Finding] = []
    for observation in observations:
        matches = evaluate_rules(observation, rules)
        if matches:
            for rule in matches:
                finding = Finding(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    host_address=observation.host_address,
                    host_os_name=observation.host_os_name,
                    host_os_accuracy=observation.host_os_accuracy,
                    host_vendor=observation.host_vendor,
                    traceroute_summary=observation.traceroute_summary,
                    host_report=observation.host_report,
                    port=observation.port,
                    protocol=observation.protocol,
                    service_name=observation.service_name,
                    service_version=observation.service_version,
                    rule_id=rule.id,
                    severity=rule.severity,
                    cve_ids=json.dumps(rule.cve),
                    description=rule.description,
                )
                session.add(finding)
                persisted.append(finding)
        else:
            finding = Finding(
                scan_id=scan_id,
                asset_id=asset_id,
                host_address=observation.host_address,
                host_os_name=observation.host_os_name,
                host_os_accuracy=observation.host_os_accuracy,
                host_vendor=observation.host_vendor,
                traceroute_summary=observation.traceroute_summary,
                host_report=observation.host_report,
                port=observation.port,
                protocol=observation.protocol,
                service_name=observation.service_name,
                service_version=observation.service_version,
                severity="informational",
                description="Open service detected without matching CVE rule",
            )
            session.add(finding)
            persisted.append(finding)
    session.flush()
    return persisted
