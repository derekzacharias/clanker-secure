from __future__ import annotations

import json
from typing import Iterable, List

from sqlmodel import Session

from clanker.core.coverage import record_rule_gap
from clanker.core.evidence import build_why_trace, dedupe_evidence, grade_evidence
from clanker.core.rule_engine import Rule, evaluate_rules, load_rules
from clanker.core.types import ServiceObservation
from clanker.db.models import Finding


def build_findings(
    session: Session,
    scan_id: int,
    asset_id: int,
    observations: Iterable[ServiceObservation],
    rules: List[Rule] | None = None,
    observation_map: dict[int, ServiceObservation] | None = None,
) -> List[Finding]:
    rules = rules or load_rules()
    persisted: List[tuple[Finding, ServiceObservation]] = []
    for observation in observations:
        matches = evaluate_rules(observation, rules)
        fingerprint_json = json.dumps(observation.fingerprint) if observation.fingerprint is not None else None
        evidence_list = observation.evidence if observation.evidence else []
        deduped_evidence = dedupe_evidence(evidence_list if isinstance(evidence_list, list) else [])
        evidence_json = json.dumps(deduped_evidence) if deduped_evidence else None
        evidence_grade = grade_evidence(deduped_evidence) if deduped_evidence else None
        context = {
            "port": observation.port,
            "protocol": observation.protocol,
            "service_name": observation.service_name,
            "service_version": observation.service_version,
            "version_confidence": observation.version_confidence,
        }
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
                    fingerprint=fingerprint_json,
                    evidence=evidence_json,
                    evidence_summary=observation.evidence_summary,
                    evidence_grade=evidence_grade,
                    why_trace=build_why_trace(rule.id, observation.evidence_summary, source="rule_engine", context=context),
                    rule_id=rule.id,
                    severity=rule.severity,
                    cve_ids=json.dumps(rule.cve),
                    description=rule.description,
                )
                session.add(finding)
                persisted.append((finding, observation))
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
                    fingerprint=fingerprint_json,
                    evidence=evidence_json,
                    evidence_summary=observation.evidence_summary,
                    evidence_grade=evidence_grade,
                    why_trace=build_why_trace(
                        None,
                        observation.evidence_summary or "No rule matched; coverage gap logged",
                        source="no_rule_match",
                        context=context,
                    ),
                    severity="informational",
                    description="Open service detected without matching CVE rule",
                )
            session.add(finding)
            persisted.append((finding, observation))
            record_rule_gap(observation, reason="no_rule_match")
    session.flush()
    if observation_map is not None:
        for finding, obs in persisted:
            if finding.id is not None:
                observation_map[finding.id] = obs
    return [pair[0] for pair in persisted]
