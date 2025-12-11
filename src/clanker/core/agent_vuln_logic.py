from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlmodel import Session, select

from clanker.core.agent_parsers import normalize_package_name, normalize_service_name, normalize_version, parse_sshd_config
from clanker.db.models import Finding

logger = logging.getLogger(__name__)


@dataclass
class AgentFindingCandidate:
    rule_id: str
    severity: str
    description: str
    cve_ids: List[str] = field(default_factory=list)
    evidence_summary: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    port: Optional[int] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None


@dataclass
class PackageAdvisory:
    rule_id: str
    package: str
    fixed_version: str
    cve_ids: List[str]
    severity: str
    description: str
    source: str
    distro_hint: Optional[str] = None
    min_version: Optional[str] = None  # inclusive


@dataclass
class ServiceRule:
    rule_id: str
    names: Sequence[str]
    version_lt: Optional[str]
    cve_ids: List[str]
    severity: str
    description: str
    cpe_template: Optional[str] = None


@dataclass
class KernelRule:
    rule_id: str
    cve_ids: List[str]
    severity: str
    description: str
    min_version: Optional[str] = None  # inclusive
    max_version: Optional[str] = None  # exclusive


PACKAGE_ADVISORIES: List[PackageAdvisory] = [
    PackageAdvisory(
        rule_id="AGENT-PKG-OPENSSL-2022-0778",
        package="openssl",
        fixed_version="1.1.1n",
        cve_ids=["CVE-2022-0778"],
        severity="high",
        description="OpenSSL BN_mod_sqrt DoS; patched in 1.1.1n (tracked via USN/RHSA advisories).",
        source="usn/rhsa/oval",
    ),
    PackageAdvisory(
        rule_id="AGENT-PKG-SUDO-2021-3156",
        package="sudo",
        fixed_version="1.9.5p2",
        cve_ids=["CVE-2021-3156"],
        severity="critical",
        description="Sudo Baron Samedit heap overflow; update to 1.9.5p2 or later.",
        source="oval",
    ),
    PackageAdvisory(
        rule_id="AGENT-PKG-OPENSSH-2020-15778",
        package="openssh-server",
        fixed_version="8.4p1",
        cve_ids=["CVE-2020-15778", "CVE-2018-15473"],
        severity="high",
        description="OpenSSH prior to 8.4 includes scp RCE and user enumeration bugs from vendor advisories.",
        source="usn/oval",
    ),
]

SERVICE_RULES: List[ServiceRule] = [
    ServiceRule(
        rule_id="AGENT-SVC-OPENSSH-OUTDATED",
        names=["ssh", "openssh", "openssh-server"],
        version_lt="8.4",
        cve_ids=["CVE-2020-15778", "CVE-2018-15473"],
        severity="high",
        description="OpenSSH service below 8.4; susceptible to scp RCE and user enumeration issues.",
        cpe_template="cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*",
    ),
    ServiceRule(
        rule_id="AGENT-SVC-NGINX-2021-23017",
        names=["nginx"],
        version_lt="1.20.2",
        cve_ids=["CVE-2021-23017"],
        severity="medium",
        description="nginx resolver vulnerability prior to 1.20.2; ensure patched build.",
        cpe_template="cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
    ),
]

KERNEL_RULES: List[KernelRule] = [
    KernelRule(
        rule_id="AGENT-KERNEL-2022-0847",
        cve_ids=["CVE-2022-0847"],
        severity="critical",
        description="Linux kernel Dirty Pipe privilege escalation; affects 5.8 through 5.16.10.",
        min_version="5.8.0",
        max_version="5.16.11",
    ),
    KernelRule(
        rule_id="AGENT-KERNEL-2016-5195",
        cve_ids=["CVE-2016-5195"],
        severity="high",
        description="Dirty COW privilege escalation; applies to kernels older than 4.8.3.",
        min_version=None,
        max_version="4.8.3",
    ),
]

LEGACY_SERVICE_KEYWORDS = [
    ("telnet", "high", "Legacy telnet service exposes cleartext authentication."),
    ("rsh", "high", "Remote shell service (rsh) allows unauthenticated command execution on legacy stacks."),
    ("ftp", "medium", "FTP service permits cleartext credentials; prefer SFTP/FTPS."),
]


def _version_tuple(version: str) -> Tuple[int | str, ...]:
    tokens = re.findall(r"[0-9]+|[a-zA-Z]+", version)
    if not tokens:
        return (0,)
    parsed: List[int | str] = []
    for token in tokens[:6]:
        if token.isdigit():
            parsed.append(int(token))
        else:
            parsed.append(token.lower())
    return tuple(parsed)  # type: ignore[return-value]


def _version_lt(current: str, reference: str) -> bool:
    return _version_tuple(current) < _version_tuple(reference)


def _version_between(current: str, minimum: Optional[str], maximum: Optional[str]) -> bool:
    cur = _version_tuple(current)
    if minimum and cur < _version_tuple(minimum):
        return False
    if maximum and cur >= _version_tuple(maximum):
        return False
    return True


def _get_value(obj: Any, key: str) -> Optional[Any]:
    if hasattr(obj, key):
        return getattr(obj, key)
    if isinstance(obj, dict):
        return obj.get(key)
    return None


def _normalize_package(obj: Any) -> tuple[str, str]:
    name = normalize_package_name(str(_get_value(obj, "name") or ""))
    version = normalize_version(str(_get_value(obj, "version") or ""))
    return name, version


def _match_package_advisories(inventory: Any, packages: Iterable[Any]) -> List[AgentFindingCandidate]:
    distro = str(_get_value(inventory, "distro") or _get_value(inventory, "os_name") or "").lower()
    findings: List[AgentFindingCandidate] = []
    for pkg in packages:
        name, version = _normalize_package(pkg)
        if not name or not version:
            continue
        for advisory in PACKAGE_ADVISORIES:
            if normalize_package_name(advisory.package) != name:
                continue
            if advisory.distro_hint and advisory.distro_hint not in distro:
                continue
            if advisory.min_version and not _version_between(version, advisory.min_version, None):
                continue
            if not _version_lt(version, advisory.fixed_version):
                continue
            summary = f"{name} {version} < {advisory.fixed_version}"
            evidence = [
                {
                    "type": "package_advisory",
                    "summary": summary,
                    "data": {
                        "package": name,
                        "installed_version": version,
                        "fixed_version": advisory.fixed_version,
                        "distro": distro or None,
                        "source": advisory.source,
                    },
                }
            ]
            findings.append(
                AgentFindingCandidate(
                    rule_id=advisory.rule_id,
                    severity=advisory.severity,
                    description=advisory.description,
                    cve_ids=advisory.cve_ids,
                    evidence_summary=summary,
                    evidence=evidence,
                )
            )
    return findings


def _match_kernel_rules(kernel_version: Optional[str]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    if not kernel_version:
        return findings
    normalized = normalize_version(kernel_version)
    for rule in KERNEL_RULES:
        if not _version_between(normalized, rule.min_version, rule.max_version):
            continue
        summary = f"Kernel {normalized} matches {rule.description}"
        evidence = [
            {
                "type": "kernel_version",
                "summary": summary,
                "data": {
                    "kernel_version": normalized,
                    "min_version": rule.min_version,
                    "max_version": rule.max_version,
                },
            }
        ]
        findings.append(
            AgentFindingCandidate(
                rule_id=rule.rule_id,
                severity=rule.severity,
                description=rule.description,
                cve_ids=rule.cve_ids,
                evidence_summary=summary,
                evidence=evidence,
            )
        )
    return findings


def _match_service_rules(services: Iterable[Any]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    for svc in services:
        raw_name = _get_value(svc, "name") or ""
        name = normalize_service_name(str(raw_name))
        version = normalize_version(str(_get_value(svc, "version") or ""))
        port = _get_value(svc, "port")
        protocol = _get_value(svc, "protocol")
        for rule in SERVICE_RULES:
            if name not in {normalize_service_name(n) for n in rule.names}:
                continue
            if rule.version_lt and version and not _version_lt(version, rule.version_lt):
                continue
            summary_bits = [name]
            if version:
                summary_bits.append(version)
            if port:
                summary_bits.append(f"port {port}")
            summary = " ".join(summary_bits)
            evidence = [
                {
                    "type": "service_version",
                    "summary": summary,
                    "data": {
                        "service": name,
                        "version": version or None,
                        "port": port,
                        "protocol": protocol,
                        "cpe": rule.cpe_template.format(version=version or "*") if rule.cpe_template else None,
                    },
                }
            ]
            findings.append(
                AgentFindingCandidate(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    description=rule.description,
                    cve_ids=rule.cve_ids,
                    evidence_summary=summary,
                    evidence=evidence,
                    port=port,
                    protocol=protocol,
                    service_name=name,
                    service_version=version or None,
                )
            )
        for keyword, severity, description in LEGACY_SERVICE_KEYWORDS:
            if keyword not in name:
                continue
            summary = f"{name} service listening on {port or 'unknown port'}"
            evidence = [
                {
                    "type": "legacy_service",
                    "summary": summary,
                    "data": {"service": name, "port": port, "protocol": protocol},
                }
            ]
            findings.append(
                AgentFindingCandidate(
                    rule_id=f"AGENT-SVC-LEGACY-{keyword.upper()}",
                    severity=severity,
                    description=description,
                    cve_ids=[],
                    evidence_summary=summary,
                    evidence=evidence,
                    port=port,
                    protocol=protocol,
                    service_name=name,
                    service_version=version or None,
                )
            )
    return findings


def _evaluate_ssh_config(configs: Dict[str, str]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    if not configs:
        return findings
    ssh_config = None
    for key, value in configs.items():
        if "ssh" in key.lower():
            ssh_config = value
            break
    if not ssh_config:
        return findings
    parsed = parse_sshd_config(ssh_config)
    permit_root = parsed.get("permit_root_login", "unknown")
    password_auth = parsed.get("password_authentication", "unknown")

    if permit_root not in {"no", "prohibit-password", "without-password"}:
        summary = f"PermitRootLogin set to {permit_root}"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-MISCONFIG-ROOT",
                severity="high",
                description="Root login over SSH is permitted; disable PermitRootLogin for hardening.",
                evidence_summary=summary,
                evidence=[{"type": "sshd_config", "summary": summary, "data": {"permit_root_login": permit_root}}],
            )
        )
    if password_auth not in {"no"}:
        summary = f"PasswordAuthentication set to {password_auth}"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-MISCONFIG-PASSWORDS",
                severity="medium",
                description="Password authentication is enabled; prefer key-based auth with MFA gateways.",
                evidence_summary=summary,
                evidence=[
                    {
                        "type": "sshd_config",
                        "summary": summary,
                        "data": {"password_authentication": password_auth},
                    }
                ],
            )
        )
    return findings


def evaluate_inventory(inventory: Any) -> List[AgentFindingCandidate]:
    """
    Evaluate an agent inventory payload and return vulnerability/misconfiguration findings.
    """
    packages = _get_value(inventory, "packages") or []
    services = _get_value(inventory, "services") or []
    configs = _get_value(inventory, "configs") or {}
    kernel_version = _get_value(inventory, "kernel_version") or _get_value(inventory, "os_version")

    findings: List[AgentFindingCandidate] = []
    findings.extend(_match_package_advisories(inventory, packages))
    findings.extend(_match_kernel_rules(kernel_version))
    findings.extend(_match_service_rules(services))
    findings.extend(_evaluate_ssh_config(configs if isinstance(configs, dict) else {}))
    return findings


def _finding_exists(
    session: Session,
    asset_id: Optional[int],
    rule_id: str,
    cve_ids: List[str],
    port: Optional[int],
    service_name: Optional[str],
    evidence_summary: str,
) -> bool:
    stmt = select(Finding).where(
        Finding.rule_id == rule_id,
        Finding.asset_id == asset_id,
        Finding.port == port,
        Finding.service_name == service_name,
        Finding.evidence_summary == evidence_summary,
    )
    if cve_ids:
        stmt = stmt.where(Finding.cve_ids == json.dumps(cve_ids))
    existing = session.exec(stmt).first()
    return existing is not None


def persist_agent_findings(
    session: Session,
    inventory: Any,
    asset_id: Optional[int],
    ingest_id: Optional[int] = None,
) -> List[Finding]:
    """
    Persist evaluated findings into the standard Finding table.
    """
    host_address = _get_value(inventory, "host_identifier") or _get_value(inventory, "hostname")
    os_name = _get_value(inventory, "os_name") or _get_value(inventory, "distro")
    distro = _get_value(inventory, "distro")
    findings_to_save = evaluate_inventory(inventory)
    persisted: List[Finding] = []
    for cand in findings_to_save:
        cve_json = json.dumps(cand.cve_ids) if cand.cve_ids else None
        evidence_json = json.dumps(cand.evidence) if cand.evidence else None
        if _finding_exists(session, asset_id, cand.rule_id, cand.cve_ids, cand.port, cand.service_name, cand.evidence_summary):
            continue
        finding = Finding(
            scan_id=None,
            asset_id=asset_id,
            host_address=host_address,
            host_os_name=os_name,
            host_vendor=str(distro) if distro else None,
            port=cand.port,
            protocol=cand.protocol,
            service_name=cand.service_name,
            service_version=cand.service_version,
            evidence=evidence_json,
            evidence_summary=cand.evidence_summary,
            rule_id=cand.rule_id,
            severity=cand.severity,
            cve_ids=cve_json,
            description=cand.description,
        )
        session.add(finding)
        persisted.append(finding)
    if persisted:
        session.flush()
        logger.info("Persisted %s agent findings (ingest_id=%s)", len(persisted), ingest_id)
    return persisted


__all__ = ["evaluate_inventory", "persist_agent_findings", "AgentFindingCandidate"]
