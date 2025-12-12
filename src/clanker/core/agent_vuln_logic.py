from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlmodel import Session, select

from clanker.config import settings
from clanker.core.agent_parsers import normalize_package_name, normalize_service_name, normalize_version, parse_sshd_config
from clanker.core.evidence import build_why_trace, dedupe_evidence, grade_evidence
from clanker.core.types import ServiceObservation
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
    rule_source: Optional[str] = None
    evidence_grade: Optional[str] = None
    why_trace: Optional[str] = None


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
    backport_fixed_version: Optional[str] = None


@dataclass
class ServiceRule:
    rule_id: str
    names: Sequence[str]
    version_lt: Optional[str]
    cve_ids: List[str]
    severity: str
    description: str
    cpe_template: Optional[str] = None
    source: Optional[str] = None


@dataclass
class KernelRule:
    rule_id: str
    cve_ids: List[str]
    severity: str
    description: str
    min_version: Optional[str] = None  # inclusive
    max_version: Optional[str] = None  # exclusive
    source: Optional[str] = None


@dataclass
class OSRule:
    rule_id: str
    distro_match: Sequence[str]
    version_lt: Optional[str]
    cve_ids: List[str]
    severity: str
    description: str
    source: Optional[str] = None


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
        source="builtin",
    ),
    ServiceRule(
        rule_id="AGENT-SVC-NGINX-2021-23017",
        names=["nginx"],
        version_lt="1.20.2",
        cve_ids=["CVE-2021-23017"],
        severity="medium",
        description="nginx resolver vulnerability prior to 1.20.2; ensure patched build.",
        cpe_template="cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
        source="builtin",
    ),
    ServiceRule(
        rule_id="AGENT-SVC-APACHE-2021-41773",
        names=["apache", "httpd", "apache2"],
        version_lt="2.4.51",
        cve_ids=["CVE-2021-41773", "CVE-2021-42013"],
        severity="critical",
        description="Apache HTTP Server path traversal/RCE fixed in 2.4.51; upgrade immediately.",
        cpe_template="cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
        source="builtin",
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
        source="builtin",
    ),
    KernelRule(
        rule_id="AGENT-KERNEL-2016-5195",
        cve_ids=["CVE-2016-5195"],
        severity="high",
        description="Dirty COW privilege escalation; applies to kernels older than 4.8.3.",
        min_version=None,
        max_version="4.8.3",
        source="builtin",
    ),
]

OS_RULES: List[OSRule] = [
    OSRule(
        rule_id="AGENT-OS-EOL-UBUNTU-1604",
        distro_match=["ubuntu"],
        version_lt="18.04",
        cve_ids=[],
        severity="high",
        description="Ubuntu release is end-of-life; upgrade to a supported LTS (18.04+).",
        source="builtin",
    ),
    OSRule(
        rule_id="AGENT-OS-EOL-CENTOS-7",
        distro_match=["centos"],
        version_lt="8",
        cve_ids=[],
        severity="high",
        description="CentOS release before 8 is end-of-life; migrate to a supported release.",
        source="builtin",
    ),
]

LEGACY_SERVICE_KEYWORDS = [
    ("telnet", "high", "Legacy telnet service exposes cleartext authentication."),
    ("rsh", "high", "Remote shell service (rsh) allows unauthenticated command execution on legacy stacks."),
    ("ftp", "medium", "FTP service permits cleartext credentials; prefer SFTP/FTPS."),
]

WEAK_SSH_CIPHERS = {
    "3des-cbc",
    "blowfish-cbc",
    "aes128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
}
WEAK_SSH_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1", "umac-64@openssh.com"}
WEAK_SSH_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}


def _parse_mode(raw: Any) -> Optional[int]:
    try:
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str) and raw:
            return int(raw, 8)
    except Exception:
        return None
    return None


def _is_world_readable(mode: Optional[int]) -> bool:
    if mode is None:
        return False
    return bool(mode & 0o004)


def _is_world_writable(mode: Optional[int]) -> bool:
    if mode is None:
        return False
    return bool(mode & 0o002)


def _safe_list(raw: Any) -> List[Any]:
    if isinstance(raw, list):
        return raw
    return []


def _safe_str(value: Any) -> str:
    return str(value) if value is not None else ""


def _extract_algorithm_list(raw_config: Optional[str], directive: str) -> List[str]:
    if not raw_config:
        return []
    directive_lower = directive.lower()
    algos: List[str] = []
    for raw_line in raw_config.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line.lower().startswith(directive_lower):
            continue
        _, _, tail = line.partition(" ")
        for token in re.split(r"[,\s]+", tail.lower()):
            if token and token not in algos:
                algos.append(token)
    return algos


def _normalize_cves(values: Iterable[Any]) -> List[str]:
    return [_safe_str(cve) for cve in values if _safe_str(cve)]


def _build_package_advisory(raw: Dict[str, Any], default_distro: Optional[str] = None) -> Optional[PackageAdvisory]:
    try:
        distro_hint = _safe_str(raw.get("distro_hint")) or None
        if not distro_hint:
            distro_hint = default_distro
        backport_fixed = _safe_str(raw.get("backport_fixed_version")) or None
        fixed_version = _safe_str(raw.get("fixed_version"))
        if backport_fixed and distro_hint:
            fixed_version = backport_fixed
        if not fixed_version:
            return None
        return PackageAdvisory(
            rule_id=_safe_str(raw.get("rule_id")),
            package=_safe_str(raw.get("package")),
            fixed_version=fixed_version,
            cve_ids=_normalize_cves(_safe_list(raw.get("cve_ids"))),
            severity=_safe_str(raw.get("severity") or "medium"),
            description=_safe_str(raw.get("description")),
            source=_safe_str(raw.get("source") or "external"),
            distro_hint=distro_hint,
            min_version=_safe_str(raw.get("min_version")) or None,
            backport_fixed_version=backport_fixed,
        )
    except Exception:
        logger.debug("Skipping invalid package advisory entry: %s", raw, exc_info=True)
        return None


def _build_service_rule(raw: Dict[str, Any]) -> Optional[ServiceRule]:
    try:
        names = [normalize_service_name(_safe_str(n)) for n in _safe_list(raw.get("names")) if _safe_str(n)]
        if not names:
            return None
        version_lt = _safe_str(raw.get("version_lt")) or None
        return ServiceRule(
            rule_id=_safe_str(raw.get("rule_id")),
            names=names,
            version_lt=version_lt,
            cve_ids=[_safe_str(cve) for cve in _safe_list(raw.get("cve_ids")) if _safe_str(cve)],
            severity=_safe_str(raw.get("severity") or "medium"),
            description=_safe_str(raw.get("description")),
            cpe_template=_safe_str(raw.get("cpe_template")) or None,
            source=_safe_str(raw.get("source")) or "external",
        )
    except Exception:
        logger.debug("Skipping invalid service rule entry: %s", raw, exc_info=True)
        return None


def _build_package_advisory_from_osv(raw: Dict[str, Any], default_distro: Optional[str]) -> Optional[PackageAdvisory]:
    pkg = _safe_str(raw.get("package") or raw.get("name"))
    fixed_version = _safe_str(raw.get("fixed_version") or raw.get("patched_version"))
    backport = _safe_str(raw.get("backport_fixed_version")) or None
    distro_hint = _safe_str(raw.get("distro_hint")) or default_distro
    if backport and distro_hint:
        fixed_version = backport
    if not pkg or not fixed_version:
        return None
    rule_id = _safe_str(raw.get("rule_id") or f"OSV-{pkg}-{fixed_version}")
    cves = _normalize_cves(
        _safe_list(raw.get("cve_ids"))
        or _safe_list(raw.get("aliases"))
        or _safe_list(raw.get("ids"))
    )
    return PackageAdvisory(
        rule_id=rule_id,
        package=pkg,
        fixed_version=fixed_version,
        cve_ids=cves,
        severity=_safe_str(raw.get("severity") or "medium"),
        description=_safe_str(raw.get("description") or raw.get("summary")),
        source=_safe_str(raw.get("source") or "osv"),
        distro_hint=distro_hint,
        min_version=_safe_str(raw.get("min_version") or raw.get("introduced_version")) or None,
        backport_fixed_version=backport,
    )


def _build_package_advisory_from_oval(raw: Dict[str, Any], default_distro: Optional[str]) -> Optional[PackageAdvisory]:
    pkg = _safe_str(raw.get("package"))
    fixed_version = _safe_str(raw.get("fixed_version"))
    backport = _safe_str(raw.get("backport_fixed_version")) or None
    distro_hint = _safe_str(raw.get("distro_hint")) or default_distro
    if backport and distro_hint:
        fixed_version = backport
    if not pkg or not fixed_version:
        return None
    rule_id = _safe_str(raw.get("rule_id") or _safe_str(raw.get("definition_id")) or f"OVAL-{pkg}")
    cves = _normalize_cves(_safe_list(raw.get("cve_ids")))
    return PackageAdvisory(
        rule_id=rule_id,
        package=pkg,
        fixed_version=fixed_version,
        cve_ids=cves,
        severity=_safe_str(raw.get("severity") or "medium"),
        description=_safe_str(raw.get("description") or raw.get("title")),
        source=_safe_str(raw.get("source") or "oval"),
        distro_hint=distro_hint,
        min_version=_safe_str(raw.get("min_version")) or None,
        backport_fixed_version=backport,
    )


def _build_kernel_rule(raw: Dict[str, Any]) -> Optional[KernelRule]:
    try:
        return KernelRule(
            rule_id=_safe_str(raw.get("rule_id")),
            cve_ids=[_safe_str(cve) for cve in _safe_list(raw.get("cve_ids")) if _safe_str(cve)],
            severity=_safe_str(raw.get("severity") or "medium"),
            description=_safe_str(raw.get("description")),
            min_version=_safe_str(raw.get("min_version")) or None,
            max_version=_safe_str(raw.get("max_version")) or None,
            source=_safe_str(raw.get("source")) or "external",
        )
    except Exception:
        logger.debug("Skipping invalid kernel rule entry: %s", raw, exc_info=True)
        return None


def _external_agent_rules(path: Path | None = None) -> Tuple[List[PackageAdvisory], List[ServiceRule], List[KernelRule]]:
    advisory_path = Path(path or settings.agent_advisories_path).resolve()
    meta = _advisory_cache_token(advisory_path)
    return _external_agent_rules_cached(advisory_path, meta)


def _advisory_cache_token(path: Path) -> str:
    if not path.exists():
        return "missing"
    if path.is_dir():
        json_files = sorted(path.glob("*.json"))
        if not json_files:
            return f"{path}-empty-dir"
        latest = max(f.stat().st_mtime for f in json_files)
        return f"{path}-{len(json_files)}-{latest}"
    return f"{path}-{path.stat().st_mtime}"


def _infer_distro_hint(path: Path) -> Optional[str]:
    tokens = path.stem.lower().replace("-", "_").split("_")
    known = {"ubuntu", "debian", "rhel", "centos", "rocky", "alma", "suse", "opensuse", "alpine"}
    for token in tokens:
        if token in known:
            return token
    return None


def _load_advisory_payloads(path: Path) -> List[tuple[Dict[str, Any], Optional[str]]]:
    if not path.exists():
        return []
    payloads: List[tuple[Dict[str, Any], Optional[str]]] = []
    if path.is_dir():
        files = sorted(path.glob("*.json"))
        for file in files:
            try:
                payloads.append((json.loads(file.read_text(encoding="utf-8")), _infer_distro_hint(file)))
            except Exception:
                logger.warning("Failed to load agent advisories from %s", file, exc_info=True)
        return payloads
    try:
        payloads.append((json.loads(path.read_text(encoding="utf-8")), _infer_distro_hint(path)))
    except Exception:
        logger.warning("Failed to load agent advisories from %s", path, exc_info=True)
    return payloads


@lru_cache(maxsize=8)
def _external_agent_rules_cached(
    advisory_path: Path, cache_token: str
) -> Tuple[List[PackageAdvisory], List[ServiceRule], List[KernelRule]]:
    if cache_token == "missing":
        return [], [], []

    payloads = _load_advisory_payloads(advisory_path)
    if not payloads:
        return [], [], []

    pkg_rules: List[PackageAdvisory] = []
    svc_rules: List[ServiceRule] = []
    kernel_rules: List[KernelRule] = []

    for payload, distro_hint in payloads:
        for entry in _safe_list(payload.get("package_advisories")):
            parsed = _build_package_advisory(entry, default_distro=distro_hint) if isinstance(entry, dict) else None
            if parsed:
                pkg_rules.append(parsed)
        for entry in _safe_list(payload.get("osv_records")):
            parsed = _build_package_advisory_from_osv(entry, distro_hint) if isinstance(entry, dict) else None
            if parsed:
                pkg_rules.append(parsed)
        for entry in _safe_list(payload.get("oval_definitions")):
            parsed = _build_package_advisory_from_oval(entry, distro_hint) if isinstance(entry, dict) else None
            if parsed:
                pkg_rules.append(parsed)
        for entry in _safe_list(payload.get("service_rules")):
            parsed = _build_service_rule(entry) if isinstance(entry, dict) else None
            if parsed:
                svc_rules.append(parsed)
        for entry in _safe_list(payload.get("kernel_rules")):
            parsed = _build_kernel_rule(entry) if isinstance(entry, dict) else None
            if parsed:
                kernel_rules.append(parsed)

    return pkg_rules, svc_rules, kernel_rules


def reload_agent_rules(path: Path | None = None) -> None:
    """
    Clear cached external agent rules. Optionally prime the cache for the given path.
    """
    _external_agent_rules_cached.cache_clear()
    if path:
        _external_agent_rules(path)


def agent_rule_counts(path: Path | None = None) -> tuple[int, int, int]:
    pkg, svc, kernel = _external_agent_rules(path)
    return len(pkg), len(svc), len(kernel)


def _all_package_advisories() -> List[PackageAdvisory]:
    external_pkg, _, _ = _external_agent_rules()
    return PACKAGE_ADVISORIES + external_pkg


def _all_service_rules() -> List[ServiceRule]:
    _, external_svc, _ = _external_agent_rules()
    return SERVICE_RULES + external_svc


def service_rule_cpe_templates() -> Dict[str, str]:
    """
    Build a mapping of normalized service names to CPE templates from service rules.
    """
    templates: Dict[str, str] = {}
    for rule in _all_service_rules():
        if not rule.cpe_template:
            continue
        for name in rule.names:
            normalized = normalize_service_name(name)
            templates.setdefault(normalized, rule.cpe_template)
    return templates


def _all_kernel_rules() -> List[KernelRule]:
    _, _, external_kernel = _external_agent_rules()
    return KERNEL_RULES + external_kernel


def _version_tuple(version: str) -> Tuple[int | str, ...]:
    tokens = re.findall(r"[0-9]+|[a-zA-Z]+", version)
    if not tokens:
        return (0,)
    parsed: List[int | str] = []
    for token in tokens[:12]:
        if token.isdigit():
            parsed.append(int(token))
        else:
            parsed.append(token.lower())
    return tuple(parsed)  # type: ignore[return-value]


def _version_lt(current: str, reference: str) -> bool:
    return _version_tuple(current) < _version_tuple(reference)


def _version_between(current: str, minimum: Optional[str], maximum: Optional[str]) -> bool:
    cur = _version_tuple(current)
    try:
        if minimum and cur < _version_tuple(minimum):
            return False
        if maximum and cur >= _version_tuple(maximum):
            return False
    except TypeError:
        # Mixed type comparisons (str vs int) indicate non-semver strings; treat as non-matching
        return False
    return True


def _extract_version_number(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    match = re.search(r"\d+(?:\.\d+)+", raw)
    if match:
        return match.group(0)
    match = re.search(r"\d+", raw)
    if match:
        return match.group(0)
    return None


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
        for advisory in _all_package_advisories():
            if normalize_package_name(advisory.package) != name:
                continue
            if advisory.distro_hint and advisory.distro_hint not in distro:
                continue
            if advisory.min_version and not _version_between(version, advisory.min_version, None):
                continue
            if not _version_lt(version, advisory.fixed_version):
                continue
            rule_source = advisory.source or "agent_advisory"
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
                        "rule_source": rule_source,
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
                    evidence_grade=grade_evidence(evidence),
                    why_trace=build_why_trace(advisory.rule_id, summary, source=rule_source),
                    rule_source=rule_source,
                )
            )
    return findings


def _match_kernel_rules(kernel_version: Optional[str]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    if not kernel_version:
        return findings
    numeric = _extract_version_number(kernel_version)
    normalized = normalize_version(numeric or kernel_version)
    for rule in _all_kernel_rules():
        if not _version_between(normalized, rule.min_version, rule.max_version):
            continue
        rule_source = rule.source or "agent_advisory"
        summary = f"Kernel {normalized} matches {rule.description}"
        evidence = [
            {
                "type": "kernel_version",
                "summary": summary,
                "data": {
                    "kernel_version": normalized,
                    "min_version": rule.min_version,
                    "max_version": rule.max_version,
                    "rule_source": rule_source,
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
                rule_source=rule_source,
            )
        )
    return findings


def _match_os_rules(os_name: Optional[str], os_version: Optional[str], distro: Optional[str]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    distro_field = _safe_str(distro or os_name).lower()
    version = _extract_version_number(_safe_str(os_version))
    if not distro_field or not version:
        return findings
    for rule in OS_RULES:
        if not any(token in distro_field for token in rule.distro_match):
            continue
        if rule.version_lt and not _version_lt(version, rule.version_lt):
            continue
        rule_source = rule.source or "agent_advisory"
        summary = f"{distro or os_name} {version} is end-of-life (<{rule.version_lt})"
        evidence = [
            {
                "type": "os_release",
                "summary": summary,
                "data": {
                    "os_name": os_name,
                    "os_version": os_version,
                    "distro": distro,
                    "rule_source": rule_source,
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
                evidence_grade=grade_evidence(evidence),
                why_trace=build_why_trace(rule.rule_id, summary, source=rule_source),
                rule_source=rule_source,
            )
        )
    return findings


def _match_service_rules(services: Iterable[Any], packages: Iterable[Any] | None = None) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    pkg_versions: Dict[str, str] = {}
    if packages:
        for pkg in packages:
            name, version = _normalize_package(pkg)
            if not name or not version:
                continue
            if name not in pkg_versions:
                pkg_versions[name] = version
    for svc in services:
        raw_name = _get_value(svc, "name") or ""
        name = normalize_service_name(str(raw_name))
        version = normalize_version(str(_get_value(svc, "version") or ""))
        if not version:
            # Attempt to map service to package version when not provided
            pkg_match = pkg_versions.get(name)
            if not pkg_match:
                # fallback: match packages that start with service name (e.g., openssh-server -> ssh)
                for pkg_name, pkg_version in pkg_versions.items():
                    if pkg_name.startswith(name):
                        pkg_match = pkg_version
                        break
            if pkg_match:
                version = pkg_match
        port = _get_value(svc, "port")
        protocol = _get_value(svc, "protocol")
        for rule in _all_service_rules():
            if name not in {normalize_service_name(n) for n in rule.names}:
                continue
            if rule.version_lt and version and not _version_lt(version, rule.version_lt):
                continue
            rule_source = rule.source or "agent_advisory"
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
                        "rule_source": rule_source,
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
                    evidence_grade=grade_evidence(evidence),
                    why_trace=build_why_trace(rule.rule_id, summary, source=rule_source),
                    rule_source=rule_source,
                )
            )
        for keyword, severity, description in LEGACY_SERVICE_KEYWORDS:
            if keyword not in name:
                continue
            summary = f"{name} service listening on {port or 'unknown port'}"
            rule_source = "builtin"
            evidence = [
                {
                    "type": "legacy_service",
                    "summary": summary,
                    "data": {"service": name, "port": port, "protocol": protocol, "rule_source": rule_source},
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
                    evidence_grade=grade_evidence(evidence),
                    why_trace=build_why_trace(f"AGENT-SVC-LEGACY-{keyword.upper()}", summary, source=rule_source),
                    rule_source=rule_source,
                )
            )
    return findings


def _evaluate_ssh_config(configs: Dict[str, str]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    if not configs:
        return findings
    ssh_config = None
    ssh_client_config = None
    for key, value in configs.items():
        lowered = key.lower()
        if "sshd" in lowered or lowered.endswith("sshd_config"):
            ssh_config = value
            continue
        if "ssh_config" in lowered or "ssh client" in lowered:
            ssh_client_config = value
    if not ssh_config:
        return findings
    parsed = parse_sshd_config(ssh_config)
    permit_root = parsed.get("permit_root_login", "unknown")
    password_auth = parsed.get("password_authentication", "unknown")
    ciphers = parsed.get("ciphers") if isinstance(parsed.get("ciphers"), list) else []
    macs = parsed.get("macs") if isinstance(parsed.get("macs"), list) else []
    kex = parsed.get("kex_algorithms") if isinstance(parsed.get("kex_algorithms"), list) else []

    rule_source = "builtin-config"
    if permit_root not in {"no", "prohibit-password", "without-password"}:
        summary = f"PermitRootLogin set to {permit_root}"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-MISCONFIG-ROOT",
                severity="high",
                description="Root login over SSH is permitted; disable PermitRootLogin for hardening.",
                evidence_summary=summary,
                evidence=[
                    {
                        "type": "sshd_config",
                        "summary": summary,
                        "data": {"permit_root_login": permit_root, "rule_source": rule_source},
                    }
                ],
                evidence_grade="medium",
                why_trace=build_why_trace("AGENT-SSH-MISCONFIG-ROOT", summary, source=rule_source),
                rule_source=rule_source,
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
                        "data": {"password_authentication": password_auth, "rule_source": rule_source},
                    }
                ],
                evidence_grade="medium",
                why_trace=build_why_trace("AGENT-SSH-MISCONFIG-PASSWORDS", summary, source=rule_source),
                rule_source=rule_source,
            )
        )
    if "permitemptypasswords yes" in ssh_config.lower():
        summary = "PermitEmptyPasswords enabled"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-MISCONFIG-EMPTY-PASSWORDS",
                severity="high",
                description="Empty passwords allowed in sshd_config; disable PermitEmptyPasswords.",
                evidence_summary=summary,
                evidence=[{"type": "sshd_config", "summary": summary, "data": {"rule_source": rule_source}}],
                evidence_grade="high",
                why_trace=build_why_trace("AGENT-SSH-MISCONFIG-EMPTY-PASSWORDS", summary, source=rule_source),
                rule_source=rule_source,
            )
        )
    weak_cipher_hits = sorted({algo for algo in ciphers if algo in WEAK_SSH_CIPHERS})
    if weak_cipher_hits:
        summary = f"Weak SSH ciphers enabled: {', '.join(weak_cipher_hits)}"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-MISCONFIG-WEAK-CIPHERS",
                severity="medium",
                description="sshd_config permits legacy/weak ciphers; restrict to AES-GCM or CHACHA20.",
                evidence_summary=summary,
                evidence=[
                    {
                        "type": "sshd_config",
                        "summary": summary,
                        "data": {"ciphers": weak_cipher_hits, "rule_source": rule_source},
                    }
                ],
                evidence_grade="medium",
                why_trace=build_why_trace("AGENT-SSH-MISCONFIG-WEAK-CIPHERS", summary, source=rule_source),
                rule_source=rule_source,
            )
        )
    weak_mac_hits = sorted({algo for algo in macs if algo in WEAK_SSH_MACS})
    if weak_mac_hits:
        summary = f"Weak SSH MACs enabled: {', '.join(weak_mac_hits)}"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-MISCONFIG-WEAK-MACS",
                severity="medium",
                description="sshd_config permits weak MACs; prefer hmac-sha2 or gcm-based integrity.",
                evidence_summary=summary,
                evidence=[
                    {
                        "type": "sshd_config",
                        "summary": summary,
                        "data": {"macs": weak_mac_hits, "rule_source": rule_source},
                    }
                ],
                evidence_grade="medium",
                why_trace=build_why_trace("AGENT-SSH-MISCONFIG-WEAK-MACS", summary, source=rule_source),
                rule_source=rule_source,
            )
        )
    weak_kex_hits = sorted({algo for algo in kex if algo in WEAK_SSH_KEX})
    if weak_kex_hits:
        summary = f"Weak SSH KEX algorithms enabled: {', '.join(weak_kex_hits)}"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-MISCONFIG-WEAK-KEX",
                severity="medium",
                description="sshd_config permits legacy Diffie-Hellman key exchange; prefer modern curves and group-exchange.",
                evidence_summary=summary,
                evidence=[
                    {
                        "type": "sshd_config",
                        "summary": summary,
                        "data": {"kex": weak_kex_hits, "rule_source": rule_source},
                    }
                ],
                evidence_grade="medium",
                why_trace=build_why_trace("AGENT-SSH-MISCONFIG-WEAK-KEX", summary, source=rule_source),
                rule_source=rule_source,
            )
        )
    return findings


def _evaluate_ssh_client_config(raw_config: Optional[str]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    if not raw_config:
        return findings
    rule_source = "builtin-config"
    ciphers = _extract_algorithm_list(raw_config, "ciphers")
    macs = _extract_algorithm_list(raw_config, "macs")
    kex = _extract_algorithm_list(raw_config, "kexalgorithms")
    weak_ciphers = sorted({algo for algo in ciphers if algo in WEAK_SSH_CIPHERS})
    weak_macs = sorted({algo for algo in macs if algo in WEAK_SSH_MACS})
    weak_kex = sorted({algo for algo in kex if algo in WEAK_SSH_KEX})
    if weak_ciphers:
        summary = "SSH client allows weak ciphers"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-CLIENT-WEAK-CIPHERS",
                severity="medium",
                description="SSH client config permits weak ciphers; restrict to modern AES-GCM/CHACHA20.",
                evidence_summary=summary,
                evidence=[
                    {
                        "type": "ssh_client_config",
                        "summary": summary,
                        "data": {"ciphers": weak_ciphers, "rule_source": rule_source},
                    }
                ],
                rule_source=rule_source,
            )
        )
    if weak_macs:
        summary = "SSH client allows weak MACs"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-CLIENT-WEAK-MACS",
                severity="medium",
                description="SSH client config permits weak MACs; prefer hmac-sha2 or gcm modes.",
                evidence_summary=summary,
                evidence=[
                    {"type": "ssh_client_config", "summary": summary, "data": {"macs": weak_macs, "rule_source": rule_source}}
                ],
                rule_source=rule_source,
            )
        )
    if weak_kex:
        summary = "SSH client allows weak key exchange"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SSH-CLIENT-WEAK-KEX",
                severity="medium",
                description="SSH client config permits weak Diffie-Hellman KEX; prefer curve25519 or ecdh-sha2-nistp256+.",
                evidence_summary=summary,
                evidence=[
                    {"type": "ssh_client_config", "summary": summary, "data": {"kex": weak_kex, "rule_source": rule_source}}
                ],
                rule_source=rule_source,
            )
        )
    return findings


def _evaluate_sudoers_config(raw_config: Optional[str]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    if not raw_config:
        return findings
    rule_source = "builtin-config"
    if "NOPASSWD" in raw_config:
        summary = "NOPASSWD sudoers entry detected"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SUDO-MISCONFIG-NOPASSWD",
                severity="medium",
                description="Sudoers contains NOPASSWD entries; enforce MFA/password prompts for sudo.",
                evidence_summary=summary,
                evidence=[{"type": "sudoers", "summary": summary, "data": {"rule_source": rule_source}}],
                evidence_grade="medium",
                why_trace=build_why_trace("AGENT-SUDO-MISCONFIG-NOPASSWD", summary, source=rule_source),
                rule_source=rule_source,
            )
        )
    if "authenticate" in raw_config and "!authenticate" in raw_config.lower():
        summary = "Sudoers contains !authenticate directive"
        findings.append(
            AgentFindingCandidate(
                rule_id="AGENT-SUDO-MISCONFIG-NOAUTH",
                severity="high",
                description="Sudoers disables authentication for some commands; require authentication for sudo.",
                evidence_summary=summary,
                evidence=[{"type": "sudoers", "summary": summary, "data": {"rule_source": rule_source}}],
                rule_source=rule_source,
            )
        )
    timeout_match = re.search(r"timestamp_timeout\s*=\s*(-?\d+)", raw_config, flags=re.IGNORECASE)
    if timeout_match:
        try:
            timeout_value = int(timeout_match.group(1))
        except Exception:
            timeout_value = None
        if timeout_value is not None and timeout_value < 0:
            summary = "Sudoers disables timestamp timeout (no re-authentication)"
            findings.append(
                AgentFindingCandidate(
                    rule_id="AGENT-SUDO-MISCONFIG-NO-TIMEOUT",
                    severity="medium",
                    description="Sudoers timestamp_timeout is -1; require periodic re-authentication for sudo.",
                    evidence_summary=summary,
                    evidence=[{"type": "sudoers", "summary": summary, "data": {"rule_source": rule_source}}],
                    evidence_grade="medium",
                    why_trace=build_why_trace("AGENT-SUDO-MISCONFIG-NO-TIMEOUT", summary, source=rule_source),
                    rule_source=rule_source,
                )
            )
    return findings


def _evaluate_file_permissions(files: Iterable[Any]) -> List[AgentFindingCandidate]:
    findings: List[AgentFindingCandidate] = []
    rule_source = "builtin-files"
    for f in files:
        path = _safe_str(_get_value(f, "path") or _get_value(f, "name"))
        mode = _parse_mode(_get_value(f, "mode") or _get_value(f, "permissions"))
        if not path or mode is None:
            continue
        if path.endswith("shadow") and _is_world_readable(mode):
            summary = f"{path} is world-readable ({oct(mode)})"
            findings.append(
                AgentFindingCandidate(
                    rule_id="AGENT-FILE-PERMS-SHADOW-WORLD",
                    severity="critical",
                    description="/etc/shadow (or equivalent) should not be world-readable.",
                    evidence_summary=summary,
                    evidence=[
                        {
                            "type": "file_perms",
                            "summary": summary,
                            "data": {"path": path, "mode": oct(mode), "rule_source": rule_source},
                        }
                    ],
                    evidence_grade="high",
                    why_trace=build_why_trace("AGENT-FILE-PERMS-SHADOW-WORLD", summary, source=rule_source),
                    rule_source=rule_source,
                )
            )
        if path.endswith("passwd") and _is_world_writable(mode):
            summary = f"{path} is world-writable ({oct(mode)})"
            findings.append(
                AgentFindingCandidate(
                    rule_id="AGENT-FILE-PERMS-PASSWD-WORLD",
                    severity="high",
                    description="/etc/passwd (or equivalent) should not be world-writable.",
                    evidence_summary=summary,
                    evidence=[
                        {
                            "type": "file_perms",
                            "summary": summary,
                            "data": {"path": path, "mode": oct(mode), "rule_source": rule_source},
                        }
                    ],
                    evidence_grade="high",
                    why_trace=build_why_trace("AGENT-FILE-PERMS-PASSWD-WORLD", summary, source=rule_source),
                    rule_source=rule_source,
                )
            )
        if any(path.endswith(key) for key in ("id_rsa", "id_dsa", "id_ed25519")) and _is_world_readable(mode):
            summary = f"Private key {path} is world-readable ({oct(mode)})"
            findings.append(
                AgentFindingCandidate(
                    rule_id="AGENT-FILE-PERMS-SSH-KEY-WORLD",
                    severity="high",
                    description="SSH private key files should be owner-only readable (0600).",
                    evidence_summary=summary,
                    evidence=[
                        {
                            "type": "file_perms",
                            "summary": summary,
                            "data": {"path": path, "mode": oct(mode), "rule_source": rule_source},
                        }
                    ],
                    evidence_grade="high",
                    why_trace=build_why_trace("AGENT-FILE-PERMS-SSH-KEY-WORLD", summary, source=rule_source),
                    rule_source=rule_source,
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
    files = _get_value(inventory, "files") or []
    kernel_version = _get_value(inventory, "kernel_version")
    os_name = _get_value(inventory, "os_name")
    os_version = _get_value(inventory, "os_version")
    distro = _get_value(inventory, "distro")

    findings: List[AgentFindingCandidate] = []
    findings.extend(_match_package_advisories(inventory, packages))
    findings.extend(_match_kernel_rules(kernel_version))
    findings.extend(_match_os_rules(os_name, os_version, distro))
    findings.extend(_match_service_rules(services, packages))
    config_map = configs if isinstance(configs, dict) else {}
    findings.extend(_evaluate_ssh_config(config_map))
    findings.extend(
        _evaluate_ssh_client_config(
            config_map.get("ssh_config") if isinstance(config_map.get("ssh_config"), str) else None
        )
    )
    findings.extend(_evaluate_sudoers_config(config_map.get("sudoers") if isinstance(config_map.get("sudoers"), str) else None))
    findings.extend(_evaluate_file_permissions(files if isinstance(files, list) else []))
    for cand in findings:
        if cand.evidence and not cand.evidence_grade:
            cand.evidence = dedupe_evidence(cand.evidence)
            cand.evidence_grade = grade_evidence(cand.evidence)
        if not cand.why_trace:
            cand.why_trace = build_why_trace(cand.rule_id, cand.evidence_summary, source=cand.rule_source)
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
    observation_candidates: List[tuple[Finding, AgentFindingCandidate]] = []
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
            evidence_grade=cand.evidence_grade,
            why_trace=cand.why_trace,
            rule_id=cand.rule_id,
            severity=cand.severity,
            cve_ids=cve_json,
            description=cand.description,
        )
        session.add(finding)
        persisted.append(finding)
        if cand.service_name:
            observation_candidates.append((finding, cand))
    if persisted:
        session.flush()
        if observation_candidates:
            observations: Dict[int, ServiceObservation] = {}
            for finding, cand in observation_candidates:
                if finding.id is None:
                    continue
                normalized_service = normalize_service_name(cand.service_name or "")
                if not normalized_service:
                    continue
                observations[finding.id] = ServiceObservation(
                    asset_id=asset_id or 0,
                    host_address=host_address,
                    host_os_name=os_name,
                    host_os_accuracy=None,
                    host_vendor=str(distro) if distro else None,
                    traceroute_summary=None,
                    host_report=None,
                    port=cand.port or 0,
                    protocol=cand.protocol or "",
                    service_name=normalized_service,
                    service_version=cand.service_version,
                    product=normalized_service,
                    version_confidence=None,
                    fingerprint=None,
                    evidence=cand.evidence,
                    evidence_summary=cand.evidence_summary,
                )
            if observations:
                from clanker.core.enrichment import enrich_cpe_only  # avoid import cycle at module load

                enrich_cpe_only(session, [f for f in persisted if f.id in observations], observations)
        logger.info("Persisted %s agent findings (ingest_id=%s)", len(persisted), ingest_id)
    return persisted


__all__ = [
    "evaluate_inventory",
    "persist_agent_findings",
    "AgentFindingCandidate",
    "reload_agent_rules",
    "agent_rule_counts",
]
