from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

KNOWN_ARCHES = {
    "noarch",
    "x86_64",
    "amd64",
    "i386",
    "i686",
    "aarch64",
    "arm64",
    "s390x",
    "ppc64le",
}

# Common aliases to converge process names to service identifiers
SERVICE_ALIASES = {
    "sshd": "ssh",
    "httpd": "httpd",
    "apache": "httpd",
    "apache2": "httpd",
    "nginx": "nginx",
    "mysqld": "mysql",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "systemd-resolved": "systemd-resolved",
    "systemd-resolve": "systemd-resolved",
}


def normalize_package_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def normalize_version(version: str) -> str:
    value = version.strip()
    if ":" in value:
        value = value.split(":", 1)[1]
    return value


def parse_dpkg_list(output: str) -> List[Dict[str, Any]]:
    packages: List[Dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Desired=") or line.startswith("||/"):
            continue
        if not line.startswith("ii"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = normalize_package_name(parts[1])
        version = normalize_version(parts[2])
        arch = parts[3] if len(parts) > 3 else None
        packages.append(
            {
                "name": name,
                "version": version,
                "arch": arch,
                "source": "dpkg",
            }
        )
    return packages


def _split_rpm_arch(value: str) -> tuple[str, Optional[str]]:
    if "." not in value:
        return value, None
    prefix, suffix = value.rsplit(".", 1)
    if suffix in KNOWN_ARCHES:
        return prefix, suffix
    return value, None


def _split_rpm_name_version(value: str) -> tuple[str, str]:
    parts = value.split("-")
    if len(parts) < 2:
        return normalize_package_name(value), ""
    if len(parts) == 2:
        return normalize_package_name(parts[0]), normalize_version(parts[1])
    name = "-".join(parts[:-2]) or parts[0]
    version = "-".join(parts[-2:])
    return normalize_package_name(name), normalize_version(version)


def parse_rpm_qa(output: str) -> List[Dict[str, Any]]:
    packages: List[Dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        without_arch, arch = _split_rpm_arch(line)
        name, version = _split_rpm_name_version(without_arch)
        packages.append(
            {
                "name": name,
                "version": version,
                "arch": arch,
                "source": "rpm",
            }
        )
    return packages


def parse_kernel_release(output: str) -> Optional[str]:
    for raw_line in output.splitlines():
        match = re.search(r"\b\d+\.\d+(?:\.\d+)?[^\s]*", raw_line)
        if match:
            return match.group(0)
    return None


def normalize_service_name(name: str) -> str:
    base = name.strip().split("/")[-1].lower()
    base = base.replace("_", "-")
    base = re.sub(r"[^a-z0-9.+-]", "", base)
    return SERVICE_ALIASES.get(base, base)


def _extract_port(local: str) -> Optional[int]:
    if not local:
        return None
    target = local
    if "]" in local:
        target = local.split("]", 1)[-1]
    if ":" not in target:
        return None
    port_part = target.rsplit(":", 1)[-1]
    if port_part.isdigit():
        try:
            return int(port_part)
        except ValueError:
            return None
    return None


def _extract_process_name(process_field: str) -> Optional[str]:
    if not process_field:
        return None
    quoted = re.search(r'"([^"]+)"', process_field)
    if quoted:
        return normalize_service_name(quoted.group(1))
    if "/" in process_field:
        return normalize_service_name(process_field.split("/")[-1])
    tokens = process_field.split()
    if tokens:
        return normalize_service_name(tokens[0])
    return None


def _extract_service_from_local(local: str) -> Optional[str]:
    if not local or ":" not in local:
        return None
    tail = local.rsplit(":", 1)[-1]
    if tail.isdigit():
        return None
    return normalize_service_name(tail)


def parse_listening_services(output: str) -> List[Dict[str, Any]]:
    services: List[Dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith(("netid", "proto", "state")):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            continue
        proto_raw = parts[0].lower()
        proto = "tcp" if "tcp" in proto_raw else "udp" if "udp" in proto_raw else proto_raw
        state = parts[1].lower() if len(parts) > 1 else "unknown"
        local = parts[4] if len(parts) > 4 else ""
        process_field = parts[-1] if parts else ""
        name = _extract_process_name(process_field) or _extract_service_from_local(local) or "unknown"
        services.append(
            {
                "name": name,
                "port": _extract_port(local),
                "protocol": proto,
                "status": "listening" if state.startswith("listen") else state,
                # banner/version fields may be added later by callers (e.g., package map enrichment)
            }
        )
    return services


def parse_file_stats(output: str) -> List[Dict[str, Any]]:
    """
    Parse simple `stat -c '%n %a'` output into structured file permission records.
    """
    files: List[Dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        path = parts[0]
        mode_raw = parts[1]
        try:
            mode_int = int(mode_raw, 8)
        except ValueError:
            continue
        files.append({"path": path, "mode": mode_int})
    return files


def parse_sshd_config(config_text: str) -> Dict[str, Any]:
    settings: Dict[str, str] = {}
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split(None, 1)
        if len(tokens) < 2:
            continue
        key = tokens[0].lower()
        value_raw = tokens[1].strip()
        if key in {"ciphers", "macs", "kexalgorithms"}:
            algos = re.split(r"[,\s]+", value_raw.lower())
            settings[key] = [algo for algo in algos if algo]
            continue
        value = value_raw.split()[0].lower()
        settings[key] = value
    return {
        "permit_root_login": settings.get("permitrootlogin", "unknown"),
        "password_authentication": settings.get("passwordauthentication", "unknown"),
        "challenge_response_auth": settings.get("challengeresponseauthentication", "unknown"),
        "max_auth_tries": settings.get("maxauthtries"),
        "port": settings.get("port"),
        "allow_users": settings.get("allowusers"),
        "allow_groups": settings.get("allowgroups"),
        "ciphers": settings.get("ciphers", []),
        "macs": settings.get("macs", []),
        "kex_algorithms": settings.get("kexalgorithms", []),
    }


__all__ = [
    "normalize_package_name",
    "normalize_version",
    "parse_dpkg_list",
    "parse_rpm_qa",
    "parse_kernel_release",
    "parse_listening_services",
    "parse_file_stats",
    "parse_sshd_config",
    "normalize_service_name",
]
