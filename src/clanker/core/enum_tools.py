from __future__ import annotations

import logging
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from clanker.config import settings
from clanker.core.types import ServiceObservation
from clanker.db.models import Asset

logger = logging.getLogger(__name__)

HTTP_PORTS: Set[int] = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443}
HTTPS_PORTS: Set[int] = {443, 8443, 9443}


@dataclass(frozen=True)
class ToolCommand:
    tool: str
    command: Sequence[str]
    output_path: Path
    description: str


def _enabled_tools() -> Set[str]:
    return {t.strip().lower() for t in settings.enum_tools_enabled.split(",") if t.strip()}


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _safe_target(asset: Asset) -> str:
    target = asset.target.strip()
    return target


def _http_targets(asset: Asset, observations: Iterable[ServiceObservation]) -> List[Tuple[str, int]]:
    targets: Set[Tuple[str, int]] = set()
    host = _safe_target(asset)
    for obs in observations:
        port = int(obs.port)
        name = (obs.service_name or "").lower()
        if port in HTTP_PORTS or "http" in name:
            scheme = "https" if "https" in name or port in HTTPS_PORTS else "http"
            targets.add((scheme, port))
    return sorted(targets, key=lambda pair: pair[1])


def _domain_from_target(target: str) -> Optional[str]:
    # Crude heuristic to avoid CIDR/URL parsing overhead
    if "://" in target or "/" in target or ":" in target:
        return None
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
        return target
    return None


def _render_command_output(cmd: Sequence[str], stdout: str, stderr: str, returncode: int) -> str:
    lines = [
        f"timestamp={datetime.utcnow().isoformat()}Z",
        f"command={shlex.join(cmd)}",
        f"return_code={returncode}",
        "",
    ]
    if stdout:
        lines.append("STDOUT:")
        lines.append(stdout)
    if stderr:
        lines.append("")
        lines.append("STDERR:")
        lines.append(stderr)
    return "\n".join(lines)


def _run_tool(cmd: ToolCommand) -> str:
    binary = cmd.command[0]
    if not _which(binary):
        return f"{cmd.tool}: skipped (binary '{binary}' not found)"
    try:
        proc = subprocess.run(
            cmd.command,
            capture_output=True,
            text=True,
            timeout=settings.enum_tool_timeout_seconds,
        )
        cmd.output_path.write_text(
            _render_command_output(cmd.command, proc.stdout or "", proc.stderr or "", proc.returncode),
            encoding="utf-8",
        )
        status = "completed" if proc.returncode == 0 else f"completed rc={proc.returncode}"
        return f"{cmd.tool}: {status} ({cmd.description}); output={cmd.output_path}"
    except subprocess.TimeoutExpired:
        return f"{cmd.tool}: timed out after {settings.enum_tool_timeout_seconds}s ({cmd.description})"
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Enumeration tool %s failed: %s", cmd.tool, exc)
        return f"{cmd.tool}: failed to run ({exc})"


def _build_http_commands(
    asset: Asset,
    scan_id: int,
    http_targets: List[Tuple[str, int]],
    enabled: Set[str],
) -> List[ToolCommand]:
    host = _safe_target(asset)
    commands: List[ToolCommand] = []
    for scheme, port in http_targets:
        url = f"{scheme}://{host}:{port}"
        suffix = f"{scheme}{port}"
        if "nikto" in enabled:
            commands.append(
                ToolCommand(
                    tool="nikto",
                    command=["nikto", "-h", url, "-ask", "no", "-nointeractive"],
                    output_path=settings.enum_tool_output_dir / f"scan{scan_id}_asset{asset.id}_nikto_{suffix}.txt",
                    description=f"nikto against {url}",
                )
            )
        if "whatweb" in enabled:
            commands.append(
                ToolCommand(
                    tool="whatweb",
                    command=["whatweb", "--color=never", "--no-errors", url],
                    output_path=settings.enum_tool_output_dir / f"scan{scan_id}_asset{asset.id}_whatweb_{suffix}.txt",
                    description=f"WhatWeb fingerprint for {url}",
                )
            )
        if "testssl" in enabled or "testssl.sh" in enabled:
            commands.append(
                ToolCommand(
                    tool="testssl.sh",
                    command=["testssl.sh", "--quiet", "--sneaky", "--fast", f"{host}:{port}"],
                    output_path=settings.enum_tool_output_dir / f"scan{scan_id}_asset{asset.id}_testssl_{suffix}.txt",
                    description=f"TLS scan {host}:{port} via testssl.sh",
                )
            )
        if "openssl" in enabled:
            commands.append(
                ToolCommand(
                    tool="openssl",
                    command=["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-brief"],
                    output_path=settings.enum_tool_output_dir / f"scan{scan_id}_asset{asset.id}_openssl_{suffix}.txt",
                    description=f"TLS handshake capture for {host}:{port}",
                )
            )
    return commands


def _build_dns_commands(asset: Asset, scan_id: int, enabled: Set[str]) -> List[ToolCommand]:
    commands: List[ToolCommand] = []
    domain = _domain_from_target(_safe_target(asset))
    if not domain:
        return commands
    if "amass" in enabled:
        commands.append(
            ToolCommand(
                tool="amass",
                command=["amass", "enum", "-d", domain, "-passive", "-timeout", "120"],
                output_path=settings.enum_tool_output_dir / f"scan{scan_id}_asset{asset.id}_amass.txt",
                description=f"Amass passive enum for {domain}",
            )
        )
    if "subfinder" in enabled:
        commands.append(
            ToolCommand(
                tool="subfinder",
                command=["subfinder", "-d", domain, "-silent"],
                output_path=settings.enum_tool_output_dir / f"scan{scan_id}_asset{asset.id}_subfinder.txt",
                description=f"Subfinder for {domain}",
            )
        )
    return commands


def _build_masscan(asset: Asset, scan_id: int, enabled: Set[str]) -> List[ToolCommand]:
    if "masscan" not in enabled:
        return []
    target = _safe_target(asset)
    if "://" in target:
        return []
    return [
        ToolCommand(
            tool="masscan",
            command=[
                "masscan",
                target,
                "-p1-65535",
                f"--rate={settings.enum_masscan_rate}",
                "--wait=1",
                "--open-only",
            ],
            output_path=settings.enum_tool_output_dir / f"scan{scan_id}_asset{asset.id}_masscan.txt",
            description=f"Port pre-scan for {target}",
        )
    ]


def _build_lynis(asset: Asset, scan_id: int, enabled: Set[str]) -> List[ToolCommand]:
    if "lynis" not in enabled:
        return []
    target = _safe_target(asset)
    if not settings.enum_allow_remote_lynis and target not in {"localhost", "127.0.0.1"}:
        return []
    return [
        ToolCommand(
            tool="lynis",
            command=["lynis", "audit", "system", "--quiet"],
            output_path=settings.enum_tool_output_dir / f"scan{scan_id}_asset{asset.id}_lynis.txt",
            description="Local host hardening audit via Lynis",
        )
    ]


def run_enum_tools(
    asset: Asset, observations: Sequence[ServiceObservation], scan_id: int
) -> List[str]:
    """
    Execute optional external enumeration tools for the given asset.
    Returns human-readable status lines suitable for scan events.
    """
    enabled = _enabled_tools()
    http_targets = _http_targets(asset, observations)

    commands: List[ToolCommand] = []
    commands.extend(_build_http_commands(asset, scan_id, http_targets, enabled))
    commands.extend(_build_dns_commands(asset, scan_id, enabled))
    commands.extend(_build_masscan(asset, scan_id, enabled))
    commands.extend(_build_lynis(asset, scan_id, enabled))

    statuses: List[str] = []
    for cmd in commands:
        statuses.append(_run_tool(cmd))
    if not commands:
        statuses.append("No external enumeration targets identified for this asset")
    return statuses
