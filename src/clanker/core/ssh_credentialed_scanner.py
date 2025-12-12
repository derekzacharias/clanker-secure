"""
Credentialed SSH scanning utilities built on Paramiko.

This module provides a reusable SSHScanner class capable of authenticating
with either passwords or private keys, executing a consistent set of commands
to enumerate host details, and returning structured results that can be fed
into a larger vulnerability scanning pipeline.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional

try:
    import paramiko
    from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError, SSHException

    _PARAMIKO_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    paramiko = None  # type: ignore[assignment]
    _PARAMIKO_AVAILABLE = False

    class AuthenticationException(Exception):
        pass

    class SSHException(Exception):
        pass

    class NoValidConnectionsError(Exception):
        pass

from clanker.core.agent_parsers import parse_file_stats, parse_sshd_config
from clanker.core.agent_parsers import parse_dpkg_list, parse_kernel_release, parse_listening_services, parse_rpm_qa

Logger = logging.Logger


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class CommandResult:
    """Container for the result of a single command execution."""

    name: str
    command: str
    stdout: str
    stderr: str
    exit_status: Optional[int]
    unavailable: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_status": self.exit_status,
            "unavailable": self.unavailable,
            "error": self.error,
        }


class SSHScanner:
    """
    Perform credentialed SSH scans across one or more hosts.

    Typical usage:
        scanner = SSHScanner(max_workers=5, verbose=True)
        results = scanner.scan_all(hosts)
    """

    def __init__(
        self,
        hosts: Optional[Iterable[str | Dict[str, Any]]] = None,
        port: int = 22,
        timeout: int = 10,
        command_timeout: int = 30,
        max_workers: int = 4,
        verbose: bool = False,
        max_retries: int = 1,
    ) -> None:
        """
        Initialize a new SSH scanner.

        Args:
            hosts: Optional host or iterable of hosts to scan. Hosts may be strings
                (hostname or IP) or dicts with authentication details.
            port: Default SSH port to use when none is specified in a host config.
            timeout: Socket, banner, and auth timeout in seconds.
            command_timeout: Time in seconds to allow each remote command to run.
            max_workers: Maximum number of concurrent scans.
            verbose: When True, enable INFO-level logging. Otherwise, warnings only.
            max_retries: Number of retry attempts per host before marking as failed.
        """
        self.hosts = self._normalize_hosts(hosts)
        self.port = port
        self.timeout = timeout
        self.command_timeout = command_timeout
        self.max_workers = max_workers
        self.logger = self._configure_logger(verbose)
        self.command_plan = self._build_default_command_plan()
        self._stats_lock = Lock()
        self.max_retries = max(0, max_retries)
        self._stats = {"started": 0, "succeeded": 0, "failed": 0, "retries": 0}

    @staticmethod
    def _configure_logger(verbose: bool) -> Logger:
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO if verbose else logging.WARNING)
        return logger

    def _log_metric(self, event: str, payload: Dict[str, Any]) -> None:
        try:
            self.logger.info("%s %s", event, json.dumps(payload))
        except Exception:
            self.logger.info("%s %s", event, payload)

    @staticmethod
    def _normalize_hosts(
        hosts: Optional[Iterable[str | Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        if hosts is None:
            return normalized
        for host in hosts:
            if isinstance(host, str):
                normalized.append({"host": host})
            elif isinstance(host, dict):
                normalized.append(host)
        return normalized

    @staticmethod
    def _build_default_command_plan() -> List[Dict[str, str]]:
        """
        Define the baseline commands to run on each host.
        """
        return [
            {"name": "system.uname", "command": "uname -a"},
            {"name": "system.kernel_release", "command": "uname -r"},
            {"name": "system.os_release", "command": "cat /etc/os-release || cat /etc/issue"},
            {"name": "system.issue", "command": "cat /etc/issue"},
            {"name": "system.proc_version", "command": "cat /proc/version"},
            {"name": "system.lsb_release", "command": "lsb_release -a"},
            {
                "name": "packages.dpkg",
                "command": "dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n' || dpkg -l",
            },
            {
                "name": "packages.rpm",
                "command": "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n' || rpm -qa",
            },
            {"name": "network.ss", "command": "ss -tulpn"},
            {"name": "network.netstat", "command": "netstat -tulpn"},
            {
                "name": "services.systemctl",
                "command": "systemctl list-units --type=service --state=running --no-legend --no-pager",
            },
            {"name": "ssh.config", "command": "cat /etc/ssh/sshd_config"},
            {"name": "ssh.client_config", "command": "cat /etc/ssh/ssh_config"},
            {"name": "auth.sudoers", "command": "cat /etc/sudoers"},
            {
                "name": "files.perms",
                "command": "for f in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/ssh/ssh_config /root/.ssh/id_* /home/*/.ssh/id_*; do [ -e \"$f\" ] && stat -c '%n %a' \"$f\"; done 2>/dev/null",
            },
        ]

    def scan_all(self, hosts: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Scan all provided hosts, optionally overriding the hosts configured at init.

        Args:
            hosts: List of host configuration dictionaries. Each dict should include
                at least the "host" key and optionally "port", "username", "password",
                "key_path", "passphrase", "allow_agent", and "look_for_keys".

        Returns:
            List of result dictionaries, one per host.
        """
        hosts_to_scan = hosts if hosts is not None else self.hosts
        if not hosts_to_scan:
            self.logger.warning("No hosts provided for scanning.")
            return []

        results: List[Dict[str, Any]] = []
        started_at = time.perf_counter()
        with self._stats_lock:
            self._stats = {
                "started": len(hosts_to_scan),
                "succeeded": 0,
                "failed": 0,
                "retries": 0,
            }
        self._log_metric(
            "ssh_scan_batch_start",
            {"hosts": self._stats["started"], "max_workers": self.max_workers, "max_retries": self.max_retries},
        )
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {
                executor.submit(self.scan_host, host_cfg): host_cfg for host_cfg in hosts_to_scan
            }
            for future in as_completed(future_map):
                try:
                    results.append(future.result())
                except Exception as exc:  # Defensive: ensure one failure doesn't break the batch
                    host = future_map[future].get("host")
                    self.logger.error("Unhandled exception while scanning %s: %s", host, exc)
                    results.append(
                        {
                            "host": host,
                            "status": "failed",
                            "error": f"Unexpected failure: {exc}",
                        }
                    )
                    with self._stats_lock:
                        self._stats["failed"] += 1
        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
        with self._stats_lock:
            stats_snapshot = dict(self._stats)
        self._log_metric(
            "ssh_scan_batch_complete",
            {
                "hosts": stats_snapshot.get("started", 0),
                "succeeded": stats_snapshot.get("succeeded", 0),
                "failed": stats_snapshot.get("failed", 0),
                "retries": stats_snapshot.get("retries", 0),
                "duration_ms": duration_ms,
            },
        )
        return results

    def scan_host(self, host_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Connect to and scan a single host.

        Args:
            host_config: Dictionary with connection and auth details for the host.

        Returns:
            A dictionary describing the scan result including command outputs and any errors.
        """
        host = host_config.get("host")
        if not host:
            return {"host": None, "status": "failed", "error": "Host is required"}

        port = host_config.get("port", self.port)
        username = host_config.get("username")
        password = host_config.get("password")
        key_path = host_config.get("key_path")
        passphrase = host_config.get("passphrase")
        allow_agent = host_config.get("allow_agent", False)
        look_for_keys = host_config.get("look_for_keys", False)
        auth_method = "key" if key_path else "password" if password else "unspecified"

        result: Dict[str, Any] = {
            "host": host,
            "port": port,
            "username": username,
            "auth_method": auth_method,
            "host_id": host_config.get("host_id"),
            "status": "failed",
            "error": None,
            "commands": [],
            "ssh_config_hardening": {},
            "started_at": utc_timestamp(),
            "completed_at": None,
            "attempts": 0,
        }

        if not _PARAMIKO_AVAILABLE:
            result["status"] = "unavailable"
            result["error"] = "paramiko is not installed; install optional dependency for SSH scans"
            result["completed_at"] = utc_timestamp()
            self.logger.warning("Skipping SSH scan for %s: paramiko not installed", host)
            return result

        attempts = 0
        while True:
            attempts += 1
            result["attempts"] = attempts
            attempt_start = time.perf_counter()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    key_filename=key_path,
                    passphrase=passphrase,
                    timeout=self.timeout,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout,
                    allow_agent=allow_agent,
                    look_for_keys=look_for_keys,
                )
                self.logger.info("Connected to %s", host)
                command_results = [self._run_command(client, cmd["name"], cmd["command"]) for cmd in self.command_plan]
                result["commands"] = [cmd.to_dict() for cmd in command_results]
                ssh_config_output = next(
                    (cmd.stdout for cmd in command_results if cmd.name == "ssh.config" and not cmd.unavailable),
                    "",
                )
                if ssh_config_output:
                    result["ssh_config_hardening"] = self._analyze_ssh_config(ssh_config_output)
                result["status"] = "success"
            except AuthenticationException as exc:
                result["error"] = f"Authentication failed: {exc}"
                self.logger.warning("Authentication failed for %s", host)
            except (socket.timeout, TimeoutError) as exc:
                result["error"] = f"Connection timed out: {exc}"
                self.logger.warning("Timeout while connecting to %s", host)
            except NoValidConnectionsError as exc:
                result["error"] = f"Unable to connect to {host}:{port} - {exc}"
                self.logger.warning("No valid connections for %s:%s", host, port)
            except SSHException as exc:
                result["error"] = f"SSH negotiation failed: {exc}"
                self.logger.warning("SSH negotiation error for %s: %s", host, exc)
            except Exception as exc:  # Catch-all to prevent a single host from killing the batch
                result["error"] = f"Unhandled error: {exc}"
                self.logger.error("Unhandled error while scanning %s: %s", host, exc)
            finally:
                result["completed_at"] = utc_timestamp()
                duration_ms = round((time.perf_counter() - attempt_start) * 1000, 2)
                self._log_metric(
                    "ssh_scan_host",
                    {
                        "host": host,
                        "status": result["status"],
                        "attempt": attempts,
                        "max_retries": self.max_retries,
                        "duration_ms": duration_ms,
                        "error": bool(result["error"]),
                    },
                )
                client.close()

            if result["status"] == "success":
                with self._stats_lock:
                    self._stats["succeeded"] += 1
                break
            if attempts > self.max_retries:
                with self._stats_lock:
                    self._stats["failed"] += 1
                break
            with self._stats_lock:
                self._stats["retries"] += 1
            time.sleep(1.0)
        return result

    def _run_command(self, client: paramiko.SSHClient, name: str, command: str) -> CommandResult:
        """
        Execute a command over an established SSH connection.
        """
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=self.command_timeout)
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode("utf-8", errors="replace")
            error_output = stderr.read().decode("utf-8", errors="replace")
            unavailable = exit_status == 127 or "not found" in error_output.lower()
            return CommandResult(
                name=name,
                command=command,
                stdout=output,
                stderr=error_output,
                exit_status=exit_status,
                unavailable=unavailable,
                error=None,
            )
        except Exception as exc:
            return CommandResult(
                name=name,
                command=command,
                stdout="",
                stderr=str(exc),
                exit_status=None,
                unavailable=False,
                error=str(exc),
            )

    @staticmethod
    def _analyze_ssh_config(config_text: str) -> Dict[str, Any]:
        """
        Perform a minimal hardening assessment of sshd_config content.
        """
        permit_root = "unknown"
        password_auth = "unknown"
        for raw_line in config_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("permitrootlogin"):
                parts = line.split()
                if len(parts) >= 2:
                    permit_root = parts[1].lower()
            if line.lower().startswith("passwordauthentication"):
                parts = line.split()
                if len(parts) >= 2:
                    password_auth = parts[1].lower()
        return {
            "permit_root_login": permit_root,
            "password_authentication": password_auth,
        }

    @staticmethod
    def extract_basic_facts(result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Pull a minimal fact set (os, kernel, running services) from a scan result.
        """
        facts: Dict[str, Any] = {}
        commands = result.get("commands") or []

        def _find(name: str) -> Optional[Dict[str, Any]]:
            for cmd in commands:
                if cmd.get("name") == name:
                    return cmd
            return None

        os_release = _find("system.os_release")
        if os_release and os_release.get("stdout"):
            for line in os_release["stdout"].splitlines():
                if line.startswith("PRETTY_NAME="):
                    facts["os"] = line.split("=", 1)[1].strip().strip('"')
                    break
        if "os" not in facts:
            issue = _find("system.issue")
            if issue and issue.get("stdout"):
                facts["os"] = issue["stdout"].splitlines()[0].strip()

        uname = _find("system.uname")
        if uname and uname.get("stdout"):
            parts = uname["stdout"].split()
            if len(parts) >= 3:
                facts["kernel"] = parts[2]
        if "kernel" not in facts:
            proc_version = _find("system.proc_version")
            if proc_version and proc_version.get("stdout"):
                facts["kernel"] = proc_version["stdout"].strip()

        systemctl = _find("services.systemctl")
        if systemctl and systemctl.get("stdout"):
            services = []
            for line in systemctl["stdout"].splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    services.append({"name": parts[0], "status": parts[2], "description": " ".join(parts[3:])})
            if services:
                facts["running_services"] = services[:50]

        if result.get("ssh_config_hardening"):
            facts["ssh_config"] = result["ssh_config_hardening"]

        return facts

    @staticmethod
    def to_agent_inventory(result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert an SSH scan result into an agent-style inventory payload so we can
        reuse the agent vuln evaluation pipeline.
        """
        commands = {cmd.get("name"): cmd for cmd in result.get("commands") or []}

        def _stdout(name: str) -> str:
            cmd = commands.get(name)
            if cmd and not cmd.get("unavailable"):
                return cmd.get("stdout") or ""
            return ""

        os_name = None
        os_version = None
        distro = None
        kernel_version = parse_kernel_release(_stdout("system.kernel_release"))

        os_release = _stdout("system.os_release")
        if os_release:
            for line in os_release.splitlines():
                if line.startswith("PRETTY_NAME=") and not os_name:
                    os_name = line.split("=", 1)[1].strip().strip('"')
                if line.startswith("VERSION_ID=") and not os_version:
                    os_version = line.split("=", 1)[1].strip().strip('"')
                if line.startswith("VERSION=") and not os_version:
                    os_version = line.split("=", 1)[1].strip().strip('"')
                if line.startswith("ID=") and not distro:
                    distro = line.split("=", 1)[1].strip().strip('"')
        if not os_name:
            issue = _stdout("system.issue")
            if issue:
                os_name = issue.splitlines()[0].strip()

        if not kernel_version:
            uname_out = _stdout("system.uname")
            kernel_version = parse_kernel_release(uname_out) or parse_kernel_release(_stdout("system.proc_version"))

        packages = []
        dpkg_out = _stdout("packages.dpkg")
        if dpkg_out:
            packages.extend(parse_dpkg_list(dpkg_out))
        rpm_out = _stdout("packages.rpm")
        if rpm_out:
            packages.extend(parse_rpm_qa(rpm_out))

        services = []
        seen_services = set()
        for svc_out in (_stdout("network.ss"), _stdout("network.netstat")):
            if not svc_out:
                continue
            for svc in parse_listening_services(svc_out):
                key = (svc.get("name"), svc.get("port"), svc.get("protocol"))
                if key in seen_services:
                    continue
                seen_services.add(key)
                services.append(svc)

        configs: Dict[str, str] = {}
        ssh_config = _stdout("ssh.config")
        if ssh_config:
            configs["sshd_config"] = ssh_config
        client_config = _stdout("ssh.client_config")
        if client_config:
            configs["ssh_config"] = client_config
        sudoers = _stdout("auth.sudoers")
        if sudoers:
            configs["sudoers"] = sudoers

        files = []
        file_stats_out = _stdout("files.perms")
        if file_stats_out:
            files.extend(parse_file_stats(file_stats_out))

        return {
            "host_identifier": result.get("host") or result.get("hostname"),
            "hostname": result.get("host") or result.get("hostname"),
            "os_name": os_name,
            "os_version": os_version,
            "kernel_version": kernel_version,
            "distro": distro,
            "packages": packages,
            "services": services,
            "interfaces": [],
            "configs": configs,
            "files": files,
            "collector_errors": {},
        }


def results_to_json(results: List[Dict[str, Any]]) -> str:
    """
    Convert a list of scan results to JSON for storage or transport.
    """
    return json.dumps(results, indent=2)
