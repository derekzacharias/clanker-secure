from __future__ import annotations

import re
import socket
import ssl
from typing import List, Optional, Sequence
import struct

import httpx

from clanker.config import settings
from clanker.core.types import ServiceObservation
from clanker.core.fingerprint.types import FingerprintEvidence, FingerprintResult

DEFAULT_TIMEOUT = settings.fingerprint_timeout_seconds


class Detector:
    name: str = "base"
    protocols: Sequence[str] = ("tcp",)

    def applies(self, observation: ServiceObservation) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def detect(self, host: str, observation: ServiceObservation) -> Optional[FingerprintResult]:  # pragma: no cover
        raise NotImplementedError


class HttpDetector(Detector):
    name = "http-basic"
    protocols = ("tcp",)
    http_ports = {80, 8000, 8080, 8088, 8081, 8888}
    https_ports = {443, 8443, 9443, 4443, 10443}

    def applies(self, observation: ServiceObservation) -> bool:
        if observation.protocol not in self.protocols:
            return False
        port = observation.port
        service = (observation.service_name or "").lower()
        return bool(
            port
            and (
                port in self.http_ports
                or port in self.https_ports
                or "http" in service
                or "ssl/http" in service
                or "https" in service
            )
        )

    def _choose_scheme(self, observation: ServiceObservation) -> str:
        service = (observation.service_name or "").lower()
        if observation.port in self.https_ports or "https" in service or "ssl/http" in service:
            return "https"
        return "http"

    def detect(self, host: str, observation: ServiceObservation) -> Optional[FingerprintResult]:
        scheme = self._choose_scheme(observation)
        url = f"{scheme}://{host}:{observation.port or 80}/"
        try:
            with httpx.Client(verify=False, timeout=DEFAULT_TIMEOUT, follow_redirects=settings.fingerprint_http_follow_redirects) as client:
                resp = client.get(url, headers={"User-Agent": "clanker-fp/0.1"})
        except Exception:
            return None
        server_header = resp.headers.get("server")
        powered_by = resp.headers.get("x-powered-by")
        title = _extract_title(resp.text or "")
        body_hash = _short_hash(resp.text or "")
        evidence = [
            FingerprintEvidence(
                type="http_response",
                summary=f"{resp.status_code} {resp.reason_phrase}",
                data={
                    "url": url,
                    "status_code": resp.status_code,
                    "reason": resp.reason_phrase,
                    "headers": dict(resp.headers),
                    "title": title,
                    "body_preview_hash": body_hash,
                },
            )
        ]
        summary_bits: List[str] = [f"{resp.status_code}"]
        if title:
            summary_bits.append(title[:80])
        if server_header:
            summary_bits.append(server_header)
        summary = " | ".join(summary_bits)
        product = server_header or powered_by
        confidence = 0.55 if product else 0.4
        return FingerprintResult(
            protocol="http",
            port=observation.port or 80,
            vendor=None,
            product=product,
            version=None,
            confidence=confidence,
            source="http_probe",
            attributes={
                "powered_by": powered_by,
                "title": title,
                "redirect_chain": [str(h.url) for h in resp.history] if resp.history else [],
            },
            evidence_summary=summary,
            evidence=evidence,
        )


class TlsDetector(Detector):
    name = "tls-handshake"
    tls_ports = {443, 8443, 9443, 993, 995, 587, 465, 10443, 4443}

    def applies(self, observation: ServiceObservation) -> bool:
        if observation.protocol != "tcp":
            return False
        port = observation.port or 0
        service = (observation.service_name or "").lower()
        return bool(port in self.tls_ports or "ssl" in service or "tls" in service or "https" in service)

    def detect(self, host: str, observation: ServiceObservation) -> Optional[FingerprintResult]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        port = observation.port or 443
        try:
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
                    version = tls_sock.version()
        except Exception:
            return None
        subject = _flatten_name(cert.get("subject", []))
        issuer = _flatten_name(cert.get("issuer", []))
        san = cert.get("subjectAltName", [])
        san_values = [entry[1] for entry in san if len(entry) >= 2]
        evidence = [
            FingerprintEvidence(
                type="tls_certificate",
                summary=f"{subject or 'unknown'} issued by {issuer or 'unknown'}",
                data={
                    "subject": subject,
                    "issuer": issuer,
                    "sans": san_values,
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "serial_number": cert.get("serialNumber"),
                    "version": cert.get("version"),
                },
            ),
            FingerprintEvidence(
                type="tls_session",
                summary=f"{version or 'TLS'} {cipher[0] if cipher else 'unknown'}",
                data={"cipher": cipher, "protocol_version": version},
            ),
        ]
        summary = f"{subject or 'unknown'} via {version or 'TLS'}"
        return FingerprintResult(
            protocol="tls",
            port=port,
            vendor=None,
            product=None,
            version=version,
            confidence=0.6,
            source="tls_handshake",
            attributes={"issuer": issuer, "subject": subject, "sans": san_values, "cipher": cipher},
            evidence_summary=summary,
            evidence=evidence,
        )


class SshDetector(Detector):
    name = "ssh-banner"

    def applies(self, observation: ServiceObservation) -> bool:
        if observation.protocol != "tcp":
            return False
        service = (observation.service_name or "").lower()
        return bool(observation.port == 22 or "ssh" in service)

    def detect(self, host: str, observation: ServiceObservation) -> Optional[FingerprintResult]:
        port = observation.port or 22
        try:
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                banner = sock.recv(512).decode(errors="ignore").strip()
        except Exception:
            return None
        if not banner:
            return None
        version, product = _parse_ssh_banner(banner)
        evidence = [
            FingerprintEvidence(
                type="ssh_banner",
                summary=banner[:120],
                data={"banner": banner, "parsed_version": version, "parsed_product": product},
            )
        ]
        summary = banner[:140]
        return FingerprintResult(
            protocol="ssh",
            port=port,
            vendor=None,
            product=product,
            version=version,
            confidence=0.65 if product else 0.45,
            source="ssh_banner",
            attributes={},
            evidence_summary=summary,
            evidence=evidence,
        )


class MysqlDetector(Detector):
    name = "mysql-handshake"

    def applies(self, observation: ServiceObservation) -> bool:
        return observation.protocol == "tcp" and observation.port in {3306, 3307}

    def detect(self, host: str, observation: ServiceObservation) -> Optional[FingerprintResult]:
        port = observation.port or 3306
        try:
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                packet = sock.recv(512)
        except Exception:
            return None
        parsed = _parse_mysql_handshake(packet)
        if not parsed:
            return None
        evidence = [
            FingerprintEvidence(
                type="mysql_handshake",
                summary=f"MySQL protocol {parsed.get('protocol_version')} {parsed.get('server_version')}",
                data=parsed,
            )
        ]
        return FingerprintResult(
            protocol="mysql",
            port=port,
            vendor="Oracle" if "mysql" in (parsed.get("server_version") or "").lower() else None,
            product=parsed.get("server_version"),
            version=parsed.get("server_version"),
            confidence=0.7,
            source="mysql_handshake",
            attributes=parsed,
            evidence_summary=evidence[0].summary,
            evidence=evidence,
        )


class RdpDetector(Detector):
    name = "rdp-probe"

    def applies(self, observation: ServiceObservation) -> bool:
        return observation.protocol == "tcp" and (observation.port == 3389 or "ms-wbt" in (observation.service_name or ""))

    def detect(self, host: str, observation: ServiceObservation) -> Optional[FingerprintResult]:
        port = observation.port or 3389
        # Minimal RDP negotiation request (TPKT + X.224 CR)
        pkt = bytes.fromhex("030000130ee000000000000100080003000000")
        try:
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                sock.sendall(pkt)
                resp = sock.recv(256)
        except Exception:
            resp = b""
        if not resp:
            summary = "RDP port reachable"
        else:
            summary = f"RDP response {len(resp)} bytes"
        evidence = [
            FingerprintEvidence(
                type="rdp_negotiation",
                summary=summary,
                data={"response_len": len(resp), "response_hex": resp.hex() if resp else None},
            )
        ]
        return FingerprintResult(
            protocol="rdp",
            port=port,
            vendor=None,
            product="RDP",
            version=None,
            confidence=0.45,
            source="rdp_probe",
            attributes={},
            evidence_summary=summary,
            evidence=evidence,
        )


class SmbDetector(Detector):
    name = "smb-probe"

    def applies(self, observation: ServiceObservation) -> bool:
        return observation.protocol == "tcp" and (observation.port in {139, 445} or "smb" in (observation.service_name or ""))

    def detect(self, host: str, observation: ServiceObservation) -> Optional[FingerprintResult]:
        port = observation.port or 445
        # SMB requires client greeting; we only check reachability and reuse nmap banner if present.
        summary = f"SMB service detected on {port}"
        evidence = [
            FingerprintEvidence(
                type="smb_banner",
                summary=summary,
                data={"service_name": observation.service_name, "service_version": observation.service_version},
            )
        ]
        return FingerprintResult(
            protocol="smb",
            port=port,
            vendor=None,
            product=observation.service_name or "smb",
            version=observation.service_version,
            confidence=0.35,
            source="nmap_banner",
            attributes={},
            evidence_summary=summary,
            evidence=evidence,
        )


class SnmpDetector(Detector):
    name = "snmp-udp"
    protocols = ("udp", "tcp")

    def applies(self, observation: ServiceObservation) -> bool:
        return (observation.protocol in self.protocols) and (observation.port in {161, 162} or "snmp" in (observation.service_name or ""))

    def detect(self, host: str, observation: ServiceObservation) -> Optional[FingerprintResult]:
        summary = "SNMP endpoint discovered"
        evidence = [
            FingerprintEvidence(
                type="snmp_probe",
                summary=summary,
                data={"service_name": observation.service_name, "service_version": observation.service_version},
            )
        ]
        return FingerprintResult(
            protocol="snmp",
            port=observation.port or 161,
            vendor=None,
            product="snmp",
            version=observation.service_version,
            confidence=0.3,
            source="nmap_banner",
            attributes={},
            evidence_summary=summary,
            evidence=evidence,
        )


def _extract_title(body: str) -> Optional[str]:
    match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


def _short_hash(value: str) -> str:
    import hashlib

    digest = hashlib.sha256(value.encode(errors="ignore")).hexdigest()
    return digest[:16]


def _flatten_name(pairs: Sequence[Sequence[tuple]]) -> Optional[str]:
    if not pairs:
        return None
    flattened: List[str] = []
    for group in pairs:
        for key, val in group:
            flattened.append(f"{key}={val}")
    return ", ".join(flattened) if flattened else None


def _parse_ssh_banner(banner: str) -> tuple[Optional[str], Optional[str]]:
    parts = banner.split()
    if not parts:
        return None, None
    proto = parts[0]
    version = None
    product = None
    if "-" in proto:
        tokens = proto.split("-")
        if len(tokens) >= 2:
            version = tokens[1]
        if len(tokens) >= 3:
            product = tokens[2]
    return version, product


def _parse_mysql_handshake(packet: bytes) -> Optional[dict]:
    if not packet or len(packet) < 6:
        return None
    # MySQL initial handshake: 3-byte length, 1-byte seq, protocol byte, then server version null-terminated
    if len(packet) < 5:
        return None
    protocol_version = packet[4]
    try:
        server_version_end = packet.index(0, 5)
        server_version = packet[5:server_version_end].decode(errors="ignore")
    except ValueError:
        server_version = None
    salt = None
    if len(packet) > server_version_end + 1 + 8:
        salt = packet[server_version_end + 1 : server_version_end + 9].hex()
    return {
        "protocol_version": protocol_version,
        "server_version": server_version,
        "salt_preview": salt,
    }


DETECTORS: List[Detector] = [HttpDetector(), TlsDetector(), SshDetector(), MysqlDetector(), RdpDetector(), SmbDetector(), SnmpDetector()]
