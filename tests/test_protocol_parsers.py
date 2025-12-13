import json
from pathlib import Path

from clanker.core.fingerprint import parse_fingerprint_artifact, parser_inventory
from clanker.core.types import ServiceObservation

DATA_DIR = Path(__file__).parent / "data" / "fingerprint"


def _load_json(filename: str) -> dict:
    return json.loads((DATA_DIR / filename).read_text())


def _observation(port: int, protocol: str = "tcp", service_name: str | None = None) -> ServiceObservation:
    return ServiceObservation(
        asset_id=1,
        host_address="192.0.2.10",
        host_os_name=None,
        host_os_accuracy=None,
        host_vendor=None,
        traceroute_summary=None,
        host_report=None,
        port=port,
        protocol=protocol,
        service_name=service_name,
        service_version=None,
        product=None,
        version_confidence=None,
        fingerprint=None,
        evidence=None,
        evidence_summary=None,
    )


def test_http_parser_structured_evidence() -> None:
    artifacts = _load_json("http_response.json")
    obs = _observation(8080)
    updated = parse_fingerprint_artifact("http_response", obs, artifacts, host="web.test")
    assert updated is not None
    assert updated.fingerprint and updated.fingerprint["protocol"] == "http"
    assert updated.service_version and updated.version_confidence >= 0.6
    assert updated.evidence and updated.evidence[0]["type"] == "http_response"
    assert "body_preview_hash" in updated.evidence[0]["data"]


def test_tls_parser_uses_certificate_metadata() -> None:
    cert = _load_json("tls_cert.json")
    artifacts = {"cert": cert, "cipher": ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128), "version": "TLSv1.3", "port": 443}
    obs = _observation(443, service_name="https")
    updated = parse_fingerprint_artifact("tls_certificate", obs, artifacts, host="api.test")
    assert updated is not None
    assert updated.fingerprint and updated.fingerprint["protocol"] == "tls"
    assert "Example Test CA" in (updated.evidence or [])[0]["data"]["issuer"]
    assert updated.version_confidence >= 0.5


def test_ssh_parser_from_banner() -> None:
    banner = (DATA_DIR / "ssh_banner.txt").read_text().strip()
    obs = _observation(22, service_name="ssh")
    updated = parse_fingerprint_artifact("ssh_banner", obs, {"banner": banner, "port": 22}, host="host.test")
    assert updated is not None
    assert updated.service_version and updated.service_version.startswith("8.9")
    assert updated.version_confidence and updated.version_confidence > 0.5


def test_mysql_parser_from_handshake_bytes() -> None:
    packet = bytes.fromhex((DATA_DIR / "mysql_handshake.hex").read_text().strip())
    obs = _observation(3306, service_name="mysql")
    updated = parse_fingerprint_artifact("mysql_handshake", obs, {"packet": packet, "port": 3306})
    assert updated is not None
    assert updated.service_version and "5.7.41" in updated.service_version
    assert updated.version_confidence and updated.version_confidence >= 0.7
    assert updated.evidence_summary and updated.evidence_summary.startswith("MySQL protocol")


def test_rdp_parser_response_fixture() -> None:
    response = bytes.fromhex((DATA_DIR / "rdp_response.hex").read_text().strip())
    obs = _observation(3389, service_name="ms-wbt-server")
    updated = parse_fingerprint_artifact("rdp_negotiation", obs, {"response": response, "port": 3389})
    assert updated is not None
    assert updated.evidence_summary and "RDP response" in updated.evidence_summary
    assert updated.fingerprint and updated.fingerprint["protocol"] == "rdp"


def test_smb_and_snmp_banners_capture_versions() -> None:
    smb_banner = (DATA_DIR / "smb_banner.txt").read_text().strip()
    snmp_banner = (DATA_DIR / "snmp_banner.txt").read_text().strip()
    smb_obs = _observation(445, service_name="smb")
    snmp_obs = _observation(161, protocol="udp", service_name="snmp")
    smb_updated = parse_fingerprint_artifact(
        "smb_banner", smb_obs, {"service_name": smb_banner, "service_version": "4.9.5-Debian"}, host=None
    )
    snmp_updated = parse_fingerprint_artifact(
        "snmp_probe", snmp_obs, {"service_name": "snmp", "service_version": "5.9"}, host=None
    )
    assert smb_updated and (smb_updated.version_confidence or 0) >= 0.4
    assert snmp_updated and (snmp_updated.version_confidence or 0) >= 0.25


def test_postgres_banner_inference_preserves_version() -> None:
    pg_obs = _observation(5432, service_name="postgresql")
    pg_updated = parse_fingerprint_artifact(
        "postgres_banner", pg_obs, {"service_name": "PostgreSQL", "service_version": "13.4"}, host=None
    )
    assert pg_updated is not None
    assert pg_updated.fingerprint and pg_updated.fingerprint["protocol"] == "postgresql"
    assert pg_updated.service_version == "13.4"
    assert (pg_updated.version_confidence or 0) >= 0.4
    # SSL response evidence path
    ssl_updated = parse_fingerprint_artifact(
        "postgres_ssl_response",
        pg_obs,
        {"service_name": "postgresql", "service_version": None, "ssl_response": "S", "port": 5432},
        host=None,
    )
    assert ssl_updated is not None
    assert "ssl_response" in (ssl_updated.evidence or [])[0]["data"]
    # Authentication message parsing
    auth_packet = bytes.fromhex((DATA_DIR / "postgres_auth.hex").read_text().strip().replace(" ", ""))
    auth_updated = parse_fingerprint_artifact(
        "postgres_auth",
        pg_obs,
        {"service_name": "postgresql", "service_version": None, "startup_response": auth_packet, "port": 5432},
        host=None,
    )
    assert auth_updated is not None
    assert any(ev for ev in (auth_updated.evidence or []) if ev["type"] == "postgres_auth")
    assert any(ev for ev in (auth_updated.evidence or []) if ev["type"] == "postgres_params")


def test_parser_inventory_includes_prioritized_protocols() -> None:
    inventory = parser_inventory()
    protocol_names = [item["name"] for item in inventory]
    assert protocol_names[0] == "http-basic"
    for expected in {
        "tls-handshake",
        "ssh-banner",
        "mysql-handshake",
        "postgres-banner",
        "rdp-probe",
        "smb-probe",
        "snmp-udp",
    }:
        assert expected in protocol_names
