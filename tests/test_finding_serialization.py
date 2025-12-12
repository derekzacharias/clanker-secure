import json
from types import SimpleNamespace

from clanker.main import _fingerprint_metadata, _serialize_finding_export
from clanker.db.models import Finding


def test_fingerprint_metadata_extracts_confidence_and_types() -> None:
    fingerprint = json.dumps({"version_confidence": 0.82})
    evidence = json.dumps([{"type": "http_response", "summary": "ok"}, {"type": "tls_certificate"}])
    dummy = SimpleNamespace(fingerprint=fingerprint, evidence=evidence)
    version_confidence, evidence_types = _fingerprint_metadata(dummy)  # type: ignore[arg-type]
    assert version_confidence == 0.82
    assert evidence_types == ["http_response", "tls_certificate"]


def test_export_serialization_includes_confidence_and_evidence_types() -> None:
    finding = Finding(
        id=42,
        severity="medium",
        status="open",
        service_name="http",
        fingerprint=json.dumps({"product": "Apache", "version_confidence": 0.75}),
        evidence=json.dumps([{"type": "http_response", "summary": "200 OK"}]),
        evidence_grade="high",
        why_trace="Matched rule RULE-HTTP-001 | source=rule_engine",
    )
    payload = _serialize_finding_export(finding, {})
    assert payload["version_confidence"] == 0.75
    assert payload["evidence_types"] == ["http_response"]
    assert payload["evidence_grade"] == "high"
    assert "rule" in (payload["why_trace"] or "").lower()
