from clanker.core.evidence import build_why_trace, dedupe_evidence, grade_evidence


def test_dedupe_prefers_high_confidence_and_source():
    evidence = [
        {"type": "banner", "summary": "nginx 1.20", "source": "scan", "confidence": 0.6},
        {"type": "banner", "summary": "nginx 1.20", "source": "kev", "confidence": 0.4},
        {"type": "banner", "summary": "nginx 1.20", "source": "scan", "confidence": 0.9},
        {"type": "advisory", "summary": "CVE-2021-23017", "source": "nvd", "confidence": 0.9},
    ]
    deduped = dedupe_evidence(evidence)
    assert len(deduped) == 2
    assert deduped[0]["confidence"] == 0.9  # strongest duplicate kept
    assert grade_evidence(deduped) == "high"


def test_build_why_trace():
    trace = build_why_trace(
        "RULE-123",
        "matched service",
        source="rule_engine",
        context={
            "port": 443,
            "protocol": "tcp",
            "service_name": "https",
            "service_version": "1.2",
            "version_confidence": 0.8,
        },
    )
    assert "RULE-123" in trace
    assert "matched service" in trace
    assert "rule_engine" in trace
    assert "https" in trace and "443" in trace


def test_grade_evidence_uses_structure_and_volume():
    evidence = [
        {"type": "http_response", "summary": "Apache", "confidence": 0.66},
        {"type": "banner", "summary": "weak", "confidence": 0.2},
    ]
    assert grade_evidence(evidence) == "high"

    low = [{"type": "note", "summary": "unverified", "confidence": 0.4}]
    assert grade_evidence(low) == "low"
