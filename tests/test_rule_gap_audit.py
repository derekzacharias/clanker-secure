from pathlib import Path

from clanker.core.coverage import load_rule_gaps, summarize_rule_gaps, stub_rule_from_gap
from clanker.core.fingerprint.detectors import _parse_mysql_handshake


def test_load_and_summarize_rule_gaps(tmp_path: Path) -> None:
    sample = Path("tests/data/rule_gaps.jsonl")
    entries = load_rule_gaps(sample)
    assert len(entries) == 3
    summary = summarize_rule_gaps(entries)
    # Should group by protocol/port/service_name
    assert summary[0]["service_name"] == "http"
    assert summary[0]["count"] == 2
    assert summary[1]["service_name"] == "ssh"
    stub = stub_rule_from_gap(summary[0])
    assert stub["match"]["port"] == 8080
    assert stub["match"]["service_name"] == "http"


def test_parse_mysql_handshake_sample() -> None:
    # Basic packet: len=0x2d000001, protocol 10, version "5.7.41-log"
    packet = bytes.fromhex(
        "2d0000010a352e372e34312d6c6f6700"
        "01000000"
        "0820460000"
        "ff21"
        "02"
        "00"
        "0f0000"
        "000000000000000000"
    )
    parsed = _parse_mysql_handshake(packet)
    assert parsed is not None
    assert parsed["protocol_version"] == 10
    assert "5.7.41" in parsed["server_version"]
