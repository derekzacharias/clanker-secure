from pathlib import Path

from clanker.core.cpe import CpeInferenceEngine
from clanker.core.types import ServiceObservation

FIXTURES = Path(__file__).parent.parent / "data" / "cpe"
CURATED_MAP = FIXTURES / "curated_map.json"


def _observation(
    *,
    service_name: str | None = None,
    service_version: str | None = None,
    product: str | None = None,
    host_vendor: str | None = None,
    port: int = 80,
    protocol: str = "tcp",
    fingerprint: dict | None = None,
) -> ServiceObservation:
    return ServiceObservation(
        asset_id=1,
        host_address="10.0.0.1",
        host_os_name=None,
        host_os_accuracy=None,
        host_vendor=host_vendor,
        traceroute_summary=None,
        host_report=None,
        port=port,
        protocol=protocol,
        service_name=service_name,
        service_version=service_version,
        product=product,
        fingerprint=fingerprint,
    )


def test_curated_match_uses_high_confidence_when_version_present():
    engine = CpeInferenceEngine(CURATED_MAP)
    obs = _observation(service_name="nginx", product="nginx", service_version="1.25.1")
    guess = engine.infer(obs)
    assert guess is not None
    assert guess.value == "cpe:2.3:a:nginx:nginx:1.25.1:*:*:*:*:*:*:*"
    assert guess.confidence == "high"
    assert guess.source == "fixture/web"


def test_confidence_degrades_when_version_missing():
    engine = CpeInferenceEngine(CURATED_MAP)
    obs = _observation(service_name="nginx", product="nginx", service_version=None)
    guess = engine.infer(obs)
    assert guess is not None
    assert guess.confidence == "medium"


def test_rule_template_fills_gap_when_no_curated_match():
    engine = CpeInferenceEngine(
        CURATED_MAP, rule_templates={"ms-wbt-server": "cpe:2.3:a:microsoft:remote_desktop:{version}:*:*:*:*:*:*:*"}
    )
    obs = _observation(service_name="ms-wbt-server", service_version="10.0")
    guess = engine.infer(obs)
    assert guess is not None
    assert guess.source == "rule-template"
    assert guess.value == "cpe:2.3:a:microsoft:remote_desktop:10.0:*:*:*:*:*:*:*"


def test_vendor_product_fallback_applies_when_no_match():
    engine = CpeInferenceEngine(CURATED_MAP)
    obs = _observation(service_version="15.1(2)S", product="ios", host_vendor="cisco")
    guess = engine.infer(obs)
    assert guess is not None
    assert guess.source.startswith("fallback")
    assert guess.value.startswith("cpe:2.3:a:cisco:ios:15.1")
    assert guess.confidence == "medium"


def test_port_filtered_entry_requires_matching_port():
    engine = CpeInferenceEngine(CURATED_MAP)
    on_expected_port = _observation(service_name="vsftpd", service_version="3.0.5", port=21)
    guess_on_port = engine.infer(on_expected_port)
    assert guess_on_port is not None
    assert guess_on_port.source == "fixture/ftp"

    off_port = _observation(service_name="vsftpd", service_version="3.0.5", port=2222)
    guess_off_port = engine.infer(off_port)
    assert guess_off_port is not None
    assert guess_off_port.source != "fixture/ftp"


def test_ssh_inference_prefers_curated_on_default_port():
    engine = CpeInferenceEngine(CURATED_MAP)
    on_port = _observation(service_name="ssh", service_version="9.3p1", port=22)
    off_port = _observation(service_name="ssh", service_version="9.3p1", port=2222)
    curated = engine.infer(on_port)
    fallback = engine.infer(off_port)
    assert curated is not None
    assert curated.source == "curated/ssh"
    assert fallback is not None
    assert fallback.source != "curated/ssh"
