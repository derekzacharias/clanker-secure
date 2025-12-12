from sqlalchemy import text

from clanker.core import rule_engine
from clanker.core.enrichment import enrich_from_feed
from clanker.core.findings import build_findings
from clanker.core.rule_engine import Rule, RuleMatch
from clanker.core.types import ServiceObservation
from clanker.core.agent_vuln_logic import persist_agent_findings
from clanker.db.models import Asset, Scan
from clanker.db.session import get_session, init_db


def test_enrich_from_feed_populates_cpe(monkeypatch):
    init_db()
    monkeypatch.setattr(rule_engine, "load_rules", lambda path=None: [])
    monkeypatch.setattr("clanker.core.enrichment.fetch_nvd_recent_feed", lambda *_, **__: None)
    monkeypatch.setattr("clanker.core.enrichment.fetch_nvd_cve", lambda *_, **__: None)

    with get_session() as session:
        asset = Asset(target="198.51.100.10")
        scan = Scan(profile="basic", status="completed")
        session.add(asset)
        session.add(scan)
        session.commit()
        session.refresh(asset)
        session.refresh(scan)

        obs = ServiceObservation(
            asset_id=asset.id or 0,
            host_address=asset.target,
            host_os_name=None,
            host_os_accuracy=None,
            host_vendor=None,
            traceroute_summary=None,
            host_report=None,
            port=80,
            protocol="tcp",
            service_name="nginx",
            service_version="1.25.1",
            product="nginx",
            evidence=[{"type": "banner", "summary": "nginx 1.25.1"}],
            evidence_summary="nginx 1.25.1 on port 80",
        )
        observation_map: dict[int, ServiceObservation] = {}
        findings = build_findings(
            session,
            scan_id=scan.id or 0,
            asset_id=asset.id or 0,
            observations=[obs],
            rules=[
                Rule(
                    id="RULE-NGINX",
                    match=RuleMatch(service_name="nginx"),
                    cve=["CVE-TEST"],
                    severity="medium",
                    description="test rule",
                )
            ],
            observation_map=observation_map,
        )
        session.commit()

        enrich_from_feed(session, findings, observations=observation_map)
        row = session.exec(
            text("SELECT cpe, cpe_confidence, source FROM finding_enrichment WHERE finding_id=:fid"),
            {"fid": findings[0].id},
        ).mappings().first()
        assert row is not None
        assert str(row["cpe"]).startswith("cpe:2.3:a:nginx:nginx:1.25.1")
        assert row["cpe_confidence"] == "high"


def test_agent_findings_enriched_with_cpe(monkeypatch):
    init_db()
    monkeypatch.setattr("clanker.core.enrichment.fetch_nvd_recent_feed", lambda *_, **__: None)
    monkeypatch.setattr("clanker.core.enrichment.fetch_nvd_cve", lambda *_, **__: None)

    with get_session() as session:
        asset = Asset(target="203.0.113.20")
        session.add(asset)
        session.commit()
        session.refresh(asset)

        inventory = {
            "host_identifier": "agent-host",
            "hostname": "agent-host",
            "os_name": "linux",
            "os_version": "Debian 12",
            "distro": "debian",
            "services": [{"name": "nginx", "version": "1.25.1", "port": 8080, "protocol": "tcp"}],
            "packages": [],
            "configs": {},
        }
        findings = persist_agent_findings(session, inventory, asset_id=asset.id)
        session.commit()

        # Only service-backed findings should receive a CPE enrichment
        enriched_rows = []
        for fid in [f.id for f in findings if f.id is not None]:
            row = session.exec(
                text("SELECT cpe, cpe_confidence, source FROM finding_enrichment WHERE finding_id = :fid"),
                {"fid": fid},
            ).mappings().first()
            if row:
                enriched_rows.append(row)
        assert enriched_rows, "expected CPE enrichment rows for agent findings"
        assert any(row["cpe"] and "nginx" in row["cpe"] for row in enriched_rows)
        assert all(row["cpe_confidence"] for row in enriched_rows if row["cpe"])
