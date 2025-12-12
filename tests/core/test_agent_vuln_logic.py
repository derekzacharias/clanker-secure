import json
from pathlib import Path
from types import SimpleNamespace

from clanker.config import settings
from clanker.core.agent_vuln_logic import AgentFindingCandidate, evaluate_inventory, reload_agent_rules


def _build_inventory() -> SimpleNamespace:
    return SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        os_name="linux",
        os_version="Ubuntu 22.04",
        kernel_version="5.10.0-10-generic",
        distro="ubuntu",
        packages=[
            {"name": "openssl", "version": "1.1.1k"},
            {"name": "sudo", "version": "1.9.5p1"},
        ],
        services=[
            {"name": "telnetd", "port": 23, "protocol": "tcp"},
            {"name": "ssh", "version": "8.2p1", "port": 22, "protocol": "tcp"},
        ],
        configs={"sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\n"},
    )


def test_agent_inventory_matches_multiple_rules():
    findings = evaluate_inventory(_build_inventory())
    rule_ids = {f.rule_id for f in findings}
    assert any(r.startswith("AGENT-PKG-OPENSSL") for r in rule_ids)
    assert "AGENT-PKG-SUDO-2021-3156" in rule_ids
    assert "AGENT-SVC-OPENSSH-OUTDATED" in rule_ids
    assert "AGENT-SVC-LEGACY-TELNET" in rule_ids
    assert "AGENT-SSH-MISCONFIG-ROOT" in rule_ids
    assert "AGENT-SSH-MISCONFIG-PASSWORDS" in rule_ids
    assert any("KERNEL" in r for r in rule_ids)


def test_secure_ssh_config_skips_misconfig_findings():
    inventory = _build_inventory()
    inventory.configs = {"sshd_config": "PermitRootLogin no\nPasswordAuthentication no\n"}
    findings = evaluate_inventory(inventory)
    assert not any(f.rule_id.startswith("AGENT-SSH-MISCONFIG") for f in findings)


def test_candidate_structure():
    finding = next(iter(evaluate_inventory(_build_inventory())), None)
    assert isinstance(finding, AgentFindingCandidate)
    assert finding.evidence_summary
    assert isinstance(finding.evidence, list)


def test_external_advisory_loader(monkeypatch, tmp_path):
    advisory_path = Path(tmp_path / "agent_advisories.json")
    payload = {
        "package_advisories": [
            {
                "rule_id": "AGENT-PKG-EXTERNAL-TEST",
                "package": "custompkg",
                "fixed_version": "2.0",
                "cve_ids": ["CVE-TEST-0001"],
                "severity": "high",
                "description": "External advisory test",
                "source": "test-suite",
            }
        ]
    }
    advisory_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(settings, "agent_advisories_path", advisory_path)
    reload_agent_rules(advisory_path)

    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[{"name": "custompkg", "version": "1.0"}],
        services=[],
        configs={},
    )
    findings = evaluate_inventory(inventory)
    rule_ids = {f.rule_id for f in findings}
    assert "AGENT-PKG-EXTERNAL-TEST" in rule_ids
    assert any(ev for f in findings for ev in f.evidence if ev["data"].get("rule_source") == "test-suite")


def test_external_advisory_reload(monkeypatch, tmp_path):
    advisory_path = Path(tmp_path / "agent_advisories.json")
    payload = {
        "package_advisories": [
            {
                "rule_id": "AGENT-PKG-RELOAD-TEST",
                "package": "reloadpkg",
                "fixed_version": "1.0",
                "cve_ids": ["CVE-RELOAD-0001"],
                "severity": "medium",
                "description": "Initial threshold",
                "source": "test-suite",
            }
        ]
    }
    advisory_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(settings, "agent_advisories_path", advisory_path)
    reload_agent_rules(advisory_path)

    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[{"name": "reloadpkg", "version": "1.5"}],
        services=[],
        configs={},
    )
    findings = evaluate_inventory(inventory)
    assert "AGENT-PKG-RELOAD-TEST" not in {f.rule_id for f in findings}

    payload["package_advisories"][0]["fixed_version"] = "2.0"
    advisory_path.write_text(json.dumps(payload), encoding="utf-8")
    reload_agent_rules(advisory_path)
    findings_after = evaluate_inventory(inventory)
    assert "AGENT-PKG-RELOAD-TEST" in {f.rule_id for f in findings_after}


def test_external_advisory_directory_loader(monkeypatch, tmp_path):
    advisory_dir = tmp_path / "agent_advisories.d"
    advisory_dir.mkdir()
    (advisory_dir / "pkg1.json").write_text(
        json.dumps(
            {
                "package_advisories": [
                    {
                        "rule_id": "AGENT-PKG-DIR-ONE",
                        "package": "dirpkg",
                        "fixed_version": "2.0",
                        "cve_ids": ["CVE-DIR-0001"],
                        "severity": "high",
                        "description": "Dir advisory one",
                        "source": "test-suite",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (advisory_dir / "svc.json").write_text(
        json.dumps(
            {
                "service_rules": [
                    {
                        "rule_id": "AGENT-SVC-DIR-SSH",
                        "names": ["ssh"],
                        "version_lt": "9.0",
                        "cve_ids": ["CVE-DIR-SSH"],
                        "severity": "medium",
                        "description": "Dir service rule",
                        "source": "test-suite",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "agent_advisories_path", advisory_dir)
    reload_agent_rules(advisory_dir)

    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[{"name": "dirpkg", "version": "1.0"}],
        services=[{"name": "ssh", "version": "8.0", "port": 22, "protocol": "tcp"}],
        configs={},
    )
    findings = evaluate_inventory(inventory)
    rule_ids = {f.rule_id for f in findings}
    assert "AGENT-PKG-DIR-ONE" in rule_ids
    assert "AGENT-SVC-DIR-SSH" in rule_ids


def test_distro_hint_inferred_from_advisory_filename(monkeypatch, tmp_path):
    advisory_dir = tmp_path / "agent_advisories.d"
    advisory_dir.mkdir()
    (advisory_dir / "ubuntu.json").write_text(
        json.dumps(
            {
                "package_advisories": [
                    {
                        "rule_id": "AGENT-PKG-UBUNTU-ONLY",
                        "package": "ubuntu-pkg",
                        "fixed_version": "2.0",
                        "cve_ids": ["CVE-UBU-0001"],
                        "severity": "high",
                        "description": "Ubuntu scoped advisory",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "agent_advisories_path", advisory_dir)
    reload_agent_rules(advisory_dir)

    ubuntu_inventory = SimpleNamespace(
        host_identifier="agent-host-ubuntu",
        hostname="agent-host-ubuntu",
        distro="ubuntu",
        packages=[{"name": "ubuntu-pkg", "version": "1.0"}],
        services=[],
        configs={},
    )
    other_inventory = SimpleNamespace(
        host_identifier="agent-host-centos",
        hostname="agent-host-centos",
        distro="centos",
        packages=[{"name": "ubuntu-pkg", "version": "1.0"}],
        services=[],
        configs={},
    )
    ubuntu_findings = evaluate_inventory(ubuntu_inventory)
    other_findings = evaluate_inventory(other_inventory)
    assert "AGENT-PKG-UBUNTU-ONLY" in {f.rule_id for f in ubuntu_findings}
    assert "AGENT-PKG-UBUNTU-ONLY" not in {f.rule_id for f in other_findings}


def test_osv_and_oval_backport_parsing(monkeypatch, tmp_path):
    advisory_path = Path(tmp_path / "ubuntu_feeds.json")
    payload = {
        "osv_records": [
            {
                "rule_id": "OSV-PKG-LIBSSL-BACKPORT",
                "package": "libssl3",
                "fixed_version": "3.0.0",
                "backport_fixed_version": "1.1.1n-0ubuntu2.10",
                "cve_ids": ["CVE-OSV-0001"],
                "severity": "critical",
                "description": "Upstream fix backported by Ubuntu security team",
                "distro_hint": "ubuntu",
            }
        ],
        "oval_definitions": [
            {
                "definition_id": "oval:com.ubuntu.jammy:def:20230778",
                "package": "openssl",
                "fixed_version": "1.1.1n-1ubuntu2.2",
                "backport_fixed_version": "1.1.1n-1ubuntu2.1",
                "cve_ids": ["CVE-OVAL-0002"],
                "severity": "high",
                "description": "Ubuntu OVAL backport",
                "distro_hint": "ubuntu",
            }
        ],
    }
    advisory_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(settings, "agent_advisories_path", advisory_path)
    reload_agent_rules(advisory_path)

    ubuntu_inventory = SimpleNamespace(
        host_identifier="agent-host-ubuntu",
        hostname="agent-host-ubuntu",
        distro="ubuntu",
        packages=[
            {"name": "libssl3", "version": "1.1.1n-0ubuntu2.5"},
            {"name": "openssl", "version": "1.1.1n-1ubuntu2.0"},
        ],
        services=[],
        configs={},
    )
    other_inventory = SimpleNamespace(
        host_identifier="agent-host-centos",
        hostname="agent-host-centos",
        distro="centos",
        packages=[
            {"name": "libssl3", "version": "1.1.1n-0ubuntu2.5"},
            {"name": "openssl", "version": "1.1.1n-1ubuntu2.0"},
        ],
        services=[],
        configs={},
    )

    ubuntu_findings = evaluate_inventory(ubuntu_inventory)
    ubuntu_rule_ids = {f.rule_id for f in ubuntu_findings}
    assert "OSV-PKG-LIBSSL-BACKPORT" in ubuntu_rule_ids
    assert "oval:com.ubuntu.jammy:def:20230778" in ubuntu_rule_ids

    other_rule_ids = {f.rule_id for f in evaluate_inventory(other_inventory)}
    assert "OSV-PKG-LIBSSL-BACKPORT" not in other_rule_ids
    assert "oval:com.ubuntu.jammy:def:20230778" not in other_rule_ids


def test_service_version_inferred_from_packages():
    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[{"name": "openssh-server", "version": "8.2p1"}],
        services=[{"name": "ssh", "port": 22, "protocol": "tcp"}],
        configs={},
    )
    findings = evaluate_inventory(inventory)
    assert "AGENT-SVC-OPENSSH-OUTDATED" in {f.rule_id for f in findings}


def test_ssh_client_config_weak_settings_detected():
    ssh_client_config = (Path(__file__).parent.parent / "data" / "agent_parsers" / "ssh_client_weak.txt").read_text()
    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[],
        services=[],
        configs={"ssh_config": ssh_client_config},
    )
    findings = evaluate_inventory(inventory)
    rule_ids = {f.rule_id for f in findings}
    assert "AGENT-SSH-CLIENT-WEAK-CIPHERS" in rule_ids
    assert "AGENT-SSH-CLIENT-WEAK-MACS" in rule_ids
    assert "AGENT-SSH-CLIENT-WEAK-KEX" in rule_ids


def test_sudoers_nopasswd_misconfig_detected():
    sudoers = (Path(__file__).parent.parent / "data" / "agent_parsers" / "sudoers_nopasswd.txt").read_text()
    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[],
        services=[],
        configs={"sudoers": sudoers},
        files=[],
    )
    findings = evaluate_inventory(inventory)
    assert any(f.rule_id == "AGENT-SUDO-MISCONFIG-NOPASSWD" for f in findings)


def test_sudoers_no_authenticate_detected():
    sudoers = "root ALL=(ALL) !authenticate\n"
    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[],
        services=[],
        configs={"sudoers": sudoers},
        files=[],
    )
    findings = evaluate_inventory(inventory)
    assert any(f.rule_id == "AGENT-SUDO-MISCONFIG-NOAUTH" for f in findings)


def test_sudoers_timestamp_timeout_detected():
    sudoers = (Path(__file__).parent.parent / "data" / "agent_parsers" / "sudoers_timestamp.txt").read_text()
    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[],
        services=[],
        configs={"sudoers": sudoers},
        files=[],
    )
    findings = evaluate_inventory(inventory)
    rule_ids = {f.rule_id for f in findings}
    assert "AGENT-SUDO-MISCONFIG-NO-TIMEOUT" in rule_ids
    assert "AGENT-SUDO-MISCONFIG-NOPASSWD" in rule_ids


def test_sshd_config_algorithm_misconfigs_detected():
    sshd_config = (Path(__file__).parent.parent / "data" / "agent_parsers" / "sshd_config_weak.txt").read_text()
    inventory = SimpleNamespace(
        host_identifier="agent-host-1",
        hostname="agent-host-1",
        distro="ubuntu",
        packages=[],
        services=[],
        configs={"sshd_config": sshd_config},
    )
    findings = evaluate_inventory(inventory)
    rule_ids = {f.rule_id for f in findings}
    assert "AGENT-SSH-MISCONFIG-WEAK-CIPHERS" in rule_ids
    assert "AGENT-SSH-MISCONFIG-WEAK-MACS" in rule_ids
    assert "AGENT-SSH-MISCONFIG-WEAK-KEX" in rule_ids


def test_service_rule_apache_path_traversal():
    inventory = SimpleNamespace(
        host_identifier="agent-host-2",
        hostname="agent-host-2",
        distro="centos",
        packages=[],
        services=[{"name": "httpd", "version": "2.4.49", "port": 80, "protocol": "tcp"}],
        configs={},
    )
    findings = evaluate_inventory(inventory)
    rule_ids = {f.rule_id for f in findings}
    assert "AGENT-SVC-APACHE-2021-41773" in rule_ids


def test_os_release_eol_detection():
    outdated = SimpleNamespace(
        host_identifier="legacy-host",
        hostname="legacy-host",
        os_name="ubuntu",
        os_version="Ubuntu 16.04.7 LTS",
        kernel_version="4.4.0-200-generic",
        distro="ubuntu",
        packages=[],
        services=[],
        configs={},
    )
    modern = SimpleNamespace(
        host_identifier="new-host",
        hostname="new-host",
        os_name="ubuntu",
        os_version="Ubuntu 22.04.3 LTS",
        distro="ubuntu",
        packages=[],
        services=[],
        configs={},
    )
    outdated_findings = evaluate_inventory(outdated)
    modern_findings = evaluate_inventory(modern)
    assert "AGENT-OS-EOL-UBUNTU-1604" in {f.rule_id for f in outdated_findings}
    assert "AGENT-OS-EOL-UBUNTU-1604" not in {f.rule_id for f in modern_findings}


def test_kernel_rule_bounds_respected():
    candidate = SimpleNamespace(
        host_identifier="kernel-host",
        hostname="kernel-host",
        kernel_version="5.17.0",
        packages=[],
        services=[],
        configs={},
    )
    findings = evaluate_inventory(candidate)
    assert not any(f.rule_id == "AGENT-KERNEL-2022-0847" for f in findings)
