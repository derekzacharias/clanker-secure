from types import SimpleNamespace

from clanker.core.agent_vuln_logic import AgentFindingCandidate, evaluate_inventory


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
