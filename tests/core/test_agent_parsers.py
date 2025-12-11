from pathlib import Path

import pytest

from clanker.core.agent_parsers import (
    normalize_package_name,
    normalize_version,
    parse_dpkg_list,
    parse_kernel_release,
    parse_listening_services,
    parse_rpm_qa,
    parse_sshd_config,
)

FIXTURES = Path(__file__).parent.parent / "data" / "agent_parsers"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_dpkg_list():
    output = load_fixture("dpkg_ubuntu.txt")
    packages = parse_dpkg_list(output)
    names = {p["name"]: p for p in packages}
    assert names["openssh-server"]["version"] == "9.3p1-1ubuntu3.4"
    assert names["curl"]["arch"] == "amd64"
    assert all(p["source"] == "dpkg" for p in packages)


def test_parse_rpm_qa():
    output = load_fixture("rpm_centos.txt")
    packages = parse_rpm_qa(output)
    names = {p["name"]: p for p in packages}
    assert names["openssh-server"]["version"] == "8.7p1-38.el9_2.4"
    assert names["tzdata"]["arch"] == "noarch"
    assert names["bash"]["arch"] == "x86_64"
    assert all(p["source"] == "rpm" for p in packages)


def test_normalize_helpers_strip_epoch_and_case():
    assert normalize_package_name("OpenSSH-Server") == "openssh-server"
    assert normalize_version("1:9.2p1-2") == "9.2p1-2"


def test_parse_kernel_release():
    uname_output = load_fixture("uname_ubuntu.txt")
    assert parse_kernel_release(uname_output) == "6.2.0-39-generic"
    assert parse_kernel_release("invalid data") is None


def test_parse_listening_services_from_ss():
    output = load_fixture("ss_ubuntu.txt")
    services = parse_listening_services(output)
    ssh = next((s for s in services if s["name"] == "ssh"), None)
    dns = next((s for s in services if s["name"] == "systemd-resolved"), None)
    assert ssh is not None
    assert ssh["port"] == 22
    assert ssh["protocol"] == "tcp"
    assert dns is not None
    assert dns["port"] == 53
    assert dns["status"] == "listening"


def test_parse_sshd_config_hardening():
    config = load_fixture("sshd_config_debian.txt")
    settings = parse_sshd_config(config)
    assert settings["permit_root_login"] == "prohibit-password"
    assert settings["password_authentication"] == "no"
    assert settings["challenge_response_auth"] == "no"
    assert settings["max_auth_tries"] == "3"
    assert settings["allow_users"] == "deploy"
