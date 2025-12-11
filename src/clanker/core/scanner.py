from __future__ import annotations

import logging
import subprocess
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
import shlex
from dataclasses import dataclass
from typing import Dict, List

from clanker.config import settings
from clanker.core.fingerprint import enrich_with_fingerprints
from clanker.core.types import ServiceObservation
from clanker.db.models import Asset

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class ScanProfile:
    key: str
    label: str
    description: str
    command: str
    args: List[str]


def _profile(key: str, label: str, description: str, command: str) -> ScanProfile:
    args = shlex.split(command)
    if args and args[0].lower() == "nmap":
        args = args[1:]
    return ScanProfile(key=key, label=label, description=description, command=command, args=args)


SCAN_PROFILE_LIST: List[ScanProfile] = [
    _profile(
        "all_tcp_ports",
        "All TCP Ports Scan",
        "SYN scan of every TCP port on the target.",
        "nmap -sS -p 1-65535 -Pn",
    ),
    _profile(
        "common_tcp_connect",
        "Common TCP Connect Scan",
        "TCP connect scan for a curated set of high-value ports.",
        "nmap -sT -p 17,19,21,22,23,25,26,37,53,80,88,110,113,123,135,137,138,139,143,443,444,445,548,554,843,993,995,1027,1030,1064,1080,1194,1221,1433,2082,2083,2084,2086,2087,2095,2096,3074,3306,3333,3389,3784,4899,5631,5800,5900,6665-6669,6697,8000,8080,8088,10000,17500,32764 -n -Pn -r",
    ),
    _profile(
        "common_tcp_syn",
        "Common TCP SYN Scan",
        "SYN scan for the same curated port set.",
        "nmap -sS -p 17,19,21,22,23,25,26,37,53,80,88,110,113,123,135,137,138,139,143,443,444,445,548,554,843,993,995,1027,1030,1064,1080,1194,1221,1433,2082,2083,2084,2086,2087,2095,2096,3074,3306,3333,3389,3784,4899,5631,5800,5900,6665-6669,6697,8000,8080,8088,10000,17500,32764 -n -Pn -r",
    ),
    _profile(
        "common_tcp_version",
        "Common TCP Version Scan",
        "Version detection on the curated port set.",
        "nmap -sV -p 17,19,21,22,23,25,26,37,53,80,88,110,113,123,135,137,138,139,143,443,444,445,548,554,843,993,995,1027,1030,1064,1080,1194,1221,1433,2082,2083,2084,2086,2087,2095,2096,3074,3306,3333,3389,3784,4899,5631,5800,5900,6665-6669,6697,8000,8080,8088,10000,17500,32764 -n -Pn -r",
    ),
    _profile(
        "honeypot_version_demo",
        "Honeypot Version Demo",
        "Checks honeypot-friendly ports for banner versions.",
        "nmap -sV -p 1433,3306,4899,5900,8000,10000 -n -Pn -r",
    ),
    _profile(
        "intense",
        "Intense Scan",
        "Intrusive scan with OS/version detection, scripts, and traceroute.",
        "nmap -T4 -A -v",
    ),
    _profile(
        "intense_udp",
        "Intense Scan Plus UDP",
        "Intense scan covering both TCP and UDP ports.",
        "nmap -sS -sU -T4 -A -v",
    ),
    _profile(
        "intense_all_tcp",
        "Intense Scan (All TCP Ports)",
        "Intense scan that sweeps all 65,535 TCP ports.",
        "nmap -p 1-65535 -T4 -A -v",
    ),
    _profile(
        "intense_no_ping",
        "Intense Scan (No Ping)",
        "Skips host discovery before running the intense scan.",
        "nmap -T4 -A -v -Pn",
    ),
    _profile(
        "ping",
        "Ping Scan",
        "Host discovery without port scanning.",
        "nmap -sn",
    ),
    _profile(
        "quick",
        "Quick Scan",
        "Aggressive timing plus fewer ports for speed.",
        "nmap -T4 -F",
    ),
    _profile(
        "quick_plus",
        "Quick Scan Plus",
        "Quick scan with OS and version detection.",
        "nmap -sV -T4 -O -F --version-light",
    ),
    _profile(
        "quick_traceroute",
        "Quick Traceroute",
        "Traceroute without full port scanning.",
        "nmap -sn --traceroute",
    ),
    _profile(
        "random_telnet_open",
        "Random Telnet Scan (Show Open)",
        "Samples 10 random hosts and reports open Telnet ports.",
        "nmap -sS -p 23 -n -iR 10 -Pn --open",
    ),
    _profile(
        "regular",
        "Regular Scan",
        "Default nmap behavior with no extra options.",
        "nmap",
    ),
    _profile(
        "slow_comprehensive",
        "Slow Comprehensive Scan",
        "Highly intrusive TCP/UDP scan with numerous probes and scripts.",
        'nmap -sS -sU -T4 -A -v -PE -PS80,443 -PA3389 -PP -PU40125 -PY --source-port 53 --script "default or (discovery and safe)"',
    ),
    _profile(
        "telnet_internet_random",
        "Telnet Internet Random",
        "Scans 100 random IPv4 hosts for open Telnet.",
        "nmap -sS -p 23 -n -iR 100 -Pn --open",
    ),
]

PROFILE_INDEX: Dict[str, ScanProfile] = {profile.key: profile for profile in SCAN_PROFILE_LIST}
DEFAULT_PROFILE_KEY = "intense"


def get_scan_profile(key: str) -> ScanProfile:
    return PROFILE_INDEX.get(key, PROFILE_INDEX[DEFAULT_PROFILE_KEY])


def list_scan_profiles() -> List[ScanProfile]:
    return SCAN_PROFILE_LIST


def _build_xml_path(asset: Asset) -> Path:
    filename = f"scan_{asset.id}_{uuid.uuid4().hex}.xml"
    return settings.xml_output_dir / filename


def execute_nmap(asset: Asset, profile: ScanProfile) -> Path:
    xml_path = _build_xml_path(asset)
    cmd = [settings.nmap_path, *profile.args, "-oX", str(xml_path), asset.target]
    logger.info("Running nmap for asset=%s", asset.target)
    try:
        subprocess.run(cmd, check=False, capture_output=True)
    except FileNotFoundError as exc:
        logger.error("nmap binary not found: %s", exc)
        raise
    return xml_path


def parse_nmap_xml(xml_file: Path, asset: Asset) -> List[ServiceObservation]:
    observations: List[ServiceObservation] = []
    if not xml_file.exists():
        logger.warning("nmap output missing for asset=%s", asset.target)
        return observations

    tree = ET.parse(xml_file)
    root = tree.getroot()
    for host_el in root.findall(".//host"):
        host_meta = _extract_host_metadata(host_el, asset)
        port_entries = _extract_open_ports(host_el)
        if not port_entries:
            continue
        host_report = _render_host_report(host_meta, port_entries)
        host_observations: List[ServiceObservation] = []
        for entry in port_entries:
            host_observations.append(
                ServiceObservation(
                    asset_id=asset.id or 0,
                    host_address=host_meta["address"],
                    host_os_name=host_meta["os_name"],
                    host_os_accuracy=host_meta["os_accuracy"],
                    host_vendor=host_meta["vendor"],
                    traceroute_summary=host_meta["traceroute_summary"],
                    host_report=host_report,
                    port=entry["port"],
                    protocol=entry["protocol"],
                    service_name=entry["service_name"],
                    service_version=entry["service_version"],
                    product=entry["product"],
                )
            )
        observations.extend(
            enrich_with_fingerprints(host_observations, host=host_meta["address"] or asset.target)
        )
    return observations
def _safe_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_host_metadata(host_el: ET.Element, asset: Asset) -> Dict[str, object]:
    address_el = host_el.find("address")
    host_address = address_el.attrib.get("addr") if address_el is not None else None
    host_vendor = address_el.attrib.get("vendor") if address_el is not None else None

    hostnames: List[str] = []
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        for hostname in hostnames_el.findall("hostname"):
            name = hostname.attrib.get("name")
            if name:
                hostnames.append(name)

    os_name = None
    os_accuracy = None
    os_matches: List[str] = []
    device_types: List[str] = []
    os_cpes: List[str] = []
    os_el = host_el.find("os")
    if os_el is not None:
        for osmatch_el in os_el.findall("osmatch"):
            name = osmatch_el.attrib.get("name")
            accuracy = osmatch_el.attrib.get("accuracy")
            if name:
                os_matches.append(f"{name}{f' ({accuracy}%)' if accuracy else ''}")
            if os_name is None:
                os_name = name
                os_accuracy = accuracy
            host_vendor = osmatch_el.attrib.get("vendor") or host_vendor
            for osclass in osmatch_el.findall("osclass"):
                dtype = osclass.attrib.get("type")
                vendor = osclass.attrib.get("vendor")
                family = osclass.attrib.get("osfamily")
                osgen = osclass.attrib.get("osgen")
                if dtype:
                    device_types.append(dtype)
                descriptor = " ".join(filter(None, [vendor, family, osgen]))
                if descriptor:
                    os_matches.append(descriptor)
                for cpe in osclass.findall("cpe"):
                    if cpe.text:
                        os_cpes.append(cpe.text)

    traceroute_summary = None
    traceroute_lines: List[str] = []
    trace_el = host_el.find("trace")
    if trace_el is not None:
        hops: List[str] = []
        header_proto = trace_el.attrib.get("proto")
        header_port = trace_el.attrib.get("port")
        trace_header = "TRACEROUTE"
        if header_proto or header_port:
            trace_header += f" (using port {header_port or '?'}{f'/{header_proto}' if header_proto else ''})"
        traceroute_lines.append(trace_header)
        traceroute_lines.append("HOP RTT     ADDRESS")
        for hop in trace_el.findall("hop"):
            hop_ip = hop.attrib.get("ipaddr")
            hop_rtt = hop.attrib.get("rtt")
            ttl = hop.attrib.get("ttl") or hop.attrib.get("hop")
            if hop_ip and hop_rtt:
                hops.append(f"{hop_ip} ({hop_rtt} ms)")
            elif hop_ip:
                hops.append(hop_ip)
            traceroute_lines.append(
                f"{(ttl or '?'):>3} {f'{hop_rtt} ms' if hop_rtt else '   ?'} {hop_ip or 'unknown'}"
            )
        if hops:
            traceroute_summary = " -> ".join(hops)

    times_el = host_el.find("times")
    latency = None
    if times_el is not None:
        srtt = _safe_float(times_el.attrib.get("srtt"))
        if srtt is not None:
            latency = srtt / 1_000_000

    status_el = host_el.find("status")
    status_state = status_el.attrib.get("state") if status_el is not None else "unknown"

    extraports: List[str] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for extra in ports_el.findall("extraports"):
            state = extra.attrib.get("state", "filtered")
            count = extra.attrib.get("count", "0")
            reason = None
            extrareasons = extra.find("extrareasons")
            if extrareasons is not None:
                reason = extrareasons.attrib.get("reason")
            extraports.append(f"Not shown: {count} {state} ports ({reason or 'filtered'})")

    uptime_text = None
    uptime_el = host_el.find("uptime")
    if uptime_el is not None and uptime_el.attrib.get("seconds"):
        try:
            seconds = int(uptime_el.attrib["seconds"])
            days, rem = divmod(seconds, 86400)
            hours, rem = divmod(rem, 3600)
            minutes, _ = divmod(rem, 60)
            uptime_text = f"{days}d {hours}h {minutes}m"
            last_boot = uptime_el.attrib.get("lastboot")
            if last_boot:
                uptime_text += f" (since {last_boot})"
        except ValueError:
            uptime_text = uptime_el.attrib.get("lastboot")

    distance_text = None
    distance_el = host_el.find("distance")
    if distance_el is not None and distance_el.attrib.get("value"):
        distance_text = f"{distance_el.attrib['value']} hop(s)"

    host_scripts: List[str] = []
    hostscript_el = host_el.find("hostscript")
    if hostscript_el is not None:
        for script in hostscript_el.findall("script"):
            script_id = script.attrib.get("id")
            output = script.attrib.get("output")
            if not script_id or not output:
                continue
            host_scripts.append(f"| {script_id}:")
            for line in output.splitlines() or ["(no output)"]:
                host_scripts.append(f"|   {line}")

    display_name = hostnames[0] if hostnames else (host_address or asset.target)
    if hostnames and host_address:
        display_name = f"{display_name} ({host_address})"

    return {
        "address": host_address,
        "vendor": host_vendor,
        "display_name": display_name,
        "latency": latency,
        "status_state": status_state,
        "extraports": extraports,
        "os_name": os_name,
        "os_accuracy": os_accuracy,
        "os_matches": os_matches[:5],
        "os_cpes": list(dict.fromkeys(os_cpes)),
        "device_types": list(dict.fromkeys(device_types)),
        "uptime": uptime_text,
        "distance": distance_text,
        "traceroute_summary": traceroute_summary,
        "traceroute_lines": traceroute_lines if traceroute_lines != ["TRACEROUTE", "HOP RTT     ADDRESS"] else [],
        "host_scripts": host_scripts,
    }


def _extract_open_ports(host_el: ET.Element) -> List[Dict[str, object]]:
    entries: List[Dict[str, object]] = []
    ports_el = host_el.find("ports")
    if ports_el is None:
        return entries
    for port_el in ports_el.findall("port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.attrib.get("state") != "open":
            continue
        service_el = port_el.find("service")
        protocol = port_el.attrib.get("protocol", "tcp")
        port_id = int(port_el.attrib.get("portid", "0"))
        service_name = None
        product = None
        version = None
        extrainfo = None
        if service_el is not None:
            service_name = service_el.attrib.get("name")
            product = service_el.attrib.get("product")
            version = service_el.attrib.get("version")
            extrainfo = service_el.attrib.get("extrainfo")
        service_version = " ".join(filter(None, [product, version, extrainfo])) or None
        scripts: List[Dict[str, str]] = []
        for script in port_el.findall("script"):
            script_id = script.attrib.get("id")
            output = script.attrib.get("output")
            if not script_id or output is None:
                continue
            scripts.append(
                {
                    "id": script_id,
                    "lines": output.splitlines() or ["(no output)"],
                }
            )
        entries.append(
            {
                "port": port_id,
                "protocol": protocol,
                "state": state_el.attrib.get("state", "open"),
                "service_name": service_name,
                "service_version": service_version,
                "product": product,
                "scripts": scripts,
            }
        )
    return entries


def _render_host_report(host_meta: Dict[str, object], port_entries: List[Dict[str, object]]) -> str:
    lines: List[str] = []
    lines.append(f"Nmap scan report for {host_meta['display_name']}")
    latency = host_meta.get("latency")
    latency_text = f"{latency:.5f}s latency" if isinstance(latency, float) else "latency unknown"
    lines.append(f"Host is up ({latency_text}).")
    for extra in host_meta.get("extraports", []):
        lines.append(extra)
    lines.append("")
    lines.append("PORT     STATE SERVICE  VERSION")
    for entry in port_entries:
        port_field = f"{entry['port']}/{entry['protocol']}".ljust(9)
        state_field = str(entry.get("state", "open")).ljust(7)
        service_field = (entry.get("service_name") or "").ljust(10)
        version_field = entry.get("service_version") or ""
        lines.append(f"{port_field}{state_field}{service_field}{version_field}".rstrip())
        for script in entry.get("scripts", []):
            script_id = script.get("id")
            script_lines = script.get("lines") or []
            if not script_id:
                continue
            lines.append(f"| {script_id}:")
            for script_line in script_lines:
                lines.append(f"|   {script_line}")
    os_matches = host_meta.get("os_matches") or []
    if os_matches:
        lines.append("")
        lines.append("Aggressive OS guesses:")
        for guess in os_matches:
            lines.append(f"- {guess}")
    os_cpes = host_meta.get("os_cpes") or []
    if os_cpes:
        lines.append(f"OS CPE: {', '.join(os_cpes)}")
    device_types = host_meta.get("device_types") or []
    if device_types:
        lines.append(f"Device type: {', '.join(device_types)}")
    uptime = host_meta.get("uptime")
    if uptime:
        lines.append(f"Uptime guess: {uptime}")
    distance = host_meta.get("distance")
    if distance:
        lines.append(f"Network Distance: {distance}")
    traceroute_lines = host_meta.get("traceroute_lines") or []
    if traceroute_lines:
        lines.append("")
        lines.extend(traceroute_lines)
    host_scripts = host_meta.get("host_scripts") or []
    if host_scripts:
        lines.append("")
        lines.append("Host script results:")
        lines.extend(host_scripts)
    return "\n".join(line.rstrip() for line in lines if line is not None).strip()
