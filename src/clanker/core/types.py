from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ServiceObservation:
    asset_id: int
    host_address: Optional[str]
    host_os_name: Optional[str]
    host_os_accuracy: Optional[str]
    host_vendor: Optional[str]
    traceroute_summary: Optional[str]
    host_report: Optional[str]
    port: int
    protocol: str
    service_name: Optional[str]
    service_version: Optional[str]
    product: Optional[str]
    fingerprint: Optional[Dict[str, object]] = field(default=None)
    evidence: Optional[List[Dict[str, object]]] = field(default=None)
    evidence_summary: Optional[str] = field(default=None)
