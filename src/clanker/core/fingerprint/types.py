from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class FingerprintEvidence:
    type: str
    summary: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "summary": self.summary, "data": self.data}


@dataclass
class FingerprintResult:
    protocol: str
    port: int
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    confidence: float = 0.0
    source: str = "unknown"
    attributes: Dict[str, Any] = field(default_factory=dict)
    evidence_summary: Optional[str] = None
    evidence: List[FingerprintEvidence] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["evidence"] = [ev.as_dict() for ev in self.evidence]
        return payload
