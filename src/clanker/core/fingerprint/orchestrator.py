from __future__ import annotations

import logging
from typing import Iterable, List

from clanker.config import settings
from clanker.core.types import ServiceObservation
from clanker.core.fingerprint.detectors import DETECTORS, Detector

logger = logging.getLogger(__name__)


def enrich_with_fingerprints(observations: Iterable[ServiceObservation], host: str) -> List[ServiceObservation]:
    if not settings.protocol_fingerprinting_enabled:
        return list(observations)

    enriched: List[ServiceObservation] = []
    if not host:
        return list(observations)
    for obs in observations:
        selected: List[Detector] = [det for det in DETECTORS if det.applies(obs)]
        fingerprint = None
        evidence = None
        for detector in selected:
            try:
                result = detector.detect(host=host, observation=obs)
            except Exception as exc:  # pragma: no cover - defensive guard
                logger.debug("Fingerprint detector %s failed for %s:%s: %s", detector.name, host, obs.port, exc)
                continue
            if result:
                fingerprint = result.as_dict()
                evidence = [ev.as_dict() for ev in result.evidence]
                obs.evidence_summary = result.evidence_summary
                break
        obs.fingerprint = fingerprint
        obs.evidence = evidence
        enriched.append(obs)
    return enriched
