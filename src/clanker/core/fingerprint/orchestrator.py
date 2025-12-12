from __future__ import annotations

import logging
from typing import Iterable, List, Optional

from clanker.config import settings
from clanker.core.types import ServiceObservation
from clanker.core.fingerprint.detectors import DETECTORS, Detector
from clanker.core.fingerprint.types import FingerprintResult

logger = logging.getLogger(__name__)


def apply_fingerprint_result(observation: ServiceObservation, result: FingerprintResult) -> ServiceObservation:
    """
    Apply a fingerprint result to an observation for downstream rule/CPE matching.
    """
    observation.fingerprint = result.as_dict()
    observation.evidence = [ev.as_dict() for ev in result.evidence]
    observation.evidence_summary = result.evidence_summary
    if result.product and not observation.service_name:
        observation.service_name = result.product
    if result.product and not observation.product:
        observation.product = result.product
    if result.version:
        if observation.version_confidence is None or (result.version_confidence or 0) >= (observation.version_confidence or 0):
            observation.service_version = result.version
            observation.version_confidence = result.version_confidence or observation.version_confidence
    elif result.version_confidence and (observation.version_confidence or 0) < result.version_confidence:
        observation.version_confidence = result.version_confidence
    return observation


def enrich_with_fingerprints(observations: Iterable[ServiceObservation], host: str) -> List[ServiceObservation]:
    if not settings.protocol_fingerprinting_enabled:
        return list(observations)

    enriched: List[ServiceObservation] = []
    if not host:
        return list(observations)
    for obs in observations:
        selected: List[Detector] = [det for det in DETECTORS if det.applies(obs)]
        for detector in selected:
            try:
                result = detector.detect(host=host, observation=obs)
            except Exception as exc:  # pragma: no cover - defensive guard
                logger.debug("Fingerprint detector %s failed for %s:%s: %s", detector.name, host, obs.port, exc)
                continue
            if result:
                apply_fingerprint_result(obs, result)
                break
        enriched.append(obs)
    return enriched


def parse_fingerprint_artifact(
    evidence_kind: str,
    observation: ServiceObservation,
    artifacts: dict,
    host: Optional[str] = None,
) -> Optional[ServiceObservation]:
    """
    Parse captured artifacts (banners, handshakes) without live probing.

    Returns the observation with fingerprint/evidence fields populated if a parser is found.
    """
    for detector in DETECTORS:
        if evidence_kind not in detector.evidence_kinds:
            continue
        if not detector.applies(observation):
            continue
        try:
            result = detector.parse_artifacts(host or observation.host_address or "", observation, artifacts)
        except Exception:
            logger.debug("parser %s failed for %s:%s", detector.name, host or observation.host_address, observation.port)
            continue
        if result:
            return apply_fingerprint_result(observation, result)
    return None
