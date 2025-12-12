from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from clanker.core.agent_parsers import normalize_service_name
from clanker.core.types import ServiceObservation

logger = logging.getLogger(__name__)

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
_ENGINE_CACHE: Dict[Tuple[Path, Tuple[Tuple[str, str], ...]], Tuple[float, "CpeInferenceEngine"]] = {}


@dataclass(frozen=True)
class CuratedCpeRecord:
    template: str
    confidence: str
    source: str
    matches: Tuple[str, ...]
    protocols: Tuple[str, ...] = ()
    ports: Tuple[int, ...] = ()


@dataclass
class CpeGuess:
    value: str
    confidence: str
    source: str = "cpe-inference"
    matched_by: Optional[str] = None


def _normalize_confidence(value: str) -> str:
    raw = (value or "medium").strip().lower()
    if raw not in CONFIDENCE_ORDER:
        return "medium"
    return raw


def _normalize_protocol(proto: str) -> str:
    return proto.strip().lower()


def _normalize_match(name: str) -> str:
    return normalize_service_name(name)


def _normalize_ports(values: Iterable[int | str]) -> Tuple[int, ...]:
    ports: List[int] = []
    for raw in values:
        try:
            port = int(raw)
        except Exception:
            continue
        if port not in ports:
            ports.append(port)
    return tuple(ports)


def _normalize_protocols(values: Iterable[str]) -> Tuple[str, ...]:
    protocols: List[str] = []
    for raw in values:
        proto = _normalize_protocol(str(raw))
        if proto and proto not in protocols:
            protocols.append(proto)
    return tuple(protocols)


def _build_curated_record(entry: Dict[str, object]) -> Optional[CuratedCpeRecord]:
    template = entry.get("cpe") if isinstance(entry, dict) else None
    if not isinstance(template, str):
        return None
    matches_raw = entry.get("match") if isinstance(entry, dict) else None
    if not isinstance(matches_raw, list) or not matches_raw:
        return None
    matches = tuple(_normalize_match(m) for m in matches_raw if isinstance(m, str) and m.strip())
    if not matches:
        return None
    confidence = _normalize_confidence(str(entry.get("confidence", "medium")))
    source = str(entry.get("source") or "curated").strip() or "curated"
    protocols_raw = entry.get("protocols") if isinstance(entry, dict) else None
    ports_raw = entry.get("ports") if isinstance(entry, dict) else None
    protocols = _normalize_protocols(protocols_raw) if isinstance(protocols_raw, list) else ()
    ports = _normalize_ports(ports_raw) if isinstance(ports_raw, list) else ()
    return CuratedCpeRecord(
        template=template,
        confidence=confidence,
        source=source,
        matches=matches,
        protocols=protocols,
        ports=ports,
    )


def _legacy_mapping_to_records(payload: Dict[str, object]) -> List[CuratedCpeRecord]:
    records: List[CuratedCpeRecord] = []
    for name, template in payload.items():
        if not isinstance(name, str) or not isinstance(template, str):
            continue
        normalized = _normalize_match(name)
        records.append(
            CuratedCpeRecord(
                template=template,
                confidence="medium",
                source="legacy-map",
                matches=(normalized,),
            )
        )
    return records


@lru_cache(maxsize=4)
def _load_curated_records_cached(path: Path, mtime: float) -> Tuple[CuratedCpeRecord, ...]:
    if not path.exists():
        return ()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("Failed to load curated CPE map from %s", path, exc_info=True)
        return ()

    records: List[CuratedCpeRecord] = []
    if isinstance(payload, dict) and all(isinstance(v, str) for v in payload.values()):
        records.extend(_legacy_mapping_to_records(payload))
    elif isinstance(payload, dict):
        services = payload.get("services") or []
        if isinstance(services, list):
            for raw in services:
                if not isinstance(raw, dict):
                    continue
                parsed = _build_curated_record(raw)
                if parsed:
                    records.append(parsed)
    elif isinstance(payload, list):
        for raw in payload:
            if not isinstance(raw, dict):
                continue
            parsed = _build_curated_record(raw)
            if parsed:
                records.append(parsed)
    return tuple(records)


def load_curated_records(path: Path) -> List[CuratedCpeRecord]:
    mtime = path.stat().st_mtime if path.exists() else 0.0
    return list(_load_curated_records_cached(path, mtime))


def _normalize_version(version: Optional[str]) -> str:
    if not version:
        return "*"
    raw = version.strip()
    if not raw:
        return "*"
    match = re.search(r"[0-9][0-9A-Za-z.+_-]*", raw)
    if match:
        return match.group(0)
    return raw


def _degrade_confidence(base: str, has_version: bool, version_confidence: Optional[float] = None) -> str:
    normalized = _normalize_confidence(base)
    if version_confidence is not None:
        try:
            if float(version_confidence) >= 0.7:
                normalized = "high"
            elif float(version_confidence) < 0.4:
                normalized = "low"
        except Exception:
            pass
    if has_version:
        return normalized
    if normalized == "high":
        return "medium"
    if normalized == "medium":
        return "low"
    return normalized


class CpeInferenceEngine:
    def __init__(self, curated_map_path: Path, rule_templates: Optional[Dict[str, str]] = None) -> None:
        self.curated_records = load_curated_records(curated_map_path)
        self._curated_index: Dict[str, List[CuratedCpeRecord]] = {}
        for record in self.curated_records:
            for name in record.matches:
                self._curated_index.setdefault(name, []).append(record)
        self.rule_templates: Dict[str, str] = {}
        if rule_templates:
            for name, template in rule_templates.items():
                normalized_name = _normalize_match(name)
                if not normalized_name or not isinstance(template, str):
                    continue
                self.rule_templates[normalized_name] = template
        self._cache: Dict[Tuple, Optional[CpeGuess]] = {}

    def _collect_names(self, observation: ServiceObservation) -> List[str]:
        names: List[str] = []
        for candidate in [
            observation.service_name,
            observation.product,
            (observation.fingerprint or {}).get("product") if observation.fingerprint else None,
        ]:
            if not candidate:
                continue
            normalized = _normalize_match(str(candidate))
            if normalized and normalized not in names:
                names.append(normalized)
        return names

    def _curated_candidates(
        self,
        names: Iterable[str],
        version: str,
        port: Optional[int],
        protocol: Optional[str],
        product_hint: str,
        version_confidence: Optional[float],
    ) -> List[CpeGuess]:
        candidates: List[CpeGuess] = []
        proto_norm = _normalize_protocol(protocol or "") if protocol else ""
        for name in names:
            for record in self._curated_index.get(name, []):
                if record.ports and (port or 0) not in record.ports:
                    continue
                if record.protocols and proto_norm and proto_norm not in record.protocols:
                    continue
                has_version = version not in ("", "*")
                confidence = _degrade_confidence(record.confidence, has_version, version_confidence)
                try:
                    value = record.template.format(version=version or "*", product=product_hint or name)
                except Exception:
                    value = record.template
                candidates.append(
                    CpeGuess(
                        value=value,
                        confidence=confidence,
                        source=record.source,
                        matched_by=name,
                    )
                )
        return candidates

    def _rule_template_candidates(
        self,
        names: Sequence[str],
        version: str,
        product_hint: str,
        rule_templates: Sequence[str] | None,
        version_confidence: Optional[float],
    ) -> List[CpeGuess]:
        templates: List[str] = []
        for name in names:
            tmpl = self.rule_templates.get(name)
            if tmpl:
                templates.append(tmpl)
        if rule_templates:
            templates.extend(t for t in rule_templates if isinstance(t, str))
        candidates: List[CpeGuess] = []
        for template in templates:
            has_version = version not in ("", "*")
            confidence = _degrade_confidence("high", has_version, version_confidence)
            product_value = product_hint or (names[0] if names else "")
            try:
                value = template.format(version=version or "*", product=product_value)
            except Exception:
                value = template
            candidates.append(
                CpeGuess(
                    value=value,
                    confidence=confidence,
                    source="rule-template",
                    matched_by="rule-template",
                )
            )
        return candidates

    def _fallback_candidates(
        self, vendor: str, product: str, version: str, version_confidence: Optional[float]
    ) -> List[CpeGuess]:
        candidates: List[CpeGuess] = []
        if vendor and product:
            has_version = version not in ("", "*")
            confidence = _degrade_confidence("medium" if has_version else "low", has_version, version_confidence)
            candidates.append(
                CpeGuess(
                    value=f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
                    confidence=confidence,
                    source="fallback-vendor-product",
                    matched_by="vendor-product",
                )
            )
        if product and not vendor:
            has_version = version not in ("", "*")
            candidates.append(
                CpeGuess(
                    value=f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*",
                    confidence=_degrade_confidence("medium" if has_version else "low", has_version, version_confidence),
                    source="fallback-product",
                    matched_by="product",
                )
            )
        return candidates

    def _version_confidence(self, observation: ServiceObservation) -> Optional[float]:
        fingerprint = observation.fingerprint or {}
        hints = [
            getattr(observation, "version_confidence", None),
            fingerprint.get("version_confidence"),
            fingerprint.get("confidence"),
        ]
        for hint in hints:
            try:
                if hint is None:
                    continue
                return float(hint)
            except Exception:
                continue
        return None

    def _vendor_hint(self, observation: ServiceObservation) -> str:
        vendor_candidates = [
            observation.host_vendor,
            (observation.fingerprint or {}).get("vendor") if observation.fingerprint else None,
        ]
        for candidate in vendor_candidates:
            if candidate:
                return str(candidate).strip().lower()
        return ""

    def _product_hint(self, observation: ServiceObservation, names: Sequence[str]) -> str:
        for candidate in [
            (observation.fingerprint or {}).get("product") if observation.fingerprint else None,
            observation.product,
            observation.service_name,
            names[0] if names else "",
        ]:
            if candidate:
                return str(candidate).strip().lower()
        return ""

    def infer(
        self, observation: ServiceObservation, rule_templates: Sequence[str] | None = None
    ) -> Optional[CpeGuess]:
        names = self._collect_names(observation)
        version = _normalize_version(observation.service_version)
        vendor = self._vendor_hint(observation)
        product_hint = self._product_hint(observation, names)
        version_confidence = self._version_confidence(observation)
        cache_key = (
            tuple(names),
            version,
            vendor,
            product_hint,
            observation.port,
            (observation.protocol or "").lower(),
            tuple(sorted(rule_templates)) if rule_templates else (),
            version_confidence,
        )
        if cache_key in self._cache:
            return self._cache[cache_key]

        candidates: List[CpeGuess] = []
        candidates.extend(
            self._curated_candidates(
                names, version, observation.port, observation.protocol, product_hint, version_confidence
            )
        )
        candidates.extend(
            self._rule_template_candidates(names, version, product_hint, rule_templates, version_confidence)
        )
        candidates.extend(self._fallback_candidates(vendor, product_hint, version, version_confidence))

        if not candidates:
            self._cache[cache_key] = None
            return None

        def _score(guess: CpeGuess) -> Tuple[int, int]:
            source_priority = 1
            if guess.source == "rule-template":
                source_priority = 2
            elif guess.source and "curated" in guess.source:
                source_priority = 3
            elif guess.source.startswith("fallback"):
                source_priority = 0
            return (source_priority, CONFIDENCE_ORDER.get(_normalize_confidence(guess.confidence), 0))

        best = sorted(candidates, key=_score, reverse=True)[0]
        self._cache[cache_key] = best
        return best


def get_cpe_engine(curated_map_path: Path, rule_templates: Optional[Dict[str, str]] = None) -> "CpeInferenceEngine":
    """
    Return a cached CpeInferenceEngine keyed by curated map mtime and normalized rule templates.
    """
    normalized_templates: List[Tuple[str, str]] = []
    if rule_templates:
        for name, template in rule_templates.items():
            normalized_name = _normalize_match(name)
            if not normalized_name or not isinstance(template, str):
                continue
            normalized_templates.append((normalized_name, template))
    key = (curated_map_path.resolve(), tuple(sorted(normalized_templates)))
    mtime = curated_map_path.stat().st_mtime if curated_map_path.exists() else 0.0
    cached = _ENGINE_CACHE.get(key)
    if cached and cached[0] == mtime:
        return cached[1]
    engine = CpeInferenceEngine(curated_map_path, rule_templates=dict(normalized_templates))
    _ENGINE_CACHE[key] = (mtime, engine)
    return engine


__all__ = ["CpeGuess", "CuratedCpeRecord", "CpeInferenceEngine", "get_cpe_engine", "load_curated_records"]
