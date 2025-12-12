from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List

from pydantic import BaseModel

from clanker.config import settings
from clanker.core.types import ServiceObservation


class RuleMatch(BaseModel):
    port: int | None = None
    service_name: str | None = None
    version_contains: str | None = None


class Rule(BaseModel):
    id: str
    match: RuleMatch
    cve: List[str]
    severity: str
    description: str


@lru_cache(maxsize=1)
def load_rules(path: Path | None = None) -> List[Rule]:
    rule_path = Path(path or settings.rules_path)
    with rule_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return [Rule(**raw_rule) for raw_rule in payload]


def evaluate_rules(observation: ServiceObservation, rules: Iterable[Rule] | None = None) -> List[Rule]:
    selected_rules = rules or load_rules()
    matches: List[Rule] = []
    fingerprint = observation.fingerprint or {}
    candidate_names = []
    if observation.service_name:
        candidate_names.append(str(observation.service_name).lower())
    for alt in (fingerprint.get("product"), fingerprint.get("protocol")):
        if alt:
            candidate_names.append(str(alt).lower())
    candidate_names = list(dict.fromkeys(candidate_names))
    candidate_version = observation.service_version or str(fingerprint.get("version") or "")

    for rule in selected_rules:
        match = rule.match
        if match.port is not None and match.port != observation.port:
            continue
        if match.service_name and match.service_name.lower() not in candidate_names:
            continue
        if match.version_contains and match.version_contains.lower() not in candidate_version.lower():
            continue
        matches.append(rule)
    return matches
