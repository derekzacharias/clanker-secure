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
    for rule in selected_rules:
        match = rule.match
        if match.port is not None and match.port != observation.port:
            continue
        if match.service_name and (observation.service_name or "").lower() != match.service_name.lower():
            continue
        if match.version_contains and match.version_contains.lower() not in (observation.service_version or "").lower():
            continue
        matches.append(rule)
    return matches
