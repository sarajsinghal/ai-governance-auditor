from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Rule:
    id: str
    version: str
    title: str
    domain: str
    severity: str
    requirement: str
    applicability: str
    kind: str
    terms: tuple[str, ...]
    frameworks: dict[str, str]
    source_refs: tuple[str, ...]


def load_catalog(path: Path | None = None) -> tuple[str, str, list[Rule]]:
    data = json.loads((path or ROOT / "rules.json").read_text(encoding="utf-8"))
    rules = [Rule(**{**item, "terms": tuple(item["terms"]), "source_refs": tuple(item["source_refs"])}) for item in data["rules"]]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("Rule IDs must be unique")
    if any(not r.frameworks or set(r.frameworks) != {"NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "OWASP LLM Top 10 2026"} for r in rules):
        raise ValueError("Each rule must map to all configured frameworks")
    return data["catalog_version"], data["reviewed_on"], rules
