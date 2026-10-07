"""NukePII custom rule engine — Faz-1 MVP (regex-only, YAML/JSON).

Users can add detectors without touching code:

```yaml
rules:
  - id: ACME_EMP_ID
    pattern: 'ACME-\\d{6}'
    confidence: 0.95
    priority: 85
    region: GLOBAL
    compliance: [GDPR]
    description: ACME employee badge
```

```python
from nukepii.core.rules import load_rules
from nukepii.core.detectors import PIIDetector
specs, errors = load_rules("rules/custom.yaml")
det = PIIDetector(custom_rules=[r.to_spec_kwargs() for r in specs])
```

MVP scope: regex + confidence/priority/region/compliance only.
Checksum/context validators arrive in Faz-2 (RuleValidator protocol).
Invalid rules never break a scan — they are collected in ``errors``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CustomRule:
    id: str
    pattern: str
    confidence: float = 0.9
    priority: int = 70
    region: str = "GLOBAL"
    compliance: list[str] = field(default_factory=list)
    description: str = ""

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.pattern)

    def to_spec_kwargs(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "pattern": self.pattern,
            "confidence": self.confidence,
            "priority": self.priority,
            "region": self.region,
            "compliance": list(self.compliance),
            "description": self.description,
        }


def _validate_raw(raw: dict[str, Any], idx: int) -> CustomRule:
    if not isinstance(raw, dict):
        raise ValueError(f"rule #{idx} must be a mapping")
    rid = str(raw.get("id", f"CUSTOM_{idx}")).strip().upper()
    if not rid:
        raise ValueError(f"rule #{idx} missing id")
    pat = raw.get("pattern")
    if not pat or not isinstance(pat, str):
        raise ValueError(f"rule {rid} missing regex 'pattern'")
    try:
        re.compile(pat)
    except re.error as exc:
        raise ValueError(f"rule {rid} bad regex: {exc}") from exc
    try:
        conf = float(raw.get("confidence", 0.9))
    except Exception as exc:
        raise ValueError(f"rule {rid} bad confidence") from exc
    if not 0.0 < conf <= 1.0:
        raise ValueError(f"rule {rid} confidence must be (0,1]")
    try:
        prio = int(raw.get("priority", 70))
    except Exception as exc:
        raise ValueError(f"rule {rid} bad priority") from exc
    region = str(raw.get("region", "GLOBAL")).strip().upper() or "GLOBAL"
    comp = raw.get("compliance", []) or []
    if isinstance(comp, str):
        comp = [comp]
    comp = [str(c).strip().upper() for c in comp if str(c).strip()]
    desc = str(raw.get("description", ""))
    return CustomRule(id=rid, pattern=pat, confidence=conf, priority=prio,
                      region=region, compliance=comp, description=desc)


def _load_yaml(text: str) -> Any:
    try:
        import yaml  # type: ignore
    except Exception as exc:
        raise ImportError("PyYAML required for .yaml rules (pip install pyyaml)") from exc
    return yaml.safe_load(text)


def load_rules(path: str | Path) -> tuple[list[CustomRule], list[str]]:
    """Load rules file (.yaml/.yml/.json). Returns (rules, errors)."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"No such rules file: {path}")
    text = p.read_text(encoding="utf-8-sig")
    try:
        data = _load_yaml(text) if p.suffix.lower() in (".yaml", ".yml") else json.loads(text)
    except ImportError:
        raise
    except Exception as exc:
        return [], [f"{p.name}: parse error: {exc}"]
    items: Any = data.get("rules", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return [], [f"{p.name}: top-level 'rules' must be a list"]
    rules: list[CustomRule] = []
    errors: list[str] = []
    for i, raw in enumerate(items):
        try:
            rules.append(_validate_raw(raw, i))
        except ValueError as exc:
            errors.append(str(exc))
    # dedupe by id, last wins
    seen: dict[str, CustomRule] = {}
    for r in rules:
        seen[r.id] = r
    return list(seen.values()), errors


def load_rules_dir(directory: str | Path) -> tuple[list[CustomRule], list[str]]:
    """Load all *.yaml/*.yml/*.json in dir (sorted). Missing dir -> ([], [])."""
    d = Path(directory)
    if not d.is_dir():
        return [], []
    rules: list[CustomRule] = []
    errors: list[str] = []
    for f in sorted(d.glob("*")):
        if f.suffix.lower() not in (".yaml", ".yml", ".json"):
            continue
        try:
            r, e = load_rules(f)
            rules.extend(r)
            errors.extend(e)
        except FileNotFoundError:
            continue
        except ImportError as exc:
            errors.append(str(exc))
    seen: dict[str, CustomRule] = {}
    for r in rules:
        seen[r.id] = r
    return list(seen.values()), errors


__all__ = ["CustomRule", "load_rules", "load_rules_dir"]
