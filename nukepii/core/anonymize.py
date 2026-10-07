"""k-Anonymity / l-Diversity / t-Closeness helpers — Faz-2.

Operates on list-of-dict records (already extracted). Generalization is
caller-supplied via hierarchies; this module checks guarantees + suppresses.

Example:
    gen = {"city": lambda v: "Marmara" if v in ("Istanbul","Bursa") else "Other",
           "age": lambda v: f"{int(v)//10*10}-{int(v)//10*10+9}"}
    report = k_anonymize(records, quasi=["city","age"], k=2, hierarchies=gen)
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
from typing import Any


def _eq_key(rec: dict[str, Any], quasi: list[str]) -> tuple:
    return tuple(str(rec.get(q, "")) for q in quasi)


def k_anonymize(records: list[dict[str, Any]], quasi: list[str], k: int = 5,
                hierarchies: dict[str, Callable[[Any], Any]] | None = None,
                suppress: bool = True) -> dict[str, Any]:
    gen = hierarchies or {}
    generalized: list[dict[str, Any]] = []
    for r in records:
        nr = dict(r)
        for q in quasi:
            if q in gen:
                try:
                    nr[q] = gen[q](r.get(q))
                except Exception:
                    nr[q] = "*"
        generalized.append(nr)
    groups: dict[tuple, list[int]] = defaultdict(list)
    for i, r in enumerate(generalized):
        groups[_eq_key(r, quasi)].append(i)
    suppressed = 0
    out: list[dict[str, Any]] = []
    for _key, idxs in groups.items():
        if len(idxs) < k and suppress:
            suppressed += len(idxs)
            continue
        for i in idxs:
            out.append(generalized[i])
    return {"records": out, "k": k, "classes": len(groups),
            "min_class": min((len(v) for v in groups.values()), default=0),
            "suppressed": suppressed, "satisfies_k": all(len(v) >= k for v in groups.values()) or not out}


def l_diversity(records: list[dict[str, Any]], quasi: list[str],
                sensitive: str, level: int = 2) -> dict[str, Any]:
    groups: dict[tuple, set[str]] = defaultdict(set)
    for r in records:
        groups[_eq_key(r, quasi)].add(str(r.get(sensitive, "")))
    bad = sum(1 for v in groups.values() if len(v) < level)
    return {"l": level, "classes": len(groups), "violating": bad,
            "satisfies_l": bad == 0}


def t_closeness(records: list[dict[str, Any]], quasi: list[str],
                sensitive: str, t: float = 0.2) -> dict[str, Any]:
    global_dist = Counter(str(r.get(sensitive, "")) for r in records)
    n = max(len(records), 1)
    global_p = {k: v / n for k, v in global_dist.items()}
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for r in records:
        groups[_eq_key(r, quasi)].append(r)
    worst = 0.0
    for members in groups.values():
        local = Counter(str(m.get(sensitive, "")) for m in members)
        m = max(len(members), 1)
        dist = sum(abs(local.get(k, 0) / m - global_p.get(k, 0)) for k in set(local) | set(global_p)) / 2
        worst = max(worst, dist)
    return {"t": t, "max_distance": round(worst, 4), "satisfies_t": worst <= t}


__all__ = ["k_anonymize", "l_diversity", "t_closeness"]
