"""Threshold-sensitivity sweep driver (Tier-1, public-reproducible).

Reproduces the paper's sweep on the open engine: confidence swept 0.000–1.000 at
0.001 resolution (1,001 points) across three deployment tiers = 3,003 points,
reporting the verdict distribution and confirming sharp (deterministic) threshold
transitions. Emits evidence/threshold_sweep.json.
"""
from __future__ import annotations

import json
import os

from lattice.policy_engine import evaluate

TIERS = {
    "solo": {"autonomous": 95, "hitl": 70, "escalate": 70},
    "team": {"autonomous": 85, "hitl": 65, "escalate": 45},
    "squadron": {"autonomous": 85, "hitl": 50, "escalate": 50},
}
STEP = 0.001
POINTS = 1001  # 0.000 .. 1.000 inclusive


def _action(c):
    return {"target": "asset-1", "tool": "adjust", "tool_class": "OTHER", "scope_tags": [],
            "time_bound": "2099-01-01T00:00:00Z", "parameters": {},
            "confidence_scores": {k: c for k in ("objective_clarity", "tool_specificity",
                "constraint_completeness", "risk_assessment_depth", "precedent_availability", "composite")}}


def _policy(thr):
    return {"policy_id": "P", "version": "1.0", "allowed_targets": ["asset-1"],
            "permitted_tools": {"OTHER": ["adjust"], "DEFAULT": ["adjust"]}, "rules": [], "thresholds": thr}


def run():
    out = {}
    total = 0
    for tier, thr in TIERS.items():
        counts = {"ALLOW": 0, "ESCALATE": 0, "BLOCK": 0}
        last = None
        boundaries = []
        for i in range(POINTS):
            c = round(i * STEP, 3)
            v = evaluate(_action(c), _policy(thr)).verdict
            counts[v] += 1
            if last is not None and v != last:
                boundaries.append({"at_confidence": c, "from": last, "to": v})
            last = v
            total += 1
        pct = {k: round(100.0 * n / POINTS, 1) for k, n in counts.items()}
        out[tier] = {"thresholds": thr, "points": POINTS, "distribution_pct": pct, "transitions": boundaries}
    return {"total_points": total, "resolution": STEP, "tiers": out}


if __name__ == "__main__":
    s = run()
    json.dump(s, open(os.path.join(os.path.dirname(__file__), "threshold_sweep.json"), "w"), indent=2)
    print(f"{s['total_points']:,} sweep points across {len(s['tiers'])} tiers")
    for tier, d in s["tiers"].items():
        print(f"  {tier}: {d['distribution_pct']}  transitions={[b['at_confidence'] for b in d['transitions']]}")
