"""Determinism driver (Tier-1, public-reproducible).

Reproduces the paper's determinism claim on the open engine: 13 governance
configurations repeated 10,000 times each = 130,000 evaluations, zero verdict
variance. Deterministic; no RNG. Emits evidence/determinism.json.
"""
from __future__ import annotations

import json
import os

from lattice.policy_engine import evaluate

REPEATS = 10_000


def _scores(v=0.95, composite=None):
    s = {k: v for k in ("objective_clarity", "tool_specificity", "constraint_completeness",
                        "risk_assessment_depth", "precedent_availability")}
    s["composite"] = v if composite is None else composite
    return s


def _ab(**kw):
    a = {"target": "asset-1", "tool": "adjust", "tool_class": "OTHER", "scope_tags": [],
         "time_bound": "2099-01-01T00:00:00Z", "parameters": {}, "confidence_scores": _scores()}
    a.update(kw)
    return a


def _pol(**kw):
    p = {"policy_id": "P", "version": "1.0", "allowed_targets": ["asset-1"],
         "permitted_tools": {"OTHER": ["adjust"], "DEFAULT": ["adjust"]}, "rules": [],
         "thresholds": {"autonomous": 85, "hitl": 65, "escalate": 45}}
    p.update(kw)
    return p


# 13 distinct configurations spanning the verdict space + every v1.1 mechanism.
CONFIGS = {
    "clean_allow": (_ab(), _pol()),
    "out_of_scope_target": (_ab(target="evil-9"), _pol()),
    "unpermitted_tool": (_ab(tool="rm_rf"), _pol()),
    "mid_confidence_escalate": (_ab(confidence_scores=_scores(0.60)), _pol()),
    "low_confidence_block": (_ab(confidence_scores=_scores(0.20)), _pol()),
    "target_denylist": (_ab(), _pol(rules=[{"type": "TARGET_DENYLIST", "effect": "BLOCK", "values": ["asset-1"]}])),
    "tool_denylist": (_ab(), _pol(rules=[{"type": "TOOL_DENYLIST", "effect": "BLOCK", "values": ["adjust"]}])),
    "scope_tag_escalate": (_ab(scope_tags=["SENSITIVE"]), _pol(rules=[{"type": "SCOPE_TAG_DENYLIST", "effect": "ESCALATE", "values": ["SENSITIVE"]}])),
    "time_window_outside": (_ab(time_bound="2099-12-31T00:00:00Z"),
                            _pol(rules=[{"type": "TIME_WINDOW", "effect": "BLOCK", "window": {"start": "2099-01-01T00:00:00Z", "end": "2099-06-01T00:00:00Z"}}])),
    "prerequisite_missing": (_ab(prerequisites_satisfied=[]), _pol(rules=[{"type": "PREREQUISITE", "effect": "BLOCK", "requires": ["iso"]}])),
    "confidence_cap_irreversible": (_ab(irreversibility_class="irreversible"), _pol(confidence_caps={"irreversibility": {"irreversible": 0.70}})),
    "composite_divergence": (_ab(confidence_scores=_scores(0.50, composite=0.95)), _pol()),
    "fail_closed_missing_component": (_ab(confidence_scores={"objective_clarity": 0.9}), _pol()),
}


def run():
    per_config = {}
    total = deviations = 0
    for name, (ab, pol) in CONFIGS.items():
        verdicts = set()
        first = None
        for _ in range(REPEATS):
            v = evaluate(ab, pol).verdict
            verdicts.add(v)
            first = first or v
        total += REPEATS
        if len(verdicts) != 1:
            deviations += 1
        per_config[name] = {"verdict": first, "distinct_verdicts": len(verdicts), "repeats": REPEATS}
    return {"configurations": len(CONFIGS), "repeats_each": REPEATS,
            "total_evaluations": total, "verdict_deviations": deviations, "per_config": per_config}


if __name__ == "__main__":
    s = run()
    json.dump(s, open(os.path.join(os.path.dirname(__file__), "determinism.json"), "w"), indent=2)
    print(f"{s['total_evaluations']:,} evaluations across {s['configurations']} configs x {s['repeats_each']:,}; "
          f"verdict deviations: {s['verdict_deviations']}")
