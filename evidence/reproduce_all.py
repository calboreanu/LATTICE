"""One-command Tier-1 reproduction.

Regenerates every public-reproducible (Tier-1) evidence number directly from the
open engine and writes the per-driver JSONs plus a consolidated
``evidence/repro_ledger.json``. Deterministic; runs in seconds; no proprietary
components. Tier-2 (AEGIS-host latency) is intentionally out of scope here.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import determinism
import threshold_sweep
import adversarial_suite
import miscalibration_eval

_BASE = os.path.dirname(__file__)


def main():
    det = determinism.run()
    sweep = threshold_sweep.run()
    adv = adversarial_suite.run()
    mis = miscalibration_eval.run()

    for name, obj in (("determinism", det), ("threshold_sweep", sweep),
                      ("adversarial_suite", adv), ("miscalibration_eval", mis)):
        json.dump(obj, open(os.path.join(_BASE, f"{name}.json"), "w"), indent=2)

    ledger = {
        "tier1_public_reproducible": {
            "determinism": {"total_evaluations": det["total_evaluations"],
                            "verdict_deviations": det["verdict_deviations"]},
            "threshold_sweep": {"total_points": sweep["total_points"],
                                "team_distribution_pct": sweep["tiers"]["team"]["distribution_pct"]},
            "adversarial": {"bypasses": adv["bypasses"], "vectors": adv["vectors"],
                            "clopper_pearson_95_upper_bound": adv["clopper_pearson_95_upper_bound"]},
            "confidence_cap": {
                "high_consequence_allow_cap_off": mis["tally"]["honest|cap=off"]["high_consequence_allow_rate"],
                "high_consequence_allow_cap_on": mis["tally"]["honest|cap=on"]["high_consequence_allow_rate"],
            },
        },
        "tier2_aegis_measured": {
            "latency": "p50 policy-eval / full-gate / cryptographic ops — measured on the AEGIS host; not reproduced here",
        },
    }
    json.dump(ledger, open(os.path.join(_BASE, "repro_ledger.json"), "w"), indent=2)

    print("Tier-1 reproduction complete:")
    print(f"  determinism      : {det['total_evaluations']:,} evaluations, {det['verdict_deviations']} verdict deviations")
    print(f"  threshold sweep  : {sweep['total_points']:,} points; team = {sweep['tiers']['team']['distribution_pct']}")
    print(f"  adversarial      : {adv['bypasses']}/{adv['vectors']} bypassed; 95% upper bound = {adv['clopper_pearson_95_upper_bound']*100:.1f}%")
    print(f"  confidence cap   : high-consequence autonomous ALLOW "
          f"{mis['tally']['honest|cap=off']['high_consequence_allow_rate']} -> "
          f"{mis['tally']['honest|cap=on']['high_consequence_allow_rate']}")
    print("  -> evidence/repro_ledger.json")


if __name__ == "__main__":
    main()
