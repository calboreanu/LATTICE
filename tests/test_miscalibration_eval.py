"""Asserts the headline properties of the confidence-miscalibration evaluation (R6).

Deterministic, so these are stable regression checks on the validated claims:
  * the cap removes autonomous authorization of high-consequence actions
    (rate -> 0) for honest and inflated planners; and
  * it does so at zero cost to low-consequence autonomous operation.
"""
from __future__ import annotations

import os
import sys

# Locate evidence/ robustly (works whether this test sits in tests/ or tests/lattice/).
_d = os.path.dirname(__file__)
for _ in range(5):
    _cand = os.path.join(_d, "evidence")
    if os.path.exists(os.path.join(_cand, "miscalibration_eval.py")):
        sys.path.insert(0, _cand)
        break
    _d = os.path.dirname(_d)
import miscalibration_eval as me  # noqa: E402


def test_cap_eliminates_high_consequence_autonomy():
    s = me.run()
    for model in ("honest", "inflated_within", "inflated_beyond"):
        assert s["tally"][f"{model}|cap=on"]["high_consequence_allow_rate"] == 0.0


def test_cap_preserves_low_consequence_autonomy():
    s = me.run()
    for model in ("honest", "inflated_within"):
        on = s["tally"][f"{model}|cap=on"]["low_consequence_allow_rate"]
        off = s["tally"][f"{model}|cap=off"]["low_consequence_allow_rate"]
        assert on == off


def test_under_reporting_never_autonomous():
    s = me.run()
    assert s["tally"]["under_report|cap=off"]["allow_rate"] == 0.0
