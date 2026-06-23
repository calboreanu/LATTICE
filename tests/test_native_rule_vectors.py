"""Native-rule test vectors (v1.1): TIME_WINDOW, PREREQUISITE, confidence cap.

Ships the new rule types in the reproducible vector corpus (R2 data package) and
checks each shipped bundle against its expected verdict, so the vectors — not just
the unit tests — demonstrate the new mechanisms.
"""
from __future__ import annotations

import glob
import json
import os

from lattice.policy_engine import evaluate


def _vectors_dir():
    # Resolve test_vectors/native_rules robustly (works in tests/ or tests/lattice/).
    d = os.path.dirname(__file__)
    for _ in range(5):
        cand = os.path.join(d, "test_vectors", "native_rules")
        if os.path.isdir(cand):
            return cand
        d = os.path.dirname(d)
    raise RuntimeError("test_vectors/native_rules not found")


_DIR = _vectors_dir()


def _load(name):
    with open(os.path.join(_DIR, name), encoding="utf-8") as f:
        return json.load(f)


def test_native_rule_vectors():
    policy = _load("policy.json")
    expected = _load("expected_verdicts.json")
    bundles = {}
    for path in glob.glob(os.path.join(_DIR, "ab_*.json")):
        b = _load(os.path.basename(path))
        bundles[b["bundle_id"]] = b

    assert set(bundles) == set(expected), (set(bundles), set(expected))

    for bundle_id, exp in expected.items():
        vr = evaluate(bundles[bundle_id], policy)
        assert vr.verdict == exp["verdict"], (bundle_id, vr.verdict, exp["verdict"])
        if "reason" in exp:
            assert exp["reason"] in vr.reason_codes, (bundle_id, exp["reason"], vr.reason_codes)
