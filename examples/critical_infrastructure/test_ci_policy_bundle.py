#!/usr/bin/env python3
"""
Critical Infrastructure Policy Bundle — Test Runner
====================================================
Demonstrates LATTICE governance primitive transfer to a non-security domain
(electric utility scheduled switching operations).

Runs three action bundles against the CI policy bundle through the
LATTICE execution gate and captures verdicts + audit traces.

Usage (from repo root):
    python -m examples.critical_infrastructure.test_ci_policy_bundle
  or:
    cd examples/critical_infrastructure && python test_ci_policy_bundle.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

# Resolve paths: script lives at examples/critical_infrastructure/,
# repo root (with src/) is two directories up.
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from lattice.policy_engine import evaluate
from lattice.execution_gate import enforce

# ---------------------------------------------------------------------------
# Load artifacts
# ---------------------------------------------------------------------------
def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)

policy = load_json(SCRIPT_DIR / "ci_policy_bundle.json")
bundle_allow = load_json(SCRIPT_DIR / "ci_bundle_allow.json")
bundle_escalate = load_json(SCRIPT_DIR / "ci_bundle_escalate.json")
bundle_block = load_json(SCRIPT_DIR / "ci_bundle_block.json")

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
TEST_CASES = [
    {
        "name": "Bundle 1 — Routine breaker opening (expected: ALLOW)",
        "bundle": bundle_allow,
        "expected_verdict": "ALLOW",
    },
    {
        "name": "Bundle 2 — Relay protection change, incomplete contingency (expected: ESCALATE)",
        "bundle": bundle_escalate,
        "expected_verdict": "ESCALATE",
    },
    {
        "name": "Bundle 3 — Out-of-scope target (expected: BLOCK)",
        "bundle": bundle_block,
        "expected_verdict": "BLOCK",
    },
]

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
print("=" * 72)
print("LATTICE CI Policy Bundle — Test Run")
print("Domain: Electric Utility Scheduled Switching Operations")
print("=" * 72)
print()

all_passed = True
audit_traces = []

for i, tc in enumerate(TEST_CASES, 1):
    print(f"--- Test Case {i}: {tc['name']} ---")
    print(f"  Target:     {tc['bundle']['target']}")
    print(f"  Tool:       {tc['bundle']['tool']}")
    print(f"  Composite:  {tc['bundle']['confidence_scores']['composite']}")

    # Phase 1: Policy evaluation only (no gate, no audit)
    vr = evaluate(tc["bundle"], policy)
    print(f"  [policy_engine.evaluate]")
    print(f"    Verdict:     {vr.verdict}")
    print(f"    Confidence:  {vr.confidence:.2f}")
    print(f"    Reasons:     {vr.reason_codes}")

    # Phase 2: Full execution gate with audit
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = os.path.join(tmpdir, f"ci_audit_case_{i}.json")
        gate_verdict, audit_record = enforce(
            tc["bundle"],
            policy,
            audit_path,
            require_signed_audit=False,
        )
        print(f"  [execution_gate.enforce]")
        print(f"    Gate verdict: {gate_verdict}")
        print(f"    Audit record ID: {audit_record.get('record_id', 'N/A')}")
        print(f"    Unit hash:    {audit_record.get('unit_hash', 'N/A')[:16]}...")

        audit_traces.append({
            "test_case": i,
            "name": tc["name"],
            "gate_verdict": gate_verdict,
            "audit_record": audit_record,
        })

    # The execution gate maps both ESCALATE and BLOCK from the policy engine
    # to a "BLOCK" gate verdict (only ALLOW passes the gate).
    # So for expected verdicts: ALLOW→ALLOW, ESCALATE→BLOCK, BLOCK→BLOCK
    expected_gate = "ALLOW" if tc["expected_verdict"] == "ALLOW" else "BLOCK"
    passed = gate_verdict == expected_gate and vr.verdict == tc["expected_verdict"]

    status = "PASS" if passed else "FAIL"
    if not passed:
        all_passed = False
    print(f"  Policy verdict match: {'YES' if vr.verdict == tc['expected_verdict'] else 'NO'} "
          f"(got {vr.verdict}, expected {tc['expected_verdict']})")
    print(f"  Gate verdict match:   {'YES' if gate_verdict == expected_gate else 'NO'} "
          f"(got {gate_verdict}, expected {expected_gate})")
    print(f"  Result: ** {status} **")
    print()

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("=" * 72)
print(f"SUMMARY: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
print("=" * 72)

# ---------------------------------------------------------------------------
# Write audit trace from Bundle 1 (ALLOW case) for deposit
# ---------------------------------------------------------------------------
audit_output_path = SCRIPT_DIR / "ci_audit_trace_bundle1.json"
with open(audit_output_path, "w") as f:
    json.dump(audit_traces[0], f, indent=2, default=str)
print(f"\nAudit trace (Bundle 1) written to: {audit_output_path}")

# Write all traces for reference
all_traces_path = SCRIPT_DIR / "ci_audit_traces_all.json"
with open(all_traces_path, "w") as f:
    json.dump(audit_traces, f, indent=2, default=str)
print(f"All audit traces written to: {all_traces_path}")

sys.exit(0 if all_passed else 1)
