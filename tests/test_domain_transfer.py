"""Cross-domain transfer with native hard-safety rules (R7b).

Demonstrates the same governance engine instantiated across three domains
(offensive security, electric-utility switching, clinical infusion) where the two
constraints the reviewer flagged as inexpressible -- maintenance/treatment
*time windows* and *prerequisite gating* -- are now enforced as NATIVE rule
types (TIME_WINDOW, PREREQUISITE), not via confidence heuristics. Generalizability
becomes evidence across multiple domains rather than a single illustration.
"""
from __future__ import annotations

from lattice.policy_engine import evaluate


def _scores(v=0.95):
    return {k: v for k in ("objective_clarity", "tool_specificity", "constraint_completeness",
                           "risk_assessment_depth", "precedent_availability", "composite")}


# --- Domain policies (native TIME_WINDOW + PREREQUISITE + confidence cap) ---

ELECTRIC = {
    "policy_id": "CI_ELECTRIC", "version": "2.0", "domain": "electric_utility_switching",
    "allowed_targets": ["SUB-47-BKR-001"],
    "permitted_tools": {"DEFAULT": ["open_breaker"], "OTHER": ["open_breaker"]},
    "thresholds": {"autonomous": 0.95, "hitl": 0.75, "escalate": 0.50},
    "rules": [
        {"type": "TARGET_ALLOWLIST", "effect": "BLOCK", "values": ["SUB-47-BKR-001"], "reason_code": "OUT_OF_WORK_ORDER"},
        {"type": "TIME_WINDOW", "effect": "ESCALATE",
         "window": {"start": "2099-06-15T06:00:00Z", "end": "2099-06-15T18:00:00Z"}, "reason_code": "OUTSIDE_MAINT_WINDOW"},
        {"type": "PREREQUISITE", "effect": "BLOCK",
         "requires": ["upstream_isolation_verified", "work_permit_active"], "reason_code": "SWITCHING_PREREQ_MISSING"},
    ],
    "confidence_caps": {"irreversibility": {"irreversible": 0.70}},
}

CLINICAL = {
    "policy_id": "CLINICAL_INFUSION", "version": "1.0", "domain": "clinical_infusion",
    "allowed_targets": ["PATIENT-101:PUMP-A"],
    "permitted_tools": {"DEFAULT": ["adjust_infusion_rate"], "OTHER": ["adjust_infusion_rate"]},
    "thresholds": {"autonomous": 0.95, "hitl": 0.75, "escalate": 0.50},
    "rules": [
        {"type": "TARGET_ALLOWLIST", "effect": "BLOCK", "values": ["PATIENT-101:PUMP-A"], "reason_code": "WRONG_PATIENT_OR_DEVICE"},
        {"type": "TIME_WINDOW", "effect": "ESCALATE",
         "window": {"start": "2099-06-15T00:00:00Z", "end": "2099-06-15T23:59:59Z"}, "reason_code": "OUTSIDE_TREATMENT_WINDOW"},
        {"type": "PREREQUISITE", "effect": "BLOCK",
         "requires": ["second_clinician_signoff", "allergy_check_complete"], "reason_code": "CLINICAL_PREREQ_MISSING"},
    ],
    "confidence_caps": {"irreversibility": {"irreversible": 0.70}},
}


def _action(target, tool, tclass, when, prereqs, **kw):
    a = {"target": target, "tool": tool, "tool_class": tclass, "scope_tags": [],
         "time_bound": when, "parameters": {}, "confidence_scores": _scores(),
         "prerequisites_satisfied": prereqs}
    a.update(kw)
    return a


IN_WINDOW = "2099-06-15T08:00:00Z"
OUT_WINDOW = "2099-06-20T08:00:00Z"  # still a future (valid) deadline, but outside the window


# --- Electric utility ------------------------------------------------------

def test_electric_allow():
    a = _action("SUB-47-BKR-001", "open_breaker", "OTHER", IN_WINDOW,
                ["upstream_isolation_verified", "work_permit_active"])
    assert evaluate(a, ELECTRIC).verdict == "ALLOW"


def test_electric_outside_window_escalates():
    a = _action("SUB-47-BKR-001", "open_breaker", "OTHER", OUT_WINDOW,
                ["upstream_isolation_verified", "work_permit_active"])
    vr = evaluate(a, ELECTRIC)
    assert vr.verdict == "ESCALATE" and "OUTSIDE_MAINT_WINDOW" in vr.reason_codes


def test_electric_missing_prereq_blocks():
    a = _action("SUB-47-BKR-001", "open_breaker", "OTHER", IN_WINDOW, ["upstream_isolation_verified"])
    vr = evaluate(a, ELECTRIC)
    assert vr.verdict == "BLOCK" and "SWITCHING_PREREQ_MISSING" in vr.reason_codes


def test_electric_out_of_scope_blocks():
    a = _action("SUB-52-BKR-010", "open_breaker", "OTHER", IN_WINDOW,
                ["upstream_isolation_verified", "work_permit_active"])
    assert evaluate(a, ELECTRIC).verdict == "BLOCK"


def test_electric_irreversible_capped():
    a = _action("SUB-47-BKR-001", "open_breaker", "OTHER", IN_WINDOW,
                ["upstream_isolation_verified", "work_permit_active"], irreversibility_class="irreversible")
    assert evaluate(a, ELECTRIC).verdict != "ALLOW"


# --- Clinical --------------------------------------------------------------

def test_clinical_allow():
    a = _action("PATIENT-101:PUMP-A", "adjust_infusion_rate", "OTHER", IN_WINDOW,
                ["second_clinician_signoff", "allergy_check_complete"])
    assert evaluate(a, CLINICAL).verdict == "ALLOW"


def test_clinical_missing_signoff_blocks():
    a = _action("PATIENT-101:PUMP-A", "adjust_infusion_rate", "OTHER", IN_WINDOW, ["allergy_check_complete"])
    vr = evaluate(a, CLINICAL)
    assert vr.verdict == "BLOCK" and "CLINICAL_PREREQ_MISSING" in vr.reason_codes


def test_clinical_wrong_patient_blocks():
    a = _action("PATIENT-999:PUMP-Z", "adjust_infusion_rate", "OTHER", IN_WINDOW,
                ["second_clinician_signoff", "allergy_check_complete"])
    assert evaluate(a, CLINICAL).verdict == "BLOCK"
