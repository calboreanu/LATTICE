# LATTICE — Governance-First Reference Pipeline (Python)

This repository provides a **safe, non-offensive, runnable reference pipeline** aligned to the LATTICE paper.
It demonstrates the core **governance gate** pattern:

**canonicalize → hash → evaluate(policy) → record(audit) → gate-check → sandboxed execute (stub)**

- **Zenodo archival DOI:** 10.5281/zenodo.18419923
- **Repository:** https://github.com/calboreanu/LATTICE
- **Release:** v1.1.0

> Note: This repo is a *reference* implementation for reproducibility. It is **not** the proprietary AEGIS system.
> The governance core (`policy_engine`, execution gate, confidence model, audit chain) is the same code AEGIS uses;
> AEGIS adds a proprietary LLM planning agent, domain tooling, and the MANDATE/TRACE integration.
>
> **Canonical engine:** `src/lattice/` is the canonical, fully-tested governance engine (used by the test suite and the paper). `lattice_ref/` is a minimal, self-contained engine used only by the `run_demo` quickstart and does **not** include the v1.1 rule types or confidence cap.

## Install
```bash
pip install -r requirements.txt   # rfc8785, jsonschema>=4.18, pytest
```

## Quickstart
```bash
python -m examples.run_demo --policy policies/policy_bundle_v5.2.json --bundle test_vectors/action_bundles/ab_allow.json
python -m examples.run_demo --policy policies/policy_bundle_v5.2.json --bundle test_vectors/action_bundles/ab_block.json
python -m examples.run_demo --policy policies/policy_bundle_v5.2.json --bundle test_vectors/tamper_cases/ab_tampered.json
```

Artifacts written: `.audit/audit_log.jsonl` (append-only), `.audit/evidence.jsonl` (optional stub evidence).

## Capabilities (v1.1)

- **Policy-as-code evaluation** with **7 native rule types**: `TARGET_DENYLIST` / `TARGET_ALLOWLIST`,
  `TOOL_DENYLIST` / `TOOL_ALLOWLIST`, `SCOPE_TAG_DENYLIST`, and the hard-safety types **`TIME_WINDOW`**
  (maintenance/treatment-window enforcement) and **`PREREQUISITE`** (prerequisite gating).
- **Policy-derived confidence cap** — `c_eff = min(c_p, c_cap)` from governance-observable features
  (irreversibility, tool privilege, novelty, cross-cell scope, contingency artifacts). A miscalibrated or
  overconfident planner cannot self-authorize a high-consequence action. Backward compatible (opt-in via a
  policy `confidence_caps` block).
- **Gated execution** (`governed_execution.governed_execute`) — the only sanctioned path from objective to tool
  execution; an invariant test proves no other path reaches the tool.
- **Coordination security** (`coordination_security`) — mutual auth, replay/stale rejection, shared-state quorum,
  escalation rate-limiting, fan-out detection, and a no-verdict-forwarding invariant for multi-cell deployments.
- **Dual-use safeguards** — authorization provenance + revocation (`authorization`), a policy linter
  (`policy_linter`), and versioned key rotation/revocation (`key_management`).
- **Cross-domain examples** — offensive-security, electric-utility switching, and clinical infusion run on the
  same engine (`examples/`, `tests/test_domain_transfer.py`).

## Tests & reproducible evidence

```bash
# Full public-runnable suite (367 passed, 3 skipped as of v1.1.0).
# Two tests under tests/lattice/ couple to the proprietary AEGIS planner and are excluded here.
PYTHONPATH=src python -m pytest tests/ \
  --ignore=tests/lattice/test_planning_agent.py \
  --ignore=tests/lattice/test_training_data_infrastructure.py \
  --basetemp=/tmp/lattice-pytest -q
```
> Tip: pass `--basetemp` to a path **outside** the repo to avoid temp-dir cleanup issues on some mounts.

Deterministic evidence (regenerable, no RNG):
```bash
PYTHONPATH=src python evidence/miscalibration_eval.py   # writes evidence/miscalibration_eval.json
```
- `evidence/owasp_matrix.json` — OWASP Top-10-for-Agentic per-risk coverage (tested vs conceptual)
- `evidence/domain_matrix.json` — cross-domain verdict matrix (3 domains)
- `evidence/miscalibration_eval.json` — confidence-cap effect under miscalibrated planners

## Repo layout
- `spec/` — paper-aligned architecture, terminology, formal properties
- `schemas/` — JSON Schemas for bundles, policies, and records
- `policies/` — example version-pinned policy bundles
- `test_vectors/` — action bundles + TOCTOU tamper cases + expected verdicts
- `src/lattice/` — Python reference implementation
- `examples/` — runnable demo + critical-infrastructure and clinical policy bundles
- `evidence/` — deterministic evaluation outputs
- `tests/` — unit + adversarial test suites

## Safety / Scope
The “execution” step is a **stub** that simulates actions and writes records. No exploit tooling is included.

## Citation
Please cite using the Zenodo DOI: **10.5281/zenodo.18419923** (see `CITATION.cff`).
