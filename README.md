# LATTICE (v1) — Governance-First Reference Pipeline (Python)

This repository provides a **safe, non-offensive, runnable reference pipeline** aligned to the LATTICE paper.
It demonstrates the core **governance gate** pattern:

**canonicalize → hash → evaluate(policy) → record(audit) → gate-check → sandboxed execute (stub)**

- **Zenodo archival DOI:** 10.5281/zenodo.18419923
- **Repository:** https://github.com/calboreanu/LATTICE
- **Release:** v1.0.0

> Note: This repo is a *toy/reference* implementation for reproducibility. It is **not** the proprietary AEGIS system.

## Quickstart
```bash
python -m examples.run_demo --policy policies/policy_bundle_v5.2.json --bundle test_vectors/action_bundles/ab_allow.json
python -m examples.run_demo --policy policies/policy_bundle_v5.2.json --bundle test_vectors/action_bundles/ab_block.json
python -m examples.run_demo --policy policies/policy_bundle_v5.2.json --bundle test_vectors/tamper_cases/ab_tampered.json
```

Artifacts written:
- `.audit/audit_log.jsonl` (append-only)
- `.audit/evidence.jsonl` (optional stub evidence)

## Repo layout
- `spec/` — paper-aligned architecture, terminology, and formal properties
- `schemas/` — JSON Schemas for bundles, policies, and records
- `policies/` — example version-pinned policy bundles
- `test_vectors/` — action bundles + TOCTOU tamper cases + expected verdicts
- `lattice_ref/` — Python reference implementation
- `examples/` — runnable demo

## Safety / Scope
The “execution” step is a **stub** that simulates actions and writes records. No exploit tooling is included.

## Citation
Please cite using the Zenodo DOI: **10.5281/zenodo.18419923** (see `CITATION.cff`).
