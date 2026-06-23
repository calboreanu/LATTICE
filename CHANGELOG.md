# Changelog

## v1.1.0 — 2026-05-31
Revision builds answering the Frontiers peer review (manuscript 1800407).

### Added
- **Native hard-safety rule types** `TIME_WINDOW` and `PREREQUISITE` in `policy_engine` (7 rule types total) — maintenance/treatment windows and prerequisite gating are now enforced as native, deterministic rules rather than via confidence heuristics.
- **Policy-derived confidence cap** `c_eff = min(c_p, c_cap)` from governance-observable features (irreversibility, tool privilege, novelty, cross-cell scope, contingency artifacts). Backward compatible: no `confidence_caps` block ⇒ unchanged behavior.
- **`governed_execution.governed_execute`** — sole sanctioned path from objective to tool execution, with a reachability-invariant test proving tools are reachable only past an ALLOW verdict.
- **`coordination_security`** — mutual authentication, replay/stale rejection, shared-state quorum, escalation rate-limiting, fan-out detection, and a no-verdict-forwarding invariant for Team/Squadron coordination.
- **`authorization`** (authorization provenance + revocation), **`policy_linter`** (over-broad-scope / wildcard / permissive-threshold detection), **`key_management`** (versioned keys with rotation + revocation).
- **Cross-domain examples**: a clinical-infusion policy bundle alongside the electric-utility one (same engine, three domains).
- **`evidence/`**: deterministic OWASP coverage matrix, cross-domain matrix, and a confidence-miscalibration evaluation.

### Fixed
- `requirements.txt` now lists real dependencies (`rfc8785`, `jsonschema`); package `__all__` no longer references AEGIS-only modules and exports the new ones.

## v1.0.0 — 2026-01-29
- Initial public release of the LATTICE *reference* (toy) pipeline.
- Includes JSON Schemas for Action Bundles, Policy Bundles, Audit Records, and Evidence Records.
- Includes a deterministic policy evaluator, canonicalization + hashing, append-only audit log, and execution gate.
- Includes sample policy bundles and test vectors (including TOCTOU tamper cases).
