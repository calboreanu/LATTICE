# Roadmap

## Completed (v1.0.0) — Paper v1 Reference Release

- [x] JSON Schemas (action bundle, policy bundle, audit record, evidence record, decision tree, tripwire, signed approved bundle)
- [x] Deterministic policy evaluation engine (5 rule types)
- [x] TOCTOU-resistant execution gate + append-only audit log + RFC 8785 canonicalization/hashing
- [x] Sample policy bundles + test vectors (including TOCTOU tamper cases)
- [x] Runnable reference pipeline (`examples/run_demo`)
- [x] Zenodo archival release (DOI 10.5281/zenodo.18419923)

## Completed (v1.1.0) — Major-Revision Builds + AEGIS Integration

Reviewer-driven hardening for the Frontiers Major Revision (manuscript 1800407). Reviewer concern IDs in brackets.

- [x] Native hard-safety rule types `TIME_WINDOW` + `PREREQUISITE` (7 rule types total) — [R7a]
- [x] Policy-derived confidence cap `c_eff = min(c_p, c_cap)` from governance-observable features — [R6/D1]
- [x] Confidence-miscalibration evaluation (honest / inflated / under-reporting planners) — [R6]
- [x] Gate-reachability invariant (`governed_execution`) — tools reachable only past an ALLOW — [R3]
- [x] Coordination security: mutual auth, replay/stale rejection, quorum, anti-flood, no verdict-forwarding — [R4]
- [x] OWASP per-risk coverage matrix (9 tested / 1 partial) — [R5]
- [x] Dual-use safeguards: authorization/revocation records, policy linter, key rotation/revocation — [R8]
- [x] Cross-domain examples: electric-utility + clinical (3 domains) — [R7b]
- [x] Fail-closed hardening of malformed-policy handling (found by the adversarial driver)
- [x] Tier-1 reproducibility drivers + `REPRODUCE.md` (determinism 130k/0; sweep 3,003; adversarial 0/21 @ 13.3%)
- [x] AEGIS stack integration via `aegis.stack.lattice_bridge` (MANDATE → LATTICE → TRACE); 1,029 cross-stack tests
- [x] 367 tests passing; engine byte-identical to the AEGIS copy

## Next Steps

- [ ] **Tier-2 latency** measurement on the AEGIS host (consistent boundaries + hardware/env) — *AEGIS station*
- [ ] Production-ready figures + supplementary compile
- [ ] Reconcile the two engines (`run_demo` → canonical `src/lattice`, or relabel `lattice_ref`)
- [ ] Wire the HMAC reference (`key_management` / `authorization` / `coordination_security`) to ECDSA P-256 in AEGIS
- [ ] Statistical audit-sampling safeguard (proposed) — implement + evaluate
