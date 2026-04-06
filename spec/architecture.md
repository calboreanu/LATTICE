# Architecture (Paper-aligned)

## 1+3 Grid Cell Pattern
A **Grid Cell** is the repeatable unit of governed autonomy consisting of:
- **LLM Orchestrator** (coordination / cognitive control)
- **Planning Agent** (goal decomposition, planning)
- **Execution Agent** (sandboxed tool invocation)
- **Governance Agent** (deterministic policy enforcement)

### Separation of concerns
- Reasoning is flexible (LLM-assisted) but **not** trusted for enforcement.
- Enforcement is **deterministic**, **non-bypassable**, and evidence-capturing.

## Governance Gate
The gate enforces a TOCTOU-resistant sequence:
1) Canonicalize the action bundle
2) Hash the canonical form
3) Evaluate the hash under a version-pinned policy bundle
4) Record the verdict in an append-only audit log (pre-commit)
5) Re-hash and compare at the gate
6) Execute only if ALLOW and hash matches
