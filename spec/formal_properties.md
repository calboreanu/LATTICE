# Formal Properties (Reference)

Domains:
- ActionBundles, PolicyBundles, ExecutedActions, AuditRecords, Verdicts = {ALLOW, BLOCK, ESCALATE}

Assumptions (reference):
- A1: Cryptographic hash (SHA-256) is collision-resistant for practical purposes
- A2: Canonicalization is deterministic
- A3: Audit log is append-only (tamper-evident via hash-linking)
- A4: Policy bundle is version-pinned
- A5: Gate revalidates hash match at execution time

## Property 1 (Determinism)
For a fixed policy bundle P and action bundle AB, evaluate(hash(AB), P) returns a unique verdict.

## Property 2 (Traceability) — typed to AuditRecords
∀E ∈ ExecutedActions: ∃C ⊆ AuditRecords such that
- hash_linked(C) ∧ (∃r_v ∈ C: r_v.verdict = ALLOW) ∧ ∀r ∈ C: signature_valid(r)

## Property 3 (Invariance)
Execution depends only on the canonical action-bundle hash and the pinned policy bundle, not on agent narrative content.

## Property 4 (Completeness)
Every proposed action yields a recorded verdict (ALLOW/BLOCK/ESCALATE) and associated evidence hooks.
