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

## Property 5 (Confidence-Cap Monotonicity) — v1.1
The governance-derived confidence cap never increases autonomy: for effective confidence
c_eff = min(c_p, c_cap) where c_cap is computed from governance-observable features
(irreversibility, tool privilege, novelty, cross-cell scope, contingency artifacts), c_eff ≤ c_p
always. When the cap binds, a CONFIDENCE_CAP_APPLIED reason is recorded, which removes the action
from autonomous ALLOW (autonomous ALLOW requires an empty reason set). Absent a policy
`confidence_caps` block, c_cap = 1 and behavior is unchanged.

## Property 6 (Gate Reachability) — v1.1
Within the trusted core, tool execution is reachable only through the governance gate: the tool
primitive (`sandbox_execute`) is invoked solely by `governed_execute`, and only after the gate
returns ALLOW. No other call site to the tool primitive exists in the core (statically checked).

## Property 7 (Coordination Integrity) — v1.1
In multi-cell deployments, no coordination message constitutes an authorization token: a cell never
executes a tool on another cell's verdict. Inter-cell messages are mutually authenticated and
monotonically sequenced (spoofed/tampered/replayed/stale messages are rejected); critical shared
state requires quorum corroboration; escalations are deduplicated and rate-limited. Coordination
compromise can therefore produce correlated misdirection but not direct bypass of per-cell
authorization.
