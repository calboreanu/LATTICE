# Overview

LATTICE is a governance-first architecture for authorized autonomous AI operations. It reframes authorization from "do we trust this AI?" to "do we trust this architecture?" — answerable through engineering validation rather than assumptions about model behavior.

## Core Concepts

- **1+3 Grid Cell** — one Governance Agent supervising Planning, Execution, and Coordination agents; no component both decides and judges.
- **Policy-as-code** — deterministic verdicts (`ALLOW` / `BLOCK` / `ESCALATE`) over action bundles, via 7 native rule types.
- **Execution gate** — non-bypassable *within the trusted core*: tools are reachable only past an `ALLOW` (checked invariant).
- **Confidence model** — oversight calibrated to risk; a policy-derived cap bounds planner overconfidence on high-consequence actions.
- **Cryptographic audit chain** — tamper-evident decision provenance (SHA-256 + ECDSA), with authorization/revocation records.

## This Repository Provides

- The governance engine (policy evaluation, execution gate, confidence model + cap, audit chain) — **identical to the engine used by AEGIS**.
- The 7 native rule types, including `TIME_WINDOW` and `PREREQUISITE`.
- Coordination security, authorization/revocation, a policy linter, and key management.
- JSON schemas, sample policies, test vectors (incl. native-rule vectors), and cross-domain examples (security, electric-utility, clinical).
- Reproducible evidence drivers — see `REPRODUCE.md`.

## Integration (the main system)

LATTICE joins the AEGIS stack via `aegis.stack.lattice_bridge.LatticeBridge`, composed by the `AegisStackBridge` façade for the MANDATE → LATTICE → TRACE handoff. Orchestration is kept thin; bundle synthesis and full governance workflows remain upstream application responsibilities.

## Paper Reference

See the LATTICE paper (Frontiers in Artificial Intelligence, manuscript 1800407) for the full framework, formal properties (`spec/formal_properties.md`), and architecture.
