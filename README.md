# LATTICE

**A Governance-First Architecture for Autonomous AI Agent Authorization**

LATTICE is an authorization and governance layer for autonomous AI agent systems. It enforces policy-as-code constraints, confidence-based verdict routing, TOCTOU-resistant execution gating, and cryptographic audit trails.

This repository contains the public reference governance pipeline described in the accompanying paper. It reproduces the architecture specification, JSON schemas, sample policy bundles, test vectors, and a reference governance pipeline sufficient to reimplement the architectural patterns. The proprietary AEGIS reference implementation (used for the empirical evaluation in the paper) is available upon reasonable request for verification purposes.

## Architecture

LATTICE sits between a Planning Agent and an Execution Agent, evaluating every proposed action bundle against a policy bundle before permitting execution. The governance pipeline produces exactly one of three verdicts for each action: ALLOW, BLOCK, or ESCALATE.

```
Planning Agent --> [Action Bundle] --> Governance Agent --> Execution Gate --> Tool
                                            |
                                      Policy Bundle
                                            |
                                       Audit Chain
```

## Components

- **Policy Engine** (`src/lattice/policy_engine.py`): Deterministic evaluation of action bundles against policy constraints. Supports five rule types: TARGET_DENYLIST, TOOL_DENYLIST, SCOPE_TAG_DENYLIST, TARGET_ALLOWLIST, TOOL_ALLOWLIST.
- **Execution Gate** (`src/lattice/execution_gate.py`): TOCTOU-safe enforcement with deep-copy isolation, SHA-256 hashing, and hash-chained audit records.
- **Audit Log** (`src/lattice/audit_log.py`): Append-only audit chain with ECDSA signatures, UUIDv7 record IDs, and hash-chain integrity.
- **Decision Tree Engine** (`src/lattice/decision_tree_engine.py`): Configurable decision tree for verdict routing.
- **Tripwire Framework** (`src/lattice/tripwire_framework.py`): Runtime anomaly detection predicates.
- **Multi-Cell Coordination** (`src/lattice/multi_cell.py`): Grid Cell coordination for Team and Squadron deployments.

## Schemas

JSON Schema (Draft 2020-12) definitions in `src/lattice/schemas/`:

- `action_bundle.schema.json` - Action bundle structure
- `policy_bundle.schema.json` - Policy bundle structure
- `audit_record.schema.json` - Audit record format
- `decision_tree.schema.json` - Decision tree configuration
- `evidence_record.schema.json` - Evidence record structure
- `signed_approved_bundle.schema.json` - Signed approved bundle
- `tripwire_predicate.schema.json` - Tripwire predicate definitions

## Quick Start

```bash
pip install -e ".[dev]"
pytest
```

### Run the demo

```bash
python examples/lattice_demo.py \
  --policy configs/policies/policy_bundle_minimal.json \
  --bundle examples/critical_infrastructure/ci_bundle_allow.json
```

## Examples

### Cybersecurity Operations (Paper Section 9)

The primary domain evaluated in the paper. Sample policy bundles are in `configs/policies/`.

### Critical Infrastructure (Paper Section 10.4)

A second-domain instantiation for electric utility scheduled switching operations. Located in `examples/critical_infrastructure/`:

- `ci_policy_bundle.json` - Policy bundle for substation SUB-47 operations
- `ci_bundle_allow.json` - Routine breaker opening (ALLOW verdict)
- `ci_bundle_escalate.json` - Irreversible relay modification (ESCALATE verdict)
- `ci_bundle_block.json` - Out-of-scope target (BLOCK verdict)
- `ci_audit_traces_all.json` - Full audit traces for all three test cases
- `test_ci_policy_bundle.py` - Executable test runner
- `ci_test_output.log` - Console output from test execution

## Tests

The test suite contains 25 modules covering policy evaluation, execution gate enforcement, confidence scoring, audit chain integrity, decision tree validation, tripwire predicates, and cryptographic primitives.

```bash
pytest tests/ -v
```

## Citation

If you use LATTICE in your research, please cite:

```bibtex
@article{calboreanu2026lattice,
  title={{LATTICE}: A Governance-First Architecture for Autonomous {AI} Agent Authorization},
  author={Calboreanu, Elias},
  journal={Frontiers in Artificial Intelligence},
  year={2026}
}
```

## License

Apache 2.0
