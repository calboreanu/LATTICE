# Reproducing LATTICE's Evidence

Every **Tier-1** claim below is reproducible from this public repository on commodity hardware in seconds — no proprietary components. This is the paper's "verify, don't trust" thesis made literal: you can re-derive the core results yourself, now.

## One command

```bash
pip install -r requirements.txt
PYTHONPATH=src python evidence/reproduce_all.py
```

Expected output (deterministic):

```
determinism      : 130,000 evaluations, 0 verdict deviations
threshold sweep  : 3,003 points; team = {'ALLOW': 15.1, 'ESCALATE': 40.0, 'BLOCK': 45.0}
adversarial      : 0/21 bypassed; 95% upper bound = 13.3%
confidence cap   : high-consequence autonomous ALLOW 0.571 -> 0.0
```

## Evidence tiers

The paper's empirical claims are tiered by how they can be verified. **No claim exceeds its tier.**

| Claim | Tier | Reproduce with |
|---|---|---|
| Determinism — 130,000 evals, zero verdict variance | **1 — open / public** | `evidence/determinism.py` |
| Threshold sweep — 3,003 points; Team 15.1/40.0/45.0%; sharp transitions at θ | **1 — open / public** | `evidence/threshold_sweep.py` |
| Adversarial — 0/21 bypassed; Clopper–Pearson 95% upper bound 13.3% | **1 — open / public** | `evidence/adversarial_suite.py` |
| Confidence cap — high-consequence autonomous ALLOW 57–71% → 0%, benign unchanged | **1 — open / public** | `evidence/miscalibration_eval.py` |
| OWASP agentic coverage — 9 tested / 1 partial (not "all ten") | **1 — open / public** | `pytest tests/test_owasp_matrix.py`; `evidence/owasp_matrix.json` |
| Cross-domain transfer — security + electric + clinical | **1 — open / public** | `pytest tests/test_domain_transfer.py`; `evidence/domain_matrix.json` |
| Non-bypassability, audit-chain, coordination security, dual-use mechanisms | **1 — open / public** | `pytest tests/` (367 passed, 3 skipped) |
| Latency — p50 policy-eval / full-gate / cryptographic ops | **2 — AEGIS host** | Measured on the AEGIS reference host (hardware/environment disclosed). Implementation-specific; **not** community-reproducible. |

Statistical claims are reported exactly: 0/21 means "no bypass observed in the evaluated suite" (upper bound 13.3%), never "robust prevention"; the OWASP table is a conceptual mapping with a tested subset, never "coverage for all ten."

## Full test suite

```bash
PYTHONPATH=src python -m pytest tests/ \
  --ignore=tests/lattice/test_planning_agent.py \
  --ignore=tests/lattice/test_training_data_infrastructure.py \
  --basetemp=/tmp/lattice-pytest -q
# 367 passed, 3 skipped
```

## What is and isn't here

The governance engine in `src/lattice/` (policy evaluation, the execution gate, the confidence model, the audit chain) is the same engine used by the proprietary AEGIS reference implementation. AEGIS additionally provides an LLM planning agent, domain tooling, and the MANDATE/TRACE integration; only the **latency** figures and the end-to-end integration scenario depend on it.
