# LATTICE v1.1.0 — Results Ledger

Verification record for the revision builds (manuscript 1800407). All results are
deterministic and reproducible on the public repository.

## Test verification (2026-05-31)

| Suite | Result |
|---|---|
| Full public-runnable suite (`pytest tests/`, 2 AEGIS-coupled tests excluded) | **367 passed, 3 skipped** |
| New tests added this revision | **67** |
| Exported package modules import cleanly | 16 / 16 |
| Core files identical `LATTICE` ↔ `AEGIS/src/lattice` | 7 / 7 (+ schema) |
| AEGIS cross-stack integration (LATTICE↔MANDATE↔TRACE + stack bridges + cross-layer) | **1029 passed, 1 skipped** |
| Standalone MANDATE suite | **429 passed** |
| Standalone TRACE suite | **8 passed** |

Reproduce:
```bash
pip install -r requirements.txt
PYTHONPATH=src python -m pytest tests/ \
  --ignore=tests/lattice/test_planning_agent.py \
  --ignore=tests/lattice/test_training_data_infrastructure.py \
  --basetemp=/tmp/lattice-pytest -q
```

## Reviewer concern → evidence

| Concern | Mechanism | Evidence | Result |
|---|---|---|---|
| R3 non-bypassability | `governed_execution` + reachability invariant | `tests/test_gate_reachability_invariant.py` | tools reachable only past ALLOW; no other call site |
| R4 coordination security | `coordination_security` | `tests/test_coordination_security.py` (12) | 4 named attacks defeated |
| R5 OWASP coverage | per-risk test matrix | `evidence/owasp_matrix.json` | 9 tested / 1 partial (honest) |
| R6 miscalibration | confidence cap + eval | `evidence/miscalibration_eval.json` | high-consequence autonomous ALLOW 57–71% → **0%**; benign unchanged; divergence-only catch 42.9% |
| R7a rule expressivity | `TIME_WINDOW` + `PREREQUISITE` | `tests/test_policy_engine_time_prereq.py` | hard-safety enforced natively |
| R7b generalizability | 3-domain transfer | `evidence/domain_matrix.json` | 8/8 verdicts across security + electric + clinical |
| R8 dual-use | authz/revocation, linter, key rotation | `tests/test_r8_mechanisms.py` (11) | provenance, revocation, scope-linting, rotation validated |

## Confidence-cap headline numbers (`miscalibration_eval.json`)

| Planner model | high-consequence ALLOW, cap OFF | cap ON | low-consequence ALLOW (OFF / ON) |
|---|---|---|---|
| honest | 0.571 | **0.000** | 0.571 / 0.571 |
| inflated_within_tolerance | 0.714 | **0.000** | 0.714 / 0.714 |
| inflated_beyond_tolerance | 0.571 | **0.000** | 0.571 / 0.571 |
| under_report | 0.000 | 0.000 | 0.000 / 0.000 |

Divergence-only catch rate on beyond-tolerance inflation: **0.429** (clipping at high confidence limits the divergence check → the cap is the necessary complement).

## Tier-1 reproduction (one command)

`pip install -r requirements.txt && PYTHONPATH=src python evidence/reproduce_all.py` regenerates, on the open engine, numbers matching the paper:

| Claim | Reproduced | Driver |
|---|---|---|
| Determinism | 130,000 evaluations, **0** verdict deviations | `evidence/determinism.py` |
| Threshold sweep | 3,003 points; Team **15.1 / 40.0 / 45.0%**; sharp transitions at θ | `evidence/threshold_sweep.py` |
| Adversarial | **0/21** bypassed; Clopper–Pearson 95% upper bound **13.3%** | `evidence/adversarial_suite.py` |
| Confidence cap | high-consequence autonomous ALLOW **0.571 → 0.000** | `evidence/miscalibration_eval.py` |

Tier-2 (latency) is AEGIS-host-measured and intentionally **not** reproduced here. See `REPRODUCE.md` for the full tier map.

**Engine hardening (found by the adversarial driver):** a malformed (non-list) policy `rules` field previously **failed open** (rules silently skipped → ALLOW); now fails closed (`POLICY_RULES_INVALID` → BLOCK), with a regression test. This is the kind of defect the Tier-1 drivers exist to surface.
