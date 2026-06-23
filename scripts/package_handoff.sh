#!/usr/bin/env bash
# Package the LATTICE reference for handoff to the AEGIS station.
# Mirrors the lab pattern (cf. AEGIS/scripts/package_ws01_handoff.sh).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DEFAULT_OUT="$(cd "${REPO_ROOT}/.." && pwd)/LATTICE_handoff_${TIMESTAMP}.zip"
OUT_PATH="${1:-${DEFAULT_OUT}}"

echo "Repo root:  ${REPO_ROOT}"
echo "Output zip: ${OUT_PATH}"
cd "${REPO_ROOT}"

zip -r "${OUT_PATH}" . \
  -x ".git/*" \
  -x ".venv/*" \
  -x ".pytest_cache/*" \
  -x "**/__pycache__/*" \
  -x "*.pyc" \
  -x "*.pyo" \
  -x "*.DS_Store" \
  -x "pytest-cache-files-*/**" \
  -x ".audit/*"

echo "Created handoff archive:"
ls -lh "${OUT_PATH}"
echo
echo "Verify before handoff:"
echo "  PYTHONPATH=src python -m pytest tests/ --ignore=tests/lattice/test_planning_agent.py --ignore=tests/lattice/test_training_data_infrastructure.py --basetemp=/tmp/lp -q"
echo "  PYTHONPATH=src python evidence/reproduce_all.py"
