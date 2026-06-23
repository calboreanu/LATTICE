# Contributing

Thanks for contributing to LATTICE.

## Ways to contribute
- File issues for schema/engine edge cases or paper-repo mismatches
- Add policy bundles, action-bundle test vectors, and adversarial vectors
- Extend rule types or confidence-cap features
- Improve the audit/crypto, coordination-security, or policy-linting tooling

## Development setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python -m pytest tests/ --basetemp=/tmp/lattice-pytest
```

## Pull request guidelines
- Add/adjust tests for any behavior change; **fail closed** where behavior is ambiguous.
- Keep schemas backward compatible when possible (or bump `version`).
- Document changes in `CHANGELOG.md` and `docs/roadmap.md`.
- The engine in `src/lattice/` is mirrored into the AEGIS monorepo; keep the two byte-identical.
