# DriftGuard 5

DriftGuard is a local, standard-library-first engineering reliability system for detecting environment drift, diagnosing failed builds, and ranking likely failure nodes in a structural dependency graph.

The `main` branch preserves the verified v5.0.0 baseline before the next development increment.

## Verified baseline

- Version 5.0.0
- 36 unit/regression tests passed in an independent local rerun
- Fresh wheel installation and CLI entry point verified
- Controlled dependency-drift exercise verified
- Python standard-library-only runtime

## Core workflow

```powershell
python -m pip install .
driftguard --root . init
driftguard --root . check
driftguard --root . validate-next
driftguard --root . guard --capture -- python -m unittest discover -s tests -v
```

DriftGuard diagnoses before mutating. It does not automatically install, upgrade, downgrade, delete, or rewrite SDKs or dependencies.
