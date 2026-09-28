# DriftGuard 6.1

DriftGuard is a local, standard-library-first engineering reliability system for detecting environment drift, diagnosing failed builds, modeling structural failure paths, connecting **source-code changes to targeted validation**, and turning graph risk into a **deduplicated validation plan**.

## What v6 adds

- Bounded source-file fingerprints for Python, Node/TypeScript, C/C++, Rust, Go, .NET, Java/Kotlin, CUDA, Vulkan/shader, Unreal, and Unity source families.
- Logical source components such as `python/src` instead of treating every file as an isolated graph node.
- `impact` command showing modified, added, and removed source files since the known-good baseline.
- Source-component nodes in the failure graph.
- `validate-next` can recommend a narrow test/build because of the source area that changed.
- `validate-plan` builds an ordered, deduplicated sequence of high-value validations across risky components.
- The exported/local HTML report surfaces the validation plan alongside source-impact evidence.
- `validation-script` exports the same plan as a reviewable PowerShell or Bash script. Only a conservative allowlist of known-safe generated commands is emitted as executable; unsupported or suspicious commands remain `# MANUAL:` comments.
- `validate-run` is dry-run by default. With explicit `--execute`, it runs only allowlisted generated validations as direct argv (never through a shell), captures bounded stdout/stderr tails, and can append evidence to `.driftguard/validation_runs.jsonl` with `--save`.
- Safe upgrade behavior for v5 baselines: source tracking requests a known-good rebaseline instead of creating a false risk spike.
- Source edits remain distinct from environment drift; they only become graph risk when compared against the source-aware baseline.

## Quick start

```powershell
python -m pip install .
driftguard --root . init

# after editing code
driftguard --root . impact
driftguard --root . validate-next
driftguard --root . validate-plan --limit 5
driftguard --root . validation-script --shell powershell -o validate.ps1
driftguard --root . validation-script --shell bash -o validate.sh
driftguard --root . validate-run --limit 5          # dry-run only
driftguard --root . validate-run --limit 5 --execute --save

# execute the recommended/normal validation through DriftGuard
driftguard --root . guard --capture -- python -m unittest discover -s tests -v
```

Other useful commands:

```powershell
driftguard --root . check
driftguard --root . predict
driftguard --root . inventory
driftguard --root . subsystems
driftguard --root . native-scan
driftguard --root . graph --format dot -o driftguard.dot
driftguard --root . explain source-component:python/src
driftguard --root . serve --port 8765
```

## Verified development evidence

The v6 development branch passes 48 local automated tests. A Linux unfamiliar-repository campaign completed 10 known-good repositories, with harmless and deliberately breaking source edits exercising targeted validation. Clean wheel build/install and v5-baseline → v6-upgrade compatibility were also verified. Windows/second-OS validation remains pending. On the 10-repository Linux campaign, structured diagnosis added a 0.344 s median machine-time overhead after eliminating a duplicate project scan; this is not a human troubleshooting-time measurement. These are implementation checks, not proof that the risk score is calibrated to real-world failure probability.

When GitHub Actions cannot create runner jobs, validate a commit-specific GitHub source ZIP locally with:

```powershell
python validation/validate_source_tree.py --expected-commit <full-commit-sha> --json-out validation-result.json
```

This checks archive identity, forced compilation, the unit/regression suite, wheel build, fresh virtual-environment install, import, and CLI startup without treating Actions as evidence.

See `VALIDATION.md` for the remaining product-validation gates.

## Safety

DriftGuard diagnoses before mutating. It does not automatically install, upgrade, downgrade, delete, or rewrite SDKs or dependencies. Risk outputs are inspectable engineering hypotheses and should be confirmed with the recommended validation.
