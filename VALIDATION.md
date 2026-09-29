# DriftGuard product-validation gates

DriftGuard's local engineering behavior is tested, but that is not the same as proving that its risk ranking predicts real-world build failures. The next release-validation cycle should keep those claims separate.

## Gate 1 — clean installation

Verify source install and wheel install in fresh environments on Windows and Linux across supported Python versions. Acceptance evidence should include CLI startup, `init`, `check`, `impact`, `validate-next`, `validate-plan`, `graph`, and one `guard --capture` execution.

## Gate 2 — unfamiliar-repository evaluation

Evaluate at least 10 repositories not used to design the signatures or tests. Include a mix of Python, Node, C/C++, .NET, Rust/Go, and at least one engine/GPU-oriented project when practical.

For each repository record the known-good baseline, controlled dependency/toolchain/source changes, DriftGuard findings, recommended validation, actual build/test result, false alarms, missed failures, and diagnosis time with/without DriftGuard.

Do not convert this evidence into a probability claim unless the dataset and calibration methodology support one.

## Gate 3 — source-impact precision

For controlled edits, verify that `impact` identifies the correct logical source component and that `validate-next` selects a useful narrow validation. Measure changed-file detection, component assignment, validation relevance, and cases where repository-specific commands cannot be inferred safely.

## Gate 4 — guard semantics

Confirm documented exit behavior in CI and shell scripts. `check` is diagnostic; automation that must block risky execution should use the documented guard/policy behavior rather than assuming every non-stable diagnostic returns a blocking exit code.

## Gate 5 — release hygiene

Before a tagged release, run the full suite, build from a clean tree, install into a fresh virtual environment, verify no cache/egg-info/build/local DriftGuard state is packaged, produce checksums, and review README claims against observed evidence.

## Current evidence

The pinned v6.0.0 RC1 anchor is `release/v6-rc1` at `b12e67bb209bd2ae16d8b1b1af1bd5a67533f4e4`; that exact candidate has 48 passing automated tests. The Linux unfamiliar-repository campaign completed 10 known-good repositories: harmless source edits passed the selected validations and deliberate breaking edits failed them, with source-failure classification added from campaign findings. A clean wheel install and v5-baseline → v6-upgrade compatibility check also passed locally. A 30-pair Linux machine-time benchmark measured 0.344 s median structured-diagnosis overhead after removing a duplicate guard scan; classification remained correct in all 30 pairs. Guard semantics were exercised on Linux: no-baseline=2, policy block=3 without execution, command failures propagate their exit code, missing command=127, and `check` remains diagnostic. The current source ZIP and wheel also pass Linux release-hygiene checks plus v5→v6 rebaseline compatibility. Windows/second-OS evidence and a timed human diagnosis comparison remain open.


## Development beyond RC1

The active development branch is now 6.1.0 and adds `validate-plan`, report/dashboard validation-plan output, and a reusable `validation/validate_source_tree.py` harness for exact-source validation. It currently defines 65 automated tests. GitHub Actions remains excluded while runs end in `startup_failure` before jobs are created.


## Portable plan export

The 6.1 development branch can export a generated validation plan with `validation-script --shell powershell|bash`. Export is intentionally conservative: fixed known commands and bounded Python/Node source checks become executable script lines; descriptive engine/manual validations and strings containing shell-control metacharacters remain comments. This reduces copy/paste ambiguity without turning arbitrary repository text into shell execution.


## Opt-in validation execution

The 6.1 branch adds `validate-run`. It is a dry-run unless `--execute` is supplied. Execution accepts only DriftGuard-owned validation patterns that can be converted to a direct argv list; it does not invoke a shell. Unsupported/descriptive steps remain manual. Results include duration, exit code, bounded output tails, completion state, and can be persisted to `.driftguard/validation_runs.jsonl` with `--save`. This feature still requires exact-source validation before it counts as release evidence.


## Expanded exact-source and Windows gates

The source-ZIP harness now exercises the installed 6.1 wheel against a temporary Python fixture: baseline, harmless source change, `validate-plan`, platform-appropriate `validation-script`, dry-run `validate-run`, successful explicit execution with saved evidence, then a deliberate syntax break whose `validate-run` must fail with exit 1. The native Windows harness mirrors the 6.1 plan/export/execute checks and accepts an explicit expected commit value instead of embedding a stale source SHA.

## 6.1 local development check — 2026-09-29

On Linux with Python 3.12.14, the updated development tree passed **65/65** unit/regression tests, built a wheel, installed it into a fresh offline virtual environment, and passed 14 validation harness steps. The harness now checks the JSON plan, dry-run behavior, pass/fail results, and saved JSONL evidence rather than trusting exit codes alone. `python examples/showcase.py` also passed its disposable harmless-edit and syntax-break sequence.

The exact committed-tree check is recorded in [`validation/RELEASE_GATE_6_1_2026-09-29.md`](validation/RELEASE_GATE_6_1_2026-09-29.md) and its sanitized JSON summary. All 23 tracked files matched the Git blob hashes at `e7a701f9186d6913a75775cd721192100963a69b`; 65 tests, 14 harness steps, and the disposable showcase passed from the clean reconstruction. This is Linux/Python 3.12 evidence, not a Windows or CI pass. Native Windows execution, timed human diagnosis, and Actions remain open.
