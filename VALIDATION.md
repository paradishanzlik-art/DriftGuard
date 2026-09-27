# DriftGuard product-validation gates

DriftGuard's local engineering behavior is tested, but that is not the same as proving that its risk ranking predicts real-world build failures. The next release-validation cycle should keep those claims separate.

## Gate 1 — clean installation

Verify source install and wheel install in fresh environments on Windows and Linux across supported Python versions. Acceptance evidence should include CLI startup, `init`, `check`, `impact`, `validate-next`, `graph`, and one `guard --capture` execution.

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

v6 currently has 47 passing local automated tests. The Linux unfamiliar-repository campaign completed 10 known-good repositories: harmless source edits passed the selected validations and deliberate breaking edits failed them, with source-failure classification added from campaign findings. A clean wheel install and v5-baseline → v6-upgrade compatibility check also passed locally. Windows/second-OS evidence and controlled diagnosis-time comparison remain open.
