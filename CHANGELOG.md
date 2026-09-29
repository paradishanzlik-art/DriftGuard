# Changelog

## 6.1.0

- Fixed a missing test import found by running the exact development source; the full suite now executes.
- Escaped project-derived labels in exported Bash/PowerShell scripts and restricted generated file checks to paths inside the target project.
- Added regression tests for script-label injection and path traversal/option confusion.
- Added a disposable end-to-end showcase and a public preview guide with measured claims and release gates.
- Strengthened the installed-wheel validation harness to check JSON outcomes and saved pass/fail evidence, not just process exit codes.
- Marked manual-only or otherwise incomplete explicit validation runs as incomplete instead of passed; the CLI returns 4 when manual work remains.
- Kept generated script output compatible with Python 3.9 by using `Path.open(newline=...)`.
- Recorded 65-test, 14-step committed-source Linux validation for `e7a701f` with a sanitized public evidence summary.
- Added `validate-plan` to build a bounded sequence of targeted validations from graph risk.
- Deduplicates equivalent validation commands while retaining the risky nodes each step covers.
- Orders validation steps by risk, direct evidence, and blast radius so high-value checks run first.
- Added JSON output with plan coverage and changed-source component context.
- Added five regression tests for command deduplication, ordering/limits, safe fallback, CLI parsing, and case-sensitive command preservation.
- Added validation-plan data to reports and the local/exported HTML dashboard.
- Added a cross-platform source-tree validator for the commit-specific GitHub source-ZIP validation workaround.
- Added `validation-script` for portable PowerShell/Bash validation scripts derived from `validate-plan`.
- Script export uses conservative command allowlisting; ambiguous/descriptive validations are rendered as manual comments instead of executable shell text.
- Added four exporter regression tests.
- Added opt-in `validate-run`: dry-run by default, explicit `--execute` for allowlisted validations, direct argv execution without a shell, bounded output capture, timeout handling, stop/continue policy, and optional JSONL evidence persistence.
- Added five validation-run regression tests, bringing the branch to 62 defined tests.
- Extended the exact-source validator to verify v6.1 from a fresh installed wheel using a temporary fixture, including plan generation, shell-script export, dry-run behavior, successful allowlisted execution, evidence persistence, and an expected deliberate failure.
- Extended the native Windows smoke harness to exercise the same v6.1 plan/export/execute loop and removed its stale hard-coded commit identifier.
- Preserved `release/v6-rc1` as the pinned v6.0.0 validation anchor while continuing development on the feature branch.

## 6.0.0

- Added bounded source manifests and source-component fingerprints.
- Added source-component nodes to the structural failure graph.
- Added `impact` for source changes since the known-good baseline.
- Enhanced `validate-next` with source-change context and targeted validation.
- Added safe compatibility behavior for v5 baselines that predate source tracking.
- Added source-impact information to reports and the local dashboard.
- Added eleven v6 regression tests; 48 tests pass locally.
- Verified clean wheel build/install and v5 → v6 baseline upgrade behavior.
- Forced Python fallback recompilation to avoid cached-bytecode false negatives.
- Added Python, Node, Go, and C/C++ source-failure classifiers from the unfamiliar-repository campaign.
- Completed a 10-repository Linux source-impact validation batch; Windows/second-OS evidence remains pending.
- Reused guard preflight reports when recording outcomes, reducing median structured-diagnosis overhead from 0.532 s to 0.344 s in the Linux benchmark.

## 5.0.0

- Added structural failure graph joining project components, dependencies, native artifacts/imports, SDKs, engines, toolchains, GPU state, and CPU architecture.
- Added node-level failure-risk ranking with bounded upstream propagation.
- Added graph delta, blast-radius analysis, `graph`, `explain`, and `validate-next`.
- Preserved v4 native inventory and v3 build-log intelligence.
- Verified 36 automated unit/regression tests.
