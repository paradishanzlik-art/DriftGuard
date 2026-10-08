# DriftGuard final beta evidence gates

**Status at 2026-10-08: OPEN. No final beta approval is asserted.**

The prior Linux release evidence at source commit e7a701f9186d6913a75775cd721192100963a69b covered 65 automated tests and 14 installed-wheel harness steps. The 10-repository Linux campaign and 0.344-second median machine overhead measurement relate to the earlier 6.0 RC1. None of those results should be relabeled as an exact-current-commit test, a native Windows pass, or a human diagnosis-time improvement.

## Gate 1: Exact committed-source, wheel, and behavior validation

After this PR is merged, choose the final commit from main. On a clean clone with Python 3.9+, Git, and packaging build prerequisites, use:

    git checkout main
    git pull --ff-only
    git rev-parse HEAD

PowerShell:

    $sha = (git rev-parse HEAD).Trim()
    python validation/run_exact_source.py --commit $sha --output source-current.json

The exact-source runner requires matching Git HEAD and a tracked-clean checkout, produces a disposable git archive of that SHA, and runs the existing clean-wheel/source fixture harness from the archive. Its sanitized summary omits local paths and logs. Do not validate the PR branch and claim the result belongs to the eventual merge SHA.

## Gate 2: Real native Windows validation

Run this **on a Windows host**, not on a Linux platform mock:

    powershell -ExecutionPolicy Bypass -File validation/windows_smoke.ps1 -ProjectRoot . -ExpectedCommit $sha -OutputPath windows-current.json

Review the native report privately: it can include local paths and tool details. Require successful regression tests, harmless edit passing, deliberate source break failing, and a python.syntax incident. The single Windows fixture does **not** replace the second-OS unfamiliar-repository study required by issue #3. Capture that second-OS campaign separately.

## Gate 3: Actual human diagnosis-time study

Use the existing HUMAN_DIAGNOSIS_STUDY.md protocol and prepared ten-case anonymized study kit. Start from human_results_template.json, which intentionally has **zero** observations. Do not fill it with invented timings.

Each observation must contain participant_id, case_id, mode (raw or structured), diagnosis_seconds, action_seconds, diagnosis_correct, and action_correct. Require at least two actual people and ten cases; each case must appear in both modes across participants, and each participant must see both modes. Verify study-kit checksum, timings, answer-key scoring, and participant provenance manually before interpreting the pilot. Machine overhead is not human time saved.

## Gate 4: GitHub Actions recovery

Issue #2 documents repeated startup_failure with **zero jobs**, including an isolated echo-only workflow control. This is not a passing CI run. Investigate repository/account Actions settings and escalate GitHub run IDs 36390200843 and 36389855029 if still affected.

After recovery, collect an actual successful six-job Ubuntu/Windows × Python 3.9/3.11/3.13 matrix on the same commit, including tests and wheel build for every job. The optional actions-current.json must have commit_sha, workflow_conclusion, run_url, and a jobs array. Every job requires matrix_os, python_version, conclusion, tests_passed, wheel_passed. The checker evaluates the submitted shape; **it cannot authenticate a manually written CI summary**. Inspect the official GitHub run independently.

## Aggregate and review

PowerShell:

    python validation/beta_gates.py --commit $sha --source source-current.json --windows windows-current.json --human human-results.json --actions actions-current.json --output beta-status.json

The checker returns exit 1 when any gate is open. Exit 0 means **evidence structurally complete; independent review required**, not automated permission to tag, publish, or claim production readiness.

Current open items: exact-current-commit source revalidation, native Windows and second-OS unfamiliar-repository cases, actual participant timings, and GitHub Actions runner startup. Keep heuristic risk scores distinct from calibrated failure probabilities. Retain the Apache-2.0 license and redact private paths and logs before sharing reports.
