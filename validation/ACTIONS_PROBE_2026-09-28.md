# GitHub Actions isolated probe — 2026-09-28

## Purpose

Determine whether DriftGuard's normal `.github/workflows/tests.yml` matrix is causing the persistent pre-job GitHub Actions failure, or whether the failure occurs before the selected workflow can construct a job.

## Control

A separate branch was created from `main`:

- branch: `diagnostic/actions-probe`
- commit: `8989afcf70f6ba7cb11d0c764ac1b93b7a8198ff`

The branch adds a new independent workflow with one GitHub-hosted Linux job and one echo step:

```yaml
name: actions-probe

on:
  push:
  workflow_dispatch:

jobs:
  probe:
    runs-on: ubuntu-latest
    steps:
      - name: Echo
        run: echo "GitHub Actions probe reached a runner"
```

The normal `tests.yml` exists on `main` at blob `563fc0f0a130985eaace156ff290d02a2a3485ae`.

## Result

The probe push created workflow run **107**, run id `36390200843`.

Observed API metadata:

- workflow name: empty
- path: `BuildFailed`
- event: `push`
- status: `completed`
- conclusion: `startup_failure`
- workflow id: `368001847`
- jobs created: **0**

No runner, checkout, repository test, or echo step was reached.

## Interpretation

This control strongly rules out the DriftGuard Python test matrix, Windows runner selection, `actions/checkout`, `actions/setup-python`, and pull-request-only behavior as the sole cause. The minimal independent push workflow failed before GitHub created any job.

This does **not** by itself prove the exact backend root cause. It is consistent with a repository/account Actions workflow-registration or dispatch failure. Similar private-repository reports with the same empty-name + `BuildFailed` + `startup_failure` + zero-job signature include:

- https://github.com/orgs/community/discussions/208832
- https://github.com/orgs/community/discussions/206902
- https://github.com/orgs/community/discussions/206103

## Decision

- Keep GitHub Actions excluded from DriftGuard validation evidence.
- Keep issue #2 open as an infrastructure/backend blocker.
- Use the exact-commit source-ZIP validation harness for release evidence.
- If repository Actions settings are normal, provide run ids `36390200843` and `36389855029` to GitHub Support together with this control.
