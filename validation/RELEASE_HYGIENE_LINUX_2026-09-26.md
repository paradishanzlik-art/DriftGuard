# DriftGuard release-hygiene and upgrade validation — Linux

**Date:** 2026-09-26/27  
**PR-head source ZIP:** `b12e67bb209bd2ae16d8b1b1af1bd5a67533f4e4`  
**Source tree:** `f780eedb3f0e3a69c74325d8f6cb9e3d6e604749`

## Packaging

- Source ZIP contains **15** Git-tracked files and no `__pycache__`, `.pyc`, build directory, egg-info, or `.driftguard` state.
- Source ZIP SHA-256: `dc6c5c1857dd01c04a27d73caae6604c5839c4291b5c1ab8994e5f42b5d02188`.
- Wheel contains **6** entries with no cache/build/test/local-state artifacts.
- Wheel SHA-256: `6ff4087b5fbd4e4c09569bf250422f0c79327747b4f926c2d088affb9169a762`.
- Fresh offline wheel installation succeeded.
- Source-ZIP regression suite: **48/48 pass**.

## CLI smoke

| Command | Exit |
|---|---:|
| `init` | 0 |
| `check --json` | 0 |
| `impact --json` | 0 |
| `validate-next --json` | 0 |
| `graph --format json` | 0 |
| `guard --capture --force` | 0 |

## v5 → v6 baseline compatibility

A known-good fixture was baselined with DriftGuard v5 and then opened with the current v6 candidate on the same host.

Observed behavior:

- v6 detected that the baseline predates source-impact tracking: **requires rebaseline = true**.
- It reported **0 synthetic source changes** before rebaseline.
- The project remained testable and known-good.
- `check` remained non-blocking (`STABLE`, score 93, risk 25/100 on this host).
- After a successful known-good validation and `init --force`, source impact returned to **0 changes** and no longer requested rebaseline.

The pre-rebaseline `validate-next` recommendation was `python --version` because a tool node differed from the older graph representation. This is visible evidence rather than a source-risk spike and is cleared by the documented rebaseline path.

## Gate status

Linux release-hygiene evidence passes for the current candidate. Native Windows/second-OS validation remains required before treating v6 as fully cross-platform validated. GitHub Actions `startup_failure` remains tracked separately and is not counted as passing CI evidence.
