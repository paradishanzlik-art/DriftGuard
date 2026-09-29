# DriftGuard guard-semantics validation — Linux

**Date:** 2026-09-26/27  
**Source-ZIP head:** `b12e67bb209bd2ae16d8b1b1af1bd5a67533f4e4`  
**Runtime code:** includes preflight-report reuse optimization and 48 passing tests

## Validated behavior

| Scenario | Expected | Observed | Result |
|---|---:|---:|---|
| `guard` without a baseline | 2 | 2 | pass |
| clean `check` | 0 | 0 | pass |
| clean guarded command | 0 | 0 | pass |
| source-changed `check` remains diagnostic | 0 | 0 | pass |
| policy-blocked guard | 3 | 3 | pass |
| blocked command execution | must not run | did not run | pass |
| failing guarded validation | propagate 1 | 1 | pass |
| failing guarded validation diagnosis | `python.syntax` | `python.syntax` | pass |
| missing guarded command | 127 | 127 | pass |

This confirms the intended contract: `check` is diagnostic; callers that need enforcement should use `guard`/policy behavior. A policy block prevents command execution, while a command that is allowed to run returns the command's own failure code.

## Scope

This evidence is Linux-only. The Windows validation script in `validation/windows_smoke.ps1` is prepared to repeat source install, regression tests, harmless edit, breaking edit, guard execution, and syntax classification on a native Windows host.
