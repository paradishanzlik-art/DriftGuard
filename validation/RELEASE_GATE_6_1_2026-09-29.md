# DriftGuard 6.1 committed-source validation

**Validated source commit:** `e7a701f9186d6913a75775cd721192100963a69b`  
**Date:** 2026-09-29 UTC  
**Host:** Linux, Python 3.12.14  
**Result:** 65/65 automated tests and 14/14 harness steps passed.

The 23 tracked files were copied into a clean directory from the development workspace. Before each copy, its bytes were hashed using Git's blob format and matched against the corresponding blob SHA from the commit's GitHub tree. The clean directory name included the commit prefix, and the harness was run with `--expected-commit e7a701f9186d6913a75775cd721192100963a69b`. This establishes byte identity with the committed source. It was a **verified tree reconstruction**, not a GitHub-generated ZIP download or a GitHub Actions job.

The harness forced Python compilation, ran the complete unit/regression suite, built a wheel, created a fresh virtual environment, installed the wheel offline, checked the installed version and CLI, then exercised `init`, `validate-plan`, Bash script export, `validate-run` dry-run, successful explicit execution, and deliberate syntax-break execution. It verified JSON semantics and saved pass/fail evidence. The deliberate failure returned exit 1 as expected and is counted as a passing *test of failure detection*.

`python examples/showcase.py` independently completed a disposable public demo from the same committed source: one changed source file, two targeted validations, no dry-run execution, a passing harmless edit, and a caught syntax failure.

The [sanitized machine-readable result](RELEASE_GATE_6_1_2026-09-29.json) contains the step names, exits, expected exits, and pass results without local paths or captured project output. The development-only full report is omitted from the repository because it includes temporary filesystem paths.

## Remaining gates

- Native Windows execution of `validation/windows_smoke.ps1` and second-OS repository cases.
- Timed human diagnosis comparison; the earlier 0.344 s measurement is machine-time overhead only.
- GitHub Actions `startup_failure` with zero jobs. No CI pass is claimed.
- License selection before publication as reusable open-source software.

This evidence supports a bounded public demo of 6.1 on Linux. It does not establish calibrated failure probabilities or production-grade support for every scanned source family.
