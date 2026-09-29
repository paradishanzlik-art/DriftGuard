# DriftGuard unfamiliar-repository validation — Linux batch

**Date:** 2026-09-26/27
**Validated code commit:** `18ccc860f0b77c613b13c1b368f91564ac2f3693`
**Tree:** `c112baa667d6b307c0e199293e396fd62bbf2caa`
**Host:** Linux, Python 3.13.5, Node 22.16.0/npm 10.9.2, Go 1.23.2, CMake 3.31.6, GCC 14.2.0

## Result

- 10/10 completed repositories had a passing known-good baseline.
- 10/10 harmless controlled source edits were detected and their recommended targeted validation passed.
- 10/10 deliberate source-breaking edits were detected and the recommended validation failed.
- 10/10 breaking cases are classified after campaign-driven fixes: 3 Python syntax, 1 Node syntax, 5 Go syntax, 1 C/C++ compile error.
- Two additional repositories were attempted but excluded because their original source failed baseline validation before mutation testing.

These results establish bounded Linux source-impact behavior on this sample. They do **not** establish calibrated failure probabilities, general false-positive/false-negative rates, Windows compatibility, or production-scale performance.

## Completed cases

| Repository | Stack | Detected component | Targeted validation | Breaking diagnosis |
|---|---|---|---|---|
| `notion/utaw` | Python | `python/utaw` | `compileall -q -f` | `python.syntax` |
| `lambdacasserole/exhaustion` | Python | `python/exhaustion` | `compileall -q -f` | `python.syntax` |
| `AlexanderOMara/test-package-json-scripts` | Node | `node/.` | `npm test` | `node.syntax` |
| `toby82/utils` | Go | `go/.` | `go test ./...` | `go.syntax` |
| `Saswat-Gewali/tinykit` | Python | `python/tinykit_py` | `compileall -q -f` | `python.syntax` |
| `sylr/go-mod-test` | Go | `go/pkg` | `go test ./...` | `go.syntax` |
| `smallsnails/go-mod-test` | Go | `go/test` | `go test ./...` | `go.syntax` |
| `zzz136454872/go_mod_test` | Go | `go/.` | `go test ./...` | `go.syntax` |
| `CMAKE-EXAMPLES/SIMPLE` | C++ | `cpp/src` | `cmake --build build --config Debug` | `cpp.compile` |
| `shrek82/hellomod` | Go | `go/.` | `go test ./...` | `go.syntax` |

## Baseline-blocked cases

- `hunterzhao/hello` — original source fails because its import path conflicts with its module path.
- `Mateodioev/testgo` — original layout mixes two Go packages in one module directory.

## Campaign-driven fixes

1. Forced Python fallback compilation with `compileall -q -f`.
2. Added `python.syntax`, `node.syntax`, and `go.syntax` source-failure signatures.
3. Added `cpp.compile` for GCC/Clang-style source compile failures.
4. Connected these diagnoses to source-component graph nodes.
5. Added regression coverage; the exact validated source snapshot passes **47/47** tests.

## Reproducibility

- Exact source ZIP SHA-256: `89a9cdcc01a06e64552ac8a1ee097ed2d0f117dfd8e68c072bd4da62296e1c1f`
- Built wheel SHA-256: `50e95b1a0fe251ddd29b9a079b0e1a926f3052b77c3fe6f5293233f1295d178e`
- The source-ZIP path is used because GitHub Actions currently terminates with `startup_failure` before runner jobs are created.

## Gates still open

- Native Windows clean-install and behavior evidence.
- Equivalent campaign evidence on Windows or another second OS family.
- Controlled diagnosis-time comparison with and without DriftGuard.
- Larger/more complex repositories before expanding product claims.
