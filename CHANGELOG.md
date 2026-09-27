# Changelog

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
