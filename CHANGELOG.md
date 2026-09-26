# Changelog

## 6.0.0

- Added bounded source manifests and source-component fingerprints.
- Added source-component nodes to the structural failure graph.
- Added `impact` for source changes since the known-good baseline.
- Enhanced `validate-next` with source-change context and targeted validation.
- Added safe compatibility behavior for v5 baselines that predate source tracking.
- Added source-impact information to reports and the local dashboard.
- Added six v6 regression tests; 42 tests pass locally.
- Verified clean wheel build/install and v5 → v6 baseline upgrade behavior.

## 5.0.0

- Added structural failure graph joining project components, dependencies, native artifacts/imports, SDKs, engines, toolchains, GPU state, and CPU architecture.
- Added node-level failure-risk ranking with bounded upstream propagation.
- Added graph delta, blast-radius analysis, `graph`, `explain`, and `validate-next`.
- Preserved v4 native inventory and v3 build-log intelligence.
- Verified 36 automated unit/regression tests.
