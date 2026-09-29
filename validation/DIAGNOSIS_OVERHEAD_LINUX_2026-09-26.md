# DriftGuard diagnosis-overhead benchmark — Linux

**Date:** 2026-09-26/27  
**Validated code commit:** `47bc7af2e613e33e44d6181359e3137ae0c74793`  
**Repositories:** 10 unfamiliar known-good repositories from the Linux validation campaign  
**Repetitions:** 3 paired measurements per repository (30 pairs)

## What this benchmark measures

This is a **machine-time overhead benchmark**, not a human troubleshooting-time study.

- **Raw failure time:** the repository's normal validation command after a deliberate source-breaking edit.
- **DriftGuard guard time:** `driftguard guard --capture --force -- <same validation>` from an equivalent known-good DriftGuard baseline.
- **Structured diagnosis time:** guard time plus `driftguard incidents --limit 1 --json` retrieval.

The command produces a classified diagnosis automatically; however, no human engineer was timed interpreting the raw logs, so the human diagnosis-time product gate remains open.

## Results

- Correct expected classification: **30/30 paired DriftGuard runs**.
- Median raw validation time across all runs: **0.048 s**.
- Median structured diagnosis time across all runs: **0.392 s**.
- Median paired structured-diagnosis overhead: **0.344 s**.
- Median `guard` runtime across repositories: **0.316 s**.
- Median incident JSON retrieval: **0.075 s**.

## Campaign-driven performance fix

The first benchmark on commit `18ccc860f0b77c613b13c1b368f91564ac2f3693` found a nearly constant ~0.53 s overhead. Inspection showed that `guard` performed a full project report before command execution and `record_outcome()` performed another full report afterward.

`record_outcome()` now accepts and reuses the preflight report when called from `guard`. This both:

1. associates the outcome with the exact pre-execution conditions that were used for prediction; and
2. avoids a duplicate full project scan.

Measured effect:

- Median paired overhead: **0.532 s → 0.344 s** (**35.4% lower**).
- Median guard runtime across repositories: **0.516 s → 0.316 s** (**38.9% lower**).
- Classification correctness remained **30/30**.

## Interpretation

For these tiny repositories, the project validation itself is often only tens of milliseconds, so DriftGuard's fixed scan/classification cost dominates the ratio. In absolute terms the median additional time for a structured JSON-retrievable diagnosis is about **0.344 s**. Larger builds should reduce the relative percentage, but that has not yet been measured and should not be inferred from this dataset.

## Gate status

Completed:
- machine-time overhead measurement on the 10-repository Linux campaign;
- performance regression identified and reduced;
- classification correctness preserved after optimization.

Still open:
- timed human diagnosis comparison using anonymized raw logs versus DriftGuard diagnoses;
- native Windows/second-OS validation;
- larger-build performance measurements.
