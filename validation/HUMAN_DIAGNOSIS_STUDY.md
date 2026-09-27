# DriftGuard human diagnosis-time study

## Purpose
Measure human time-to-correct-diagnosis and time-to-action when given either a raw failed validation log or DriftGuard's structured diagnosis. This study is deliberately separate from the machine-time overhead benchmark.

## Minimum pilot
Use at least two participants. Participant A and Participant B use counterbalanced assignments so neither person sees the same failure in both modes.

For each assigned case:
1. Start a stopwatch immediately before opening the assigned raw log or DriftGuard JSON.
2. Record **time to diagnosis** when the participant first commits to a failure category/root cause.
3. Record the diagnosis text and confidence from 1–5.
4. Continue timing until the participant states the **next concrete engineering action** they would take; record **time to action**.
5. Do not reveal the answer key until all cases are complete.

## Scoring
A diagnosis is correct when it matches the answer-key failure family (Python syntax, JavaScript syntax, Go syntax, or C/C++ compile error). An action is correct when it would directly inspect/fix the reported source error and rerun the targeted validation.

Compare median time-to-correct-diagnosis, median time-to-correct-action, accuracy, and confidence by mode. With only two participants this is a pilot, not a statistically generalizable usability study.

## Prepared study kit
A 10-case anonymized study kit has been generated from the unfamiliar-repository campaign. It contains raw logs, DriftGuard diagnoses, counterbalanced A/B assignments, blank result sheets, and a hidden answer key.

Study-kit SHA-256: `a46ae2a2987d18ea23671b6fd9caa36186e782ff2ee01b3822a7e8425421acbf`.

The actual timed human study remains open until real participant results are collected.
