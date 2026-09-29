# Public preview guide

DriftGuard 6.1 is suitable for a bounded engineering portfolio demo. Present the observed behavior and validation evidence below; do not describe its heuristic score as a failure probability or claim production-wide cross-platform coverage.

## Suggested 90-second walkthrough

1. Run `python examples/showcase.py` from a source checkout. It creates a disposable fixture and prints only aggregate results.
2. Explain the baseline → harmless edit → `impact` → targeted plan → dry-run → passing validation → deliberate syntax failure sequence.
3. Show the risk graph and the distinction between source impact and environment drift using a project you are authorized to share.
4. Point to [`VALIDATION.md`](VALIDATION.md) for the exact checks run and the remaining gates.

Suggested description:

> I built DriftGuard, a local Python CLI that compares a project with a known-good baseline, connects source and environment changes to a failure graph, and recommends validations. Its 6.1 demo catches a deliberate syntax failure after a successful harmless edit. A 10-repository Linux evaluation and a 30-pair overhead measurement support narrower claims; Windows and human diagnosis-time studies remain open.

## Before sharing any output

- Use the disposable demo or a repository you can disclose. Inspect exported HTML/JSON, incident logs, and `.driftguard/` before posting: they can contain absolute paths and captured build output.
- Record a baseline only after the project's normal validation passes. A baseline is a snapshot, not an automated proof of correctness.
- Review `validate-run` in dry-run mode before `--execute`. Allowlisted commands such as `npm test` can execute scripts defined by the target project.
- If publishing the source repository, choose and add an explicit license. No license terms have been selected in this branch.
- Keep the Windows, diagnosis-time, and GitHub Actions limitations visible beside the claims; do not use a green CI badge while jobs fail before starting.

## Release gates still open

| Gate | Current position |
| --- | --- |
| Linux 6.1 source suite, wheel install, end-to-end fixture | Completed on verified commit `e7a701f`; see `validation/RELEASE_GATE_6_1_2026-09-29.md` |
| Native Windows | Run `validation/windows_smoke.ps1` on a real Windows host; retain its JSON evidence |
| Human diagnosis-time study | Conduct the prepared counterbalanced study; do not infer time saved from command overhead |
| GitHub Actions | Resolve the zero-job `startup_failure` before counting a CI matrix as evidence |
| License and visibility | Owner chooses terms and whether/when the private repository becomes public |

These open gates limit release and marketing claims. They do not prevent showing the bounded demo with the stated context.
