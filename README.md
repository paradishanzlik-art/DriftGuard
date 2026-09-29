# DriftGuard

**See what changed, choose a useful check, and explain a failed build.**

DriftGuard is a local Python CLI for engineering projects. It records a known-good baseline, detects environment and source changes, ranks affected components in a failure graph, and suggests targeted validations. Its `guard` command can run your normal build or tests and classify captured failures. It does not install or change dependencies.

## Try the complete demo

From a source checkout, run:

```sh
python examples/showcase.py
```

The standard-library-only demo creates a disposable Python project, establishes a passing baseline, makes a harmless edit, previews and runs the recommended checks, then introduces a syntax error and verifies that the check fails. It cleans up its temporary project afterward. A successful run prints:

```text
DriftGuard 6.1 disposable showcase
Source changes found: 1
Targeted validation steps: 2
Dry-run executed: False
Harmless change validation passed: True
Deliberate syntax failure caught: True
All project files and DriftGuard state were removed after this run.
```

## Use it on your project

Python 3.9 or newer is required; DriftGuard itself has no runtime package dependencies.

```sh
python -m pip install .

# Run your own project's test/build first; init records the current state as known-good.
driftguard --root . init

# After a change:
driftguard --root . impact
driftguard --root . validate-plan --limit 5
driftguard --root . validate-run --limit 5             # preview only
driftguard --root . validate-run --limit 5 --execute   # run allowlisted checks

# Wrap the normal project test command and diagnose any captured failure:
driftguard --root . guard --capture -- python -m unittest discover -s tests -v
```

The `--execute` option may run a project's test or build scripts. Review the dry-run plan before using it. `validate-run --execute` returns 1 for a failed check and 4 when manual steps remain incomplete. `guard` returns the wrapped command's exit code; a preflight policy block returns 3. See [validation and exit semantics](VALIDATION.md).

| Command | Result |
| --- | --- |
| `check --json` | Environment drift, findings, and inspectable risk drivers |
| `impact --json` | Added, modified, and removed source since the baseline |
| `validate-next --json` | One targeted next check |
| `validate-plan --json` | Ordered checks with overlapping graph nodes deduplicated |
| `validation-script --shell bash -o validate.sh` | Reviewable script; unsupported checks stay as manual comments |
| `validate-run --json` | Dry-run plan, or direct-argv execution with explicit `--execute` |
| `graph --format dot -o driftguard.dot` | Structural failure graph for inspection |
| `guard --capture -- <command>` | Preflight, wrapped command, captured failure diagnosis |
| `export -o report.html` | Standalone local report; review its contents before sharing |

Use `driftguard --help` for the full command list. Project state and captured logs live in `.driftguard/`, which should stay out of version control. Reports and logs can contain local paths or project output; review or redact them before posting.

## Evidence and scope

The pinned 6.0 RC1 at commit `b12e67bb209bd2ae16d8b1b1af1bd5a67533f4e4` passed 48 automated tests and a Linux campaign on 10 unfamiliar known-good repositories. In those 10 cases, harmless source edits passed selected validations and deliberate breaking edits failed them. A 30-pair Linux benchmark measured **0.344 s median added machine time** to obtain a structured diagnosis after a performance fix. That number does not measure time saved for a human engineer.

The 6.1 branch adds the validation plan, script export, and opt-in execution shown above. At source commit `e7a701f9186d6913a75775cd721192100963a69b`, **65 tests and 14 installed-wheel validation steps passed on Linux/Python 3.12** after all 23 tracked files were verified against their Git blob hashes. The [commit-specific record](validation/RELEASE_GATE_6_1_2026-09-29.md) and [validation plan](VALIDATION.md) distinguish this evidence from the earlier RC1.

Risk scores are heuristic rankings, **not calibrated probabilities of build failure**. Native Windows and broader second-OS evaluation, a timed human diagnosis study, and functioning GitHub Actions runners remain open gates. The repository's Actions runs have ended before jobs start; they are not counted as passing CI. See [remaining validation gates](VALIDATION.md) and the [public preview guide](PUBLIC_PREVIEW.md).

## How it works

DriftGuard samples bounded source fingerprints and project configuration, plus available SDK, toolchain, dependency, GPU, and native-binary metadata. It compares the current snapshot with the baseline, connects changes to logical components and graph nodes, then proposes checks for the affected areas. Supported source-family detection includes Python, Node/TypeScript, C/C++, Rust, Go, .NET, Java/Kotlin, CUDA, shaders, Unreal, and Unity; command generation and validation coverage vary by family. Unsupported engine or project-specific checks are marked for manual review.

## License

DriftGuard is licensed under the [Apache License 2.0](LICENSE).

See the [changelog](CHANGELOG.md) for version history.
