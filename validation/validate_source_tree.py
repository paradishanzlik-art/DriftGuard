#!/usr/bin/env python3
"""Validate an extracted DriftGuard GitHub source ZIP without relying on Actions."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


def run_step(name: str, command: list[str], cwd: Path, expected_exit_codes: tuple[int, ...] = (0,)) -> dict:
    started = datetime.now(timezone.utc)
    proc = subprocess.run(command, cwd=str(cwd), text=True, capture_output=True)
    ended = datetime.now(timezone.utc)
    ok = proc.returncode in expected_exit_codes
    result = {
        "name": name,
        "command": command,
        "exit_code": proc.returncode,
        "expected_exit_codes": list(expected_exit_codes),
        "ok": ok,
        "duration_seconds": round((ended - started).total_seconds(), 3),
        "stdout_tail": proc.stdout[-6000:],
        "stderr_tail": proc.stderr[-6000:],
    }
    print(f"[{'PASS' if ok else 'FAIL'}] {name} ({result['duration_seconds']}s)")
    if not ok:
        if result["stdout_tail"]:
            print(result["stdout_tail"])
        if result["stderr_tail"]:
            print(result["stderr_tail"], file=sys.stderr)
    return result


def executable_in_venv(venv_dir: Path, name: str) -> Path:
    if os.name == "nt":
        suffix = ".exe" if name in {"python", "pip", "driftguard"} else ""
        return venv_dir / "Scripts" / f"{name}{suffix}"
    return venv_dir / "bin" / name


def validate(root: Path, expected_commit: str | None, skip_wheel: bool) -> dict:
    root = root.resolve()
    if not (root / "driftguard.py").is_file() or not (root / "tests").is_dir():
        raise SystemExit(f"Not a DriftGuard source tree: {root}")

    identity = {
        "root": str(root),
        "archive_directory": root.name,
        "expected_commit": expected_commit,
        "commit_hint_match": None,
    }
    if expected_commit:
        short = expected_commit.lower()[:7]
        identity["commit_hint_match"] = short in root.name.lower()
        if not identity["commit_hint_match"]:
            raise SystemExit(
                "Source ZIP identity check failed: the extracted directory name does not "
                f"contain expected commit prefix {short}. Use a commit-specific GitHub source ZIP."
            )

    steps = []
    steps.append(run_step(
        "compile",
        [sys.executable, "-m", "compileall", "-q", "-f", "driftguard.py", "tests"],
        root,
    ))
    if steps[-1]["exit_code"] == 0:
        steps.append(run_step(
            "unit-regression-suite",
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            root,
        ))

    if not skip_wheel and all(step["exit_code"] == 0 for step in steps):
        with tempfile.TemporaryDirectory(prefix="driftguard-source-zip-") as td:
            temp = Path(td)
            wheelhouse = temp / "wheelhouse"
            wheelhouse.mkdir()
            steps.append(run_step(
                "build-wheel",
                [
                    sys.executable, "-m", "pip", "wheel", ".",
                    "--no-deps", "--no-build-isolation", "-w", str(wheelhouse),
                ],
                root,
            ))
            wheels = sorted(wheelhouse.glob("*.whl"))
            if steps[-1]["exit_code"] == 0 and wheels:
                venv_dir = temp / "venv"
                steps.append(run_step(
                    "create-clean-venv",
                    [sys.executable, "-m", "venv", str(venv_dir)],
                    root,
                ))
                py = executable_in_venv(venv_dir, "python")
                if steps[-1]["exit_code"] == 0:
                    steps.append(run_step(
                        "offline-wheel-install",
                        [str(py), "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])],
                        root,
                    ))
                if steps[-1]["exit_code"] == 0:
                    steps.append(run_step(
                        "installed-import-smoke",
                        [
                            str(py), "-c",
                            "import driftguard,sys; print(driftguard.APP_VERSION); "
                            "sys.exit(0 if driftguard.APP_VERSION == '6.1.0' else 1)",
                        ],
                        temp,
                    ))
                    dg = executable_in_venv(venv_dir, "driftguard")
                    steps.append(run_step(
                        "installed-cli-smoke",
                        [str(dg), "--help"],
                        temp,
                    ))

                    fixture = temp / "fixture"
                    (fixture / "src").mkdir(parents=True)
                    (fixture / "tests").mkdir()
                    (fixture / "pyproject.toml").write_text(
                        '[project]\nname = "fixture"\nversion = "0.0.0"\nrequires-python = ">=3.9"\n',
                        encoding="utf-8",
                    )
                    (fixture / "src" / "app.py").write_text(
                        "def value():\n    return 1\n",
                        encoding="utf-8",
                    )
                    (fixture / "tests" / "test_app.py").write_text(
                        "from pathlib import Path\n"
                        "import sys\n"
                        "import unittest\n"
                        "sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))\n"
                        "import app\n"
                        "class T(unittest.TestCase):\n"
                        "    def test_value(self):\n"
                        "        self.assertEqual(app.value(), 1)\n",
                        encoding="utf-8",
                    )
                    steps.append(run_step(
                        "installed-fixture-init",
                        [str(dg), "--root", str(fixture), "init"],
                        fixture,
                    ))
                    (fixture / "src" / "app.py").write_text(
                        "def value():\n    return 1\n\n# harmless edit\n",
                        encoding="utf-8",
                    )
                    steps.append(run_step(
                        "installed-validate-plan",
                        [str(dg), "--root", str(fixture), "validate-plan", "--limit", "5", "--json"],
                        fixture,
                    ))
                    script_path = fixture / ("validate.ps1" if os.name == "nt" else "validate.sh")
                    shell_name = "powershell" if os.name == "nt" else "bash"
                    steps.append(run_step(
                        "installed-validation-script",
                        [
                            str(dg), "--root", str(fixture), "validation-script",
                            "--shell", shell_name, "--limit", "5", "-o", str(script_path),
                        ],
                        fixture,
                    ))
                    if steps[-1]["ok"] and not script_path.is_file():
                        steps.append({
                            "name": "validation-script-present",
                            "command": [],
                            "exit_code": 1,
                            "expected_exit_codes": [0],
                            "ok": False,
                            "duration_seconds": 0.0,
                            "stdout_tail": "",
                            "stderr_tail": "validation-script reported success but created no output file",
                        })
                    steps.append(run_step(
                        "installed-validate-run-dry",
                        [str(dg), "--root", str(fixture), "validate-run", "--limit", "5", "--json"],
                        fixture,
                    ))
                    steps.append(run_step(
                        "installed-validate-run-pass",
                        [
                            str(dg), "--root", str(fixture), "validate-run",
                            "--limit", "5", "--timeout", "120", "--execute", "--save", "--json",
                        ],
                        fixture,
                    ))
                    (fixture / "src" / "app.py").write_text(
                        "def value()\n    return 1\n",
                        encoding="utf-8",
                    )
                    steps.append(run_step(
                        "installed-validate-run-breaking",
                        [
                            str(dg), "--root", str(fixture), "validate-run",
                            "--limit", "5", "--timeout", "120", "--execute", "--save", "--json",
                        ],
                        fixture,
                        expected_exit_codes=(1,),
                    ))
                    # An exit code alone is weak evidence: an unrelated CLI
                    # crash could also return 1. Verify the reported outcome
                    # and the evidence written by the installed package.
                    semantic_errors = []
                    observed = {}
                    for name in (
                        "installed-validate-plan", "installed-validate-run-dry",
                        "installed-validate-run-pass", "installed-validate-run-breaking",
                    ):
                        step = next(s for s in steps if s["name"] == name)
                        try:
                            observed[name] = json.loads(step["stdout_tail"])
                        except (ValueError, TypeError):
                            semantic_errors.append(f"{name} did not produce valid JSON")
                    plan = observed.get("installed-validate-plan", {})
                    dry = observed.get("installed-validate-run-dry", {})
                    passing = observed.get("installed-validate-run-pass", {})
                    breaking = observed.get("installed-validate-run-breaking", {})
                    if plan.get("step_count", 0) < 1:
                        semantic_errors.append("source change produced no validation plan")
                    if dry.get("execution_requested") is not False or dry.get("executable_steps", 0) < 1:
                        semantic_errors.append("dry-run did not report executable steps without executing")
                    if passing.get("execution_requested") is not True or not passing.get("passed") or passing.get("executed_steps", 0) < 1:
                        semantic_errors.append("harmless source validation did not execute and pass")
                    if breaking.get("execution_requested") is not True or breaking.get("failed_steps", 0) < 1 or breaking.get("passed") is not False:
                        semantic_errors.append("deliberate syntax break was not reported as a failed validation")
                    evidence_path = fixture / ".driftguard" / "validation_runs.jsonl"
                    try:
                        evidence = [json.loads(line) for line in evidence_path.read_text(encoding="utf-8").splitlines()]
                        if len(evidence) < 2 or not evidence[-2].get("passed") or evidence[-1].get("failed_steps", 0) < 1:
                            semantic_errors.append("saved validation evidence does not contain pass and failure")
                    except (OSError, ValueError):
                        semantic_errors.append("saved validation evidence is absent or invalid")
                    steps.append({
                        "name": "installed-validation-semantics",
                        "command": [],
                        "exit_code": 1 if semantic_errors else 0,
                        "expected_exit_codes": [0],
                        "ok": not semantic_errors,
                        "duration_seconds": 0.0,
                        "stdout_tail": "Pass and failure outcomes verified" if not semantic_errors else "",
                        "stderr_tail": "; ".join(semantic_errors),
                    })
                    print(f"[{'PASS' if not semantic_errors else 'FAIL'}] installed-validation-semantics")
            elif steps[-1]["exit_code"] == 0:
                steps.append({
                    "name": "wheel-present",
                    "command": [],
                    "exit_code": 1,
                    "duration_seconds": 0.0,
                    "stdout_tail": "",
                    "stderr_tail": "pip wheel exited successfully but produced no wheel",
                })

    passed = bool(steps) and all(bool(step.get("ok", step.get("exit_code") == 0)) for step in steps)
    return {
        "schema": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": sys.platform,
        "identity": identity,
        "passed": passed,
        "steps": steps,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate an extracted, commit-specific DriftGuard GitHub source ZIP."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--expected-commit", help="Full GitHub commit SHA expected in the archive directory name.")
    parser.add_argument("--skip-wheel", action="store_true", help="Run compile/tests only.")
    parser.add_argument("--json-out", type=Path, help="Write machine-readable validation evidence.")
    args = parser.parse_args()

    result = validate(args.root, args.expected_commit, args.skip_wheel)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Wrote evidence: {args.json_out.resolve()}")
    print("SOURCE ZIP VALIDATION:", "PASS" if result["passed"] else "FAIL")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
