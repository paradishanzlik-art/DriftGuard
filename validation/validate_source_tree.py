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


def run_step(name: str, command: list[str], cwd: Path) -> dict:
    started = datetime.now(timezone.utc)
    proc = subprocess.run(command, cwd=str(cwd), text=True, capture_output=True)
    ended = datetime.now(timezone.utc)
    result = {
        "name": name,
        "command": command,
        "exit_code": proc.returncode,
        "duration_seconds": round((ended - started).total_seconds(), 3),
        "stdout_tail": proc.stdout[-6000:],
        "stderr_tail": proc.stderr[-6000:],
    }
    print(f"[{'PASS' if proc.returncode == 0 else 'FAIL'}] {name} ({result['duration_seconds']}s)")
    if proc.returncode != 0:
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
                        [str(py), "-c", "import driftguard; print(driftguard.APP_VERSION)"],
                        temp,
                    ))
                    dg = executable_in_venv(venv_dir, "driftguard")
                    steps.append(run_step(
                        "installed-cli-smoke",
                        [str(dg), "--help"],
                        temp,
                    ))
            elif steps[-1]["exit_code"] == 0:
                steps.append({
                    "name": "wheel-present",
                    "command": [],
                    "exit_code": 1,
                    "duration_seconds": 0.0,
                    "stdout_tail": "",
                    "stderr_tail": "pip wheel exited successfully but produced no wheel",
                })

    passed = bool(steps) and all(step["exit_code"] == 0 for step in steps)
    return {
        "schema": 1,
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
