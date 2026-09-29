#!/usr/bin/env python3
"""Run a disposable, end-to-end DriftGuard demo with no external packages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


DRIFTGUARD = Path(__file__).resolve().parents[1] / "driftguard.py"


def pause(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


def stage(number: int, title: str, delay: float) -> None:
    print()
    print("=" * 72)
    print(f"STEP {number}: {title}")
    print("=" * 72)
    sys.stdout.flush()
    pause(delay)


def show_command(*args: str) -> None:
    print(f"$ driftguard --root . {' '.join(args)}")
    sys.stdout.flush()


def call(
    root: Path,
    *args: str,
    expected: tuple[int, ...] = (0,),
    show: bool = True,
) -> dict | None:
    if show:
        show_command(*args)
    command = [sys.executable, str(DRIFTGUARD), "--root", str(root), *args]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    if result.returncode not in expected:
        raise RuntimeError(
            f"{' '.join(args)} returned {result.returncode}, expected {expected}\n"
            f"stdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}"
        )
    return json.loads(result.stdout) if "--json" in args else None


def print_plan(plan: dict) -> None:
    steps = plan.get("steps") or []
    print(f"Targeted validation steps: {plan.get('step_count', len(steps))}")
    for item in steps:
        order = item.get("order", "?")
        risk = item.get("risk_label") or item.get("risk") or "n/a"
        command = item.get("command", "<manual validation>")
        print(f"  [{order}] risk={risk}  {command}")


def print_execution(result: dict) -> None:
    print(f"Execution requested: {result.get('execution_requested')}")
    if "passed" in result:
        print(f"Passed: {result.get('passed')}")
    if "complete" in result:
        print(f"Complete: {result.get('complete')}")
    if "executed_steps" in result:
        print(f"Executed steps: {result.get('executed_steps')}")
    if "manual_steps" in result:
        print(f"Manual steps: {result.get('manual_steps')}")
    if "failed_steps" in result:
        print(f"Failed steps: {result.get('failed_steps')}")

    for item in result.get("results") or []:
        order = item.get("order", "?")
        status = item.get("status", "unknown")
        exit_code = item.get("exit_code")
        command = item.get("command") or item.get("display_command") or ""
        suffix = f" exit={exit_code}" if exit_code is not None else ""
        print(f"  [{order}] {status}{suffix}  {command}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--present",
        action="store_true",
        help="Add short pauses between stages for screen recording or live demos.",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=None,
        help="Override the presentation pause in seconds (implies --present).",
    )
    args = parser.parse_args()

    delay = 1.0 if args.present else 0.0
    if args.pause is not None:
        delay = max(0.0, args.pause)

    print("DriftGuard 6.1 - disposable end-to-end showcase")
    print("This demo creates a temporary project, changes it, validates it,")
    print("introduces a real syntax failure, catches it, and then deletes everything.")
    sys.stdout.flush()
    pause(delay)

    with tempfile.TemporaryDirectory(prefix="driftguard-showcase-") as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "tests").mkdir()
        (root / "pyproject.toml").write_text(
            '[project]\nname = "driftguard-showcase"\nversion = "0.0.0"\n',
            encoding="utf-8",
        )
        source = root / "src" / "app.py"
        source.write_text("def answer():\n    return 42\n", encoding="utf-8")
        (root / "tests" / "test_app.py").write_text(
            "import sys\nimport unittest\nfrom pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))\n"
            "from app import answer\n"
            "class DemoTest(unittest.TestCase):\n"
            "    def test_answer(self):\n        self.assertEqual(answer(), 42)\n",
            encoding="utf-8",
        )

        stage(1, "Create a known-good disposable project", delay)
        print("src/app.py")
        print("  def answer():")
        print("      return 42")
        print()
        print("tests/test_app.py")
        print("  verifies answer() == 42")
        sys.stdout.flush()
        pause(delay)

        stage(2, "Verify the project before recording a baseline", delay)
        print("$ python -m unittest discover -s tests")
        tests = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if tests.returncode:
            raise RuntimeError(tests.stderr)
        print("PASS - project tests are green")
        sys.stdout.flush()
        pause(delay)

        stage(3, "Record the known-good DriftGuard baseline", delay)
        call(root, "init")
        print("Baseline recorded.")
        sys.stdout.flush()
        pause(delay)

        stage(4, "Make a harmless source change and detect its impact", delay)
        source.write_text(
            "def answer():\n    return 42\n\n# harmless change\n",
            encoding="utf-8",
        )
        print("Changed src/app.py:")
        print("  + # harmless change")
        print()
        impact = call(root, "impact", "--json")
        assert impact is not None
        print(f"Source changes found: {impact.get('total_changes', 0)}")
        changed_components = impact.get("changed_components") or []
        if changed_components:
            print("Affected components:")
            for component in changed_components:
                print(f"  - {component}")
        sys.stdout.flush()
        pause(delay)

        stage(5, "Build a targeted validation plan", delay)
        plan = call(
            root,
            "validate-plan",
            "--limit",
            "5",
            "--json",
            expected=(0, 1),
        )
        assert plan is not None
        print_plan(plan)
        sys.stdout.flush()
        pause(delay)

        stage(6, "Preview the plan safely - no commands execute", delay)
        dry = call(root, "validate-run", "--limit", "5", "--json")
        assert dry is not None
        print_execution(dry)
        print("Dry-run safety check: PASS - nothing executed.")
        sys.stdout.flush()
        pause(delay)

        stage(7, "Execute the targeted checks for the harmless change", delay)
        passing = call(
            root,
            "validate-run",
            "--limit",
            "5",
            "--execute",
            "--json",
        )
        assert passing is not None
        print_execution(passing)
        if not passing.get("passed"):
            raise RuntimeError("Harmless change validation did not pass")
        print("Harmless source change: VALIDATED")
        sys.stdout.flush()
        pause(delay)

        if not impact.get("total_changes") or not plan.get("step_count"):
            raise RuntimeError(
                "Expected the harmless source change to produce a validation plan"
            )
        if dry.get("execution_requested"):
            raise RuntimeError("Dry-run unexpectedly executed validation")

        stage(8, "Introduce a deliberate syntax failure", delay)
        source.write_text("def answer()\n    return 42\n", encoding="utf-8")
        print("Changed src/app.py:")
        print("  - def answer():")
        print("  + def answer()")
        print("                 ^ missing ':'")
        sys.stdout.flush()
        pause(delay)

        stage(9, "Run DriftGuard validation and catch the break", delay)
        failing = call(
            root,
            "validate-run",
            "--limit",
            "5",
            "--execute",
            "--json",
            expected=(1,),
        )
        assert failing is not None
        print_execution(failing)
        if not failing.get("failed_steps"):
            raise RuntimeError("The deliberate syntax error was not caught")
        print("Deliberate syntax failure: CAUGHT")
        sys.stdout.flush()
        pause(delay)

        stage(10, "Demo result", delay)
        print("Source impact detected:              PASS")
        print("Targeted validation plan generated: PASS")
        print("Dry-run prevented execution:        PASS")
        print("Harmless change validated:          PASS")
        print("Deliberate syntax failure caught:   PASS")
        print()
        print("All project files and DriftGuard state are now removed.")
        print("DriftGuard 6.1 Beta demo complete.")
        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
