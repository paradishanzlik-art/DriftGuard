#!/usr/bin/env python3
"""Run a disposable, end-to-end DriftGuard demo with no external packages."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


DRIFTGUARD = Path(__file__).resolve().parents[1] / "driftguard.py"


def call(root: Path, *args: str, expected: tuple[int, ...] = (0,)) -> dict | None:
    command = [sys.executable, str(DRIFTGUARD), "--root", str(root), *args]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    if result.returncode not in expected:
        raise RuntimeError(
            f"{' '.join(args)} returned {result.returncode}, expected {expected}\n"
            f"stdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}"
        )
    return json.loads(result.stdout) if "--json" in args else None


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="driftguard-showcase-") as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "tests").mkdir()
        (root / "pyproject.toml").write_text(
            '[project]\nname = "driftguard-showcase"\nversion = "0.0.0"\n', encoding="utf-8"
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

        # A baseline should be recorded only after the project's own checks pass.
        tests = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
            cwd=root, capture_output=True, text=True,
        )
        if tests.returncode:
            raise RuntimeError(tests.stderr)
        call(root, "init")

        source.write_text("def answer():\n    return 42\n\n# harmless change\n", encoding="utf-8")
        impact = call(root, "impact", "--json")
        plan = call(root, "validate-plan", "--limit", "5", "--json", expected=(0, 1))
        dry = call(root, "validate-run", "--limit", "5", "--json")
        passing = call(root, "validate-run", "--limit", "5", "--execute", "--json")
        assert impact is not None and plan is not None and dry is not None and passing is not None
        if not impact.get("total_changes") or not plan.get("step_count"):
            raise RuntimeError("Expected the harmless source change to produce a validation plan")
        if dry.get("execution_requested") or not passing.get("passed"):
            raise RuntimeError("Dry-run or passing validation did not behave as expected")

        source.write_text("def answer()\n    return 42\n", encoding="utf-8")
        failing = call(root, "validate-run", "--limit", "5", "--execute", "--json", expected=(1,))
        assert failing is not None
        if not failing.get("failed_steps"):
            raise RuntimeError("The deliberate syntax error was not caught")

        print("DriftGuard 6.1 disposable showcase")
        print(f"Source changes found: {impact['total_changes']}")
        print(f"Targeted validation steps: {plan['step_count']}")
        print(f"Dry-run executed: {dry.get('execution_requested')}")
        print(f"Harmless change validation passed: {passing['passed']}")
        print(f"Deliberate syntax failure caught: {failing['failed_steps'] > 0}")
        print("All project files and DriftGuard state were removed after this run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
