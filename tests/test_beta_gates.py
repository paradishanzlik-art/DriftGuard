"""Independent beta evidence governance tests (no external dependencies)."""
import importlib.util
from pathlib import Path
import unittest

MOD = Path(__file__).resolve().parents[1] / "validation" / "beta_gates.py"
spec = importlib.util.spec_from_file_location("beta_gates", MOD)
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)
SHA = "1" * 40


def source():
    return {"validated_commit": SHA, "harness_passed": True, "steps": [
        {"name": n, "passed": True} for n in sorted(gates.NEEDED)
    ]}


def windows():
    return {"code_commit": SHA, "passed": True, "regression_suite_exit": 0,
            "clean_source_changes": 0, "harmless_source_changes": 1,
            "harmless_guard_exit": 0, "harmless_execute_failed_steps": 0,
            "breaking_source_changes": 1, "breaking_guard_exit": 1,
            "breaking_signature": "python.syntax", "os": "Microsoft Windows 10"}


def human():
    return {"observations": [
        {"participant_id": f"p{idx}", "case_id": f"c{i}",
         "mode": ("raw" if (i+idx) % 2 == 0 else "structured"),
         "diagnosis_seconds": 12.2, "action_seconds": 20.4,
         "diagnosis_correct": True, "action_correct": True}
        for idx in range(2) for i in range(10)]}


def actions():
    return {"commit_sha": SHA, "workflow_conclusion": "success",
            "run_url": "https://github.com/owner/repo/actions/runs/123",
            "jobs": [{"matrix_os": o, "python_version": p, "conclusion": "success",
                      "tests_passed": True, "wheel_passed": True}
                     for o in ("ubuntu-latest", "windows-latest") for p in ("3.9", "3.11", "3.13")]}


class EvidenceGatesTest(unittest.TestCase):
    def test_all_absent_blocks(self):
        report = gates.evaluate(SHA)
        self.assertEqual(report["decision"], "BETA_GATES_OPEN")
        self.assertEqual(len(report["gates"]), 4)

    def test_complete_evidence_requires_manual_review(self):
        report = gates.evaluate(SHA, source(), windows(), human(), actions())
        self.assertEqual(report["decision"], "EVIDENCE_COMPLETE_REVIEW_REQUIRED")
        self.assertTrue(all(x["status"] == "PASS" for x in report["gates"]))

    def test_stale_source_is_not_a_pass(self):
        s = source()
        s["validated_commit"] = "0" * 40
        self.assertEqual(gates.evaluate(SHA, s)["gates"][0]["status"], "BLOCKED")

    def test_broken_semantics_is_not_a_pass(self):
        s = source()
        s["steps"][-1]["passed"] = False
        self.assertEqual(gates.evaluate(SHA, s)["gates"][0]["status"], "BLOCKED")

    def test_windows_simulation_or_wrong_commit_not_accepted(self):
        w = windows()
        w["os"] = "Linux simulator"
        self.assertEqual(gates.evaluate(SHA, windows=w)["gates"][1]["status"], "BLOCKED")
        w["os"] = "Windows"
        w["code_commit"] = "0" * 40
        self.assertEqual(gates.evaluate(SHA, windows=w)["gates"][1]["status"], "BLOCKED")

    def test_windows_failure_classification_required(self):
        w = windows()
        w["breaking_signature"] = "unknown"
        self.assertEqual(gates.evaluate(SHA, windows=w)["gates"][1]["status"], "BLOCKED")

    def test_human_requires_coverage_and_valid_times(self):
        h = human()
        self.assertEqual(gates.human_gate(h)["status"], "PASS")
        h["observations"][0]["diagnosis_seconds"] = 0
        self.assertEqual(gates.human_gate(h)["status"], "BLOCKED")
        h = human()
        h["observations"] = h["observations"][:-1]
        self.assertEqual(gates.human_gate(h)["status"], "BLOCKED")

    def test_ci_zero_job_startup_failure_not_a_pass(self):
        a = actions()
        a["workflow_conclusion"] = "startup_failure"
        a["jobs"] = []
        self.assertEqual(gates.actions_gate(a, SHA)["status"], "BLOCKED")

    def test_ci_missing_matrix_cell_blocks(self):
        a = actions()
        a["jobs"].pop()
        self.assertEqual(gates.actions_gate(a, SHA)["status"], "BLOCKED")

    def test_short_sha_rejected(self):
        with self.assertRaises(ValueError):
            gates.evaluate("1" * 7)


if __name__ == "__main__":
    unittest.main()
