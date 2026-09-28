import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import driftguard


class DriftGuardV61Tests(unittest.TestCase):
    def test_validation_plan_deduplicates_equivalent_commands(self):
        report = {
            "failure_graph_prediction": {
                "ranked_nodes": [
                    {
                        "node_id": "source-component:python/src",
                        "kind": "source-component",
                        "label": "python source · src",
                        "risk": 82,
                        "risk_label": "HIGH",
                        "direct": True,
                        "blast_radius": 4,
                        "reasons": ["source changed"],
                        "validation": "python -m unittest discover -s tests -v",
                    },
                    {
                        "node_id": "component:python",
                        "kind": "component",
                        "label": "python",
                        "risk": 61,
                        "risk_label": "ELEVATED",
                        "direct": False,
                        "blast_radius": 8,
                        "reasons": ["propagated risk"],
                        "validation": "python   -m   unittest discover -s tests -v",
                    },
                    {
                        "node_id": "dependency:python/requests",
                        "kind": "dependency",
                        "label": "requests",
                        "risk": 55,
                        "risk_label": "ELEVATED",
                        "direct": True,
                        "blast_radius": 2,
                        "reasons": ["dependency changed"],
                        "validation": "python -m pip check",
                    },
                ]
            },
            "source_impact": {
                "total_changes": 2,
                "changed_components": ["python/src"],
            },
        }
        plan = driftguard.build_validation_plan(report, 5)
        self.assertEqual(plan["step_count"], 2)
        self.assertEqual(plan["steps"][0]["risk"], 82)
        self.assertEqual(plan["steps"][0]["covered_nodes"], 2)
        self.assertEqual(plan["steps"][1]["command"], "python -m pip check")
        self.assertEqual(plan["coverage"]["covered_risky_nodes"], 3)
        self.assertEqual(plan["source_changes"]["total"], 2)

    def test_validation_plan_respects_limit_and_risk_order(self):
        report = {
            "failure_graph_prediction": {
                "ranked_nodes": [
                    {"node_id": "a", "risk": 90, "risk_label": "HIGH", "direct": True, "blast_radius": 1, "reasons": ["a"], "validation": "cmd-a"},
                    {"node_id": "b", "risk": 70, "risk_label": "ELEVATED", "direct": True, "blast_radius": 2, "reasons": ["b"], "validation": "cmd-b"},
                    {"node_id": "c", "risk": 50, "risk_label": "ELEVATED", "direct": True, "blast_radius": 3, "reasons": ["c"], "validation": "cmd-c"},
                ]
            }
        }
        plan = driftguard.build_validation_plan(report, 2)
        self.assertEqual([x["command"] for x in plan["steps"]], ["cmd-a", "cmd-b"])
        self.assertEqual([x["order"] for x in plan["steps"]], [1, 2])

    def test_validation_plan_has_safe_empty_fallback(self):
        plan = driftguard.build_validation_plan({"failure_graph_prediction": {"ranked_nodes": []}}, 5)
        self.assertEqual(plan["step_count"], 0)
        self.assertEqual(plan["fallback"], "Run the normal project test/build suite.")

    def test_parser_accepts_validate_plan(self):
        parser = driftguard.build_parser()
        args = parser.parse_args(["validate-plan", "--limit", "3", "--json"])
        self.assertEqual(args.command, "validate-plan")
        self.assertEqual(args.limit, 3)
        self.assertTrue(args.json)


    def test_validation_plan_preserves_case_sensitive_commands(self):
        report = {
            "failure_graph_prediction": {
                "ranked_nodes": [
                    {"node_id": "upper", "risk": 60, "risk_label": "ELEVATED", "direct": True, "blast_radius": 1, "reasons": ["upper"], "validation": 'python -m compileall "Src"'},
                    {"node_id": "lower", "risk": 59, "risk_label": "ELEVATED", "direct": True, "blast_radius": 1, "reasons": ["lower"], "validation": 'python -m compileall "src"'},
                ]
            }
        }
        plan = driftguard.build_validation_plan(report, 5)
        self.assertEqual(plan["step_count"], 2)
        self.assertEqual(
            [step["command"] for step in plan["steps"]],
            ['python -m compileall "Src"', 'python -m compileall "src"'],
        )


    def test_render_validation_script_bash(self):
        plan = {
            "steps": [
                {"order": 1, "primary_node": "source-component:python/src", "command": '"/usr/bin/python3" -m unittest discover -s tests -v'},
                {"order": 2, "primary_node": "engine:unreal/5.6", "command": "Compile the affected Unreal Editor target/module for the pinned engine, then run relevant automation tests"},
            ]
        }
        script = driftguard.render_validation_script(plan, "bash")
        self.assertIn('PYTHON_BIN="', script)
        self.assertIn('"$PYTHON_BIN" -m unittest discover -s tests -v', script)
        self.assertIn("# MANUAL: Compile the affected Unreal Editor", script)

    def test_render_validation_script_powershell(self):
        plan = {
            "steps": [
                {"order": 1, "primary_node": "source-component:python/pkg", "command": '"/usr/bin/python3" -m compileall -q -f "pkg"'},
                {"order": 2, "primary_node": "dependency:node/pkg", "command": "npm test"},
            ]
        }
        script = driftguard.render_validation_script(plan, "powershell")
        self.assertIn('$Python = if ($env:PYTHON)', script)
        self.assertIn("& $Python -m compileall -q -f 'pkg'", script)
        self.assertIn("npm test", script)
        self.assertIn("if ($LASTEXITCODE -ne 0)", script)

    def test_validation_script_rejects_shell_metacharacters(self):
        self.assertIsNone(
            driftguard._portable_validation_command('node --check "src/app.js;rm -rf /"', "bash")
        )

    def test_parser_accepts_validation_script(self):
        parser = driftguard.build_parser()
        args = parser.parse_args(["validation-script", "--shell", "powershell", "--limit", "4", "-o", "plan.ps1"])
        self.assertEqual(args.command, "validation-script")
        self.assertEqual(args.shell, "powershell")
        self.assertEqual(args.limit, 4)
        self.assertEqual(args.output, "plan.ps1")


    def test_validation_argv_python_compileall(self):
        argv = driftguard._validation_argv('"/opt/python" -m compileall -q -f "src"')
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(argv[1:], ["-m", "compileall", "-q", "-f", "src"])

    def test_validation_argv_rejects_shell_control(self):
        self.assertIsNone(driftguard._validation_argv('node --check "src/a.js;rm -rf /"'))

    def test_prepare_validation_execution_marks_manual_steps(self):
        plan = {
            "steps": [
                {"order": 1, "primary_node": "a", "risk": 50, "risk_label": "ELEVATED", "command": "npm test"},
                {"order": 2, "primary_node": "b", "risk": 40, "risk_label": "GUARDED", "command": "Run the engine editor validation manually"},
            ]
        }
        prepared = driftguard.prepare_validation_execution(plan)
        self.assertEqual(prepared["executable_steps"], 1)
        self.assertEqual(prepared["manual_steps"], 1)
        self.assertTrue(prepared["steps"][0]["executable"])
        self.assertFalse(prepared["steps"][1]["executable"])

    def test_execute_validation_plan_uses_direct_argv(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plan = {
                "steps": [
                    {"order": 1, "primary_node": "a", "risk": 50, "risk_label": "ELEVATED", "command": "git --version"},
                ]
            }
            original = driftguard.subprocess.run
            seen = []
            class Dummy:
                returncode = 0
                stdout = "git version test"
                stderr = ""
            def fake_run(argv, **kwargs):
                seen.append((argv, kwargs))
                return Dummy()
            driftguard.subprocess.run = fake_run
            try:
                result = driftguard.execute_validation_plan(root, plan, timeout_seconds=15)
            finally:
                driftguard.subprocess.run = original
            self.assertEqual(seen[0][0], ["git", "--version"])
            self.assertNotIn("shell", seen[0][1])
            self.assertTrue(result["passed"])
            self.assertTrue(result["complete"])
            self.assertEqual(result["results"][0]["status"], "passed")

    def test_parser_accepts_validate_run(self):
        parser = driftguard.build_parser()
        args = parser.parse_args(["validate-run", "--limit", "3", "--timeout", "45", "--execute", "--save", "--json"])
        self.assertEqual(args.command, "validate-run")
        self.assertEqual(args.limit, 3)
        self.assertEqual(args.timeout, 45)
        self.assertTrue(args.execute)
        self.assertTrue(args.save)
        self.assertTrue(args.json)


if __name__ == "__main__":
    unittest.main()
