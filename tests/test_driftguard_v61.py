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


if __name__ == "__main__":
    unittest.main()
