import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import driftguard


def source_snapshot(fp="a"):
    return {
        "project": {"families": ["python"]},
        "project_files": {"pyproject.toml": {"sha256": "p"}},
        "tools": {"python": {"present": True, "version": "Python 3.14", "path": "/python"}},
        "host": {"machine": "x86_64", "gpu": None, "gpu_driver_fingerprint": "g"},
        "native": {"dependency_graph": {"packages": {}, "fingerprint": "d"}, "sdks": {}, "engines": {}, "native_artifacts": {"artifacts": []}},
        "source_manifest": {
            "schema": 1,
            "fingerprint": fp,
            "files": {"src/app.py": {"sha256": fp, "size": 10, "family": "python", "bucket": "src"}},
            "components": {"python/src": {"family": "python", "bucket": "src", "file_count": 1, "fingerprint": fp, "sample_paths": ["src/app.py"], "validation": "python -m unittest discover -s tests -v"}},
        },
    }


class DriftGuardV6Tests(unittest.TestCase):
    def test_source_manifest_fingerprint_changes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            a = driftguard.scan_source_manifest(root)
            (root / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            b = driftguard.scan_source_manifest(root)
            self.assertNotEqual(a["fingerprint"], b["fingerprint"])
            self.assertNotEqual(a["components"]["python/src"]["fingerprint"], b["components"]["python/src"]["fingerprint"])

    def test_failure_graph_contains_source_component(self):
        g = driftguard.build_failure_graph(source_snapshot())
        ids = {n["id"] for n in g["nodes"]}
        self.assertIn("source-component:python/src", ids)
        self.assertTrue(any(e["src"] == "component:python" and e["dst"] == "source-component:python/src" for e in g["edges"]))

    def test_source_delta_reports_changed_file_and_component(self):
        baseline = source_snapshot("a")
        current = source_snapshot("b")
        d = driftguard.source_change_delta(baseline, current)
        self.assertEqual(d["changed"], ["src/app.py"])
        self.assertEqual(d["changed_components"], ["python/src"])
        self.assertEqual(d["total_changes"], 1)

    def test_source_node_change_is_ranked_and_has_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / ".driftguard").mkdir()
            bg = driftguard.build_failure_graph(source_snapshot("a"))
            cg = driftguard.build_failure_graph(source_snapshot("b"))
            report = {"findings": [], "current": {"failure_graph": cg, "project": {"families": ["python"]}}}
            pred = driftguard.failure_graph_prediction(root, report, bg)
            row = next(x for x in pred["ranked_nodes"] if x["node_id"] == "source-component:python/src")
            self.assertGreaterEqual(row["risk"], 48)
            self.assertIn("unittest", row["validation"])

    def test_legacy_graph_neutralizes_new_source_nodes(self):
        legacy = driftguard._build_failure_graph_v5({k: v for k, v in source_snapshot("a").items() if k != "source_manifest"})
        current = driftguard.build_failure_graph(source_snapshot("a"))
        neutral = driftguard._neutralize_missing_source_baseline(legacy, current)
        delta = driftguard.graph_delta(neutral, current)
        self.assertNotIn("source-component:python/src", delta["added_nodes"])
        self.assertNotIn("source-component:python/src", delta["changed_nodes"])

    def test_empty_source_baseline_is_still_valid(self):
        baseline = {"source_manifest": {"files": {}, "components": {}}}
        current = {"source_manifest": {"files": {}, "components": {}}}
        d = driftguard.source_change_delta(baseline, current)
        self.assertTrue(d["baseline_available"])
        self.assertFalse(d["requires_rebaseline"])
        self.assertEqual(d["total_changes"], 0)


    def test_python_compile_validation_forces_recompile(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pkg").mkdir()
            (root / "pkg" / "mod.py").write_text("VALUE = 1\\n", encoding="utf-8")
            cmd = driftguard._source_validation(root, "python", "pkg", ["pkg/mod.py"])
            self.assertIn("compileall", cmd)
            self.assertIn(" -f ", cmd)


if __name__ == "__main__":
    unittest.main()
