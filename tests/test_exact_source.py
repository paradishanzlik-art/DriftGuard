"""Exact-source provenance prerequisites using a disposable local Git repo."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

SRC = Path(__file__).resolve().parents[1] / "validation" / "run_exact_source.py"
spec = importlib.util.spec_from_file_location("run_exact_source", SRC)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GitHeadTest(unittest.TestCase):
    def test_commit_mismatch_dirty_tree_and_clean_tree(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", td, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", td, "config", "user.name", "Test"], check=True)
            (root / "app.py").write_text("x = 1\n")
            subprocess.run(["git", "-C", td, "add", "app.py"], check=True)
            subprocess.run(["git", "-C", td, "commit", "-qm", "baseline"], check=True)
            sha = module.git(root, "rev-parse", "HEAD")
            module.check_head(root, sha)
            with self.assertRaisesRegex(ValueError, "does not match"):
                module.check_head(root, "0" * 40)
            with self.assertRaisesRegex(ValueError, "40-character"):
                module.check_head(root, "abc")
            (root / "app.py").write_text("x = 2\n")
            with self.assertRaisesRegex(ValueError, "dirty"):
                module.check_head(root, sha)


if __name__ == "__main__":
    unittest.main()
