#!/usr/bin/env python3
"""Run DriftGuard's wheel/fixture validation from the exact Git HEAD tree.

Requires Git and local wheel-build prerequisites. No Actions runner needed.
The sanitized result omits captured logs and local filesystem paths.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True).stdout.strip()


def check_head(root, sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Expected a lowercase full 40-character commit SHA")
    if git(root, "rev-parse", "HEAD") != sha:
        raise ValueError("Checkout HEAD does not match the expected commit")
    if git(root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Tracked source tree is dirty; commit or restore changes first")


def run(root, sha):
    check_head(root, sha)
    sys.path.insert(0, str(root / "validation"))
    from validate_source_tree import validate
    with tempfile.TemporaryDirectory(prefix="driftguard-committed-source-") as td:
        temp = Path(td)
        archive = temp / "source.zip"
        subprocess.run(["git", "-C", str(root), "archive", "--format=zip", "-o", str(archive), sha], check=True)
        extracted = temp / ("DriftGuard-" + sha)
        extracted.mkdir()
        with zipfile.ZipFile(archive) as zf:
            # Git archive produced the ZIP from the verified local commit.
            # Reject path traversal even if an attacker substituted the archive.
            for name in zf.namelist():
                path = Path(name)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("Unexpected unsafe path in Git archive")
            zf.extractall(extracted)
        full = validate(extracted, sha, skip_wheel=False)
    return {
        "schema": 1,
        "validated_commit": sha,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "clean git archive from exact, tracked-clean HEAD",
        "platform": full.get("platform"),
        "harness_passed": full["passed"],
        "steps": [{"name": s["name"], "exit_code": s.get("exit_code"),
                   "passed": s.get("ok", s.get("exit_code") == 0)} for s in full["steps"]],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--commit", required=True, help="Full Git commit SHA to validate")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--output", type=Path, required=True, help="Sanitized JSON evidence destination")
    a = ap.parse_args(argv)
    try:
        result = run(a.root.resolve(), a.commit)
    except (ValueError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        print("Source validation could not complete:", str(exc), file=sys.stderr)
        return 2
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("EXACT SOURCE:", "PASS" if result["harness_passed"] else "FAIL")
    print("Evidence:", a.output)
    return 0 if result["harness_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
