#!/usr/bin/env python3
"""Conservative, offline DriftGuard beta evidence gate checker (Python 3.9+).

Evidence is *claimed*, not cryptographically authenticated. A PASS indicates
internal consistency of submitted evidence, not independent verification.
"""
import argparse
import json
import math
from pathlib import Path
import re
import sys

SHA = re.compile(r"^[0-9a-f]{40}$")
NEEDED = {
    "compile", "unit-regression-suite", "build-wheel", "create-clean-venv",
    "offline-wheel-install", "installed-import-smoke", "installed-cli-smoke",
    "installed-fixture-init", "installed-validate-plan", "installed-validation-script",
    "installed-validate-run-dry", "installed-validate-run-pass",
    "installed-validate-run-breaking", "installed-validation-semantics",
}


def evidence(path):
    if not path:
        return None
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if not isinstance(obj, dict):
            raise ValueError("expected a JSON object")
        return obj
    except (OSError, UnicodeError, ValueError) as exc:
        return {"_invalid": str(exc)}


def gate(kind, passed, detail):
    return {"gate": kind, "status": "PASS" if passed else "BLOCKED", "detail": detail}


def same_commit(data, commit, *keys):
    return any(data.get(key) == commit for key in keys)


def source_gate(data, commit):
    if data is None:
        return gate("source", False, "No current-commit clean-source evidence supplied")
    if "_invalid" in data:
        return gate("source", False, "Unreadable evidence: " + data["_invalid"])
    identity = data.get("identity") or {}
    anchored = same_commit(data, commit, "validated_commit") or (identity.get("expected_commit") == commit and identity.get("commit_hint_match") is True)
    steps = data.get("steps") or []
    by_name = {s.get("name"): s for s in steps if isinstance(s, dict)}
    coverage = NEEDED.issubset(by_name)
    all_ok = all(by_name.get(name, {}).get("passed", by_name.get(name, {}).get("ok")) is True for name in NEEDED)
    summary = data.get("harness_passed", data.get("passed")) is True
    passed = anchored and coverage and all_ok and summary
    return gate("source", passed, "Commit-aligned complete clean-source harness" if passed else "Stale, missing, or failing source harness; required 14 semantic steps and current SHA")


def windows_gate(data, commit):
    if data is None:
        return gate("windows", False, "Native Windows JSON evidence not supplied")
    if "_invalid" in data:
        return gate("windows", False, "Unreadable evidence: " + data["_invalid"])
    checks = (
        data.get("code_commit") == commit,
        data.get("passed") is True,
        data.get("regression_suite_exit") == 0,
        data.get("clean_source_changes") == 0,
        isinstance(data.get("harmless_source_changes"), int) and data["harmless_source_changes"] >= 1,
        data.get("harmless_guard_exit") == 0,
        data.get("harmless_execute_failed_steps") == 0,
        isinstance(data.get("breaking_source_changes"), int) and data["breaking_source_changes"] >= 1,
        data.get("breaking_guard_exit") not in (None, 0),
        data.get("breaking_signature") == "python.syntax",
        "windows" in str(data.get("os", "")).lower(),
    )
    passed = all(checks)
    return gate("windows", passed, "Native Windows suite, guard, and expected break evidence" if passed else "Windows evidence absent, inconsistent, not native, or does not match current commit")


def human_gate(data):
    if data is None:
        return gate("human", False, "Timed participant study results not supplied")
    if "_invalid" in data:
        return gate("human", False, "Unreadable evidence: " + data["_invalid"])
    observations = data.get("observations")
    if not isinstance(observations, list):
        return gate("human", False, "Expected observations array with raw and structured condition timings")
    participants, cases, pairs = set(), set(), set()
    modes_by_case = {}
    modes_by_person = {}
    valid = True
    for obs in observations:
        if not isinstance(obs, dict):
            valid = False
            continue
        p, c, m = obs.get("participant_id"), obs.get("case_id"), obs.get("mode")
        key = (p, c)
        if not isinstance(p, str) or not p or not isinstance(c, str) or not c or m not in ("raw", "structured") or key in pairs:
            valid = False
            continue
        pairs.add(key)
        participants.add(p)
        cases.add(c)
        modes_by_case.setdefault(c, set()).add(m)
        modes_by_person.setdefault(p, set()).add(m)
        for time_key in ("diagnosis_seconds", "action_seconds"):
            v = obs.get(time_key)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
                valid = False
        if not isinstance(obs.get("diagnosis_correct"), bool) or not isinstance(obs.get("action_correct"), bool):
            valid = False
    passed = valid and len(participants) >= 2 and len(cases) >= 10 and all(x == {"raw", "structured"} for x in modes_by_case.values()) and all(x == {"raw", "structured"} for x in modes_by_person.values())
    msg = f"{len(participants)} participants, {len(cases)} cases, {len(observations)} observations; structurally valid but unaudited participant provenance" if passed else "Requires >=2 people, >=10 counterbalanced cases, valid times, and both modes per case/person"
    return gate("human", passed, msg)


def actions_gate(data, commit):
    if data is None:
        return gate("actions", False, "No full GitHub Actions matrix job evidence; startup_failure is not a pass")
    if "_invalid" in data:
        return gate("actions", False, "Unreadable evidence: " + data["_invalid"])
    jobs = data.get("jobs")
    if not isinstance(jobs, list):
        return gate("actions", False, "Expected official 2 OS x 3 Python-version job outcomes")
    expected = {(o, p) for o in ("ubuntu-latest", "windows-latest") for p in ("3.9", "3.11", "3.13")}
    complete = set()
    for job in jobs:
        if isinstance(job, dict) and job.get("conclusion") == "success" and job.get("tests_passed") is True and job.get("wheel_passed") is True:
            complete.add((job.get("matrix_os"), str(job.get("python_version"))))
    passed = data.get("commit_sha") == commit and data.get("workflow_conclusion") == "success" and isinstance(data.get("run_url"), str) and data["run_url"].startswith("https://github.com/") and expected <= complete
    return gate("actions", passed, "Submitted successful six-job matrix (verify run against GitHub independently)" if passed else "Missing successful current-SHA six-job matrix and wheel steps")


def evaluate(commit, source=None, windows=None, human=None, actions=None):
    if not SHA.fullmatch(commit):
        raise ValueError("--commit must be a full lowercase 40-character Git SHA")
    results = [source_gate(source, commit), windows_gate(windows, commit), human_gate(human), actions_gate(actions, commit)]
    return {
        "schema": 1, "target_commit": commit, "decision": "EVIDENCE_COMPLETE_REVIEW_REQUIRED" if all(g["status"] == "PASS" for g in results) else "BETA_GATES_OPEN",
        "note": "Local structural validation only; review provenance and real platform results before tagging or announcing release.",
        "gates": results,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--commit", required=True, help="Exact main/release commit SHA")
    ap.add_argument("--source", help="Current SHA clean-source harness JSON")
    ap.add_argument("--windows", help="Native Windows smoke JSON")
    ap.add_argument("--human", help="Completed counterbalanced human-study JSON")
    ap.add_argument("--actions", help="Official matrix run information, transcribed to JSON")
    ap.add_argument("--output", help="Write the gate report as JSON")
    a = ap.parse_args(argv)
    try:
        result = evaluate(a.commit, evidence(a.source), evidence(a.windows), evidence(a.human), evidence(a.actions))
    except ValueError as exc:
        ap.error(str(exc))
    encoded = json.dumps(result, indent=2) + "\n"
    if a.output:
        Path(a.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["decision"] == "EVIDENCE_COMPLETE_REVIEW_REQUIRED" else 1


if __name__ == "__main__":
    sys.exit(main())
