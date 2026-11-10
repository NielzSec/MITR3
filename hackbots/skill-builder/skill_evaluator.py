#!/usr/bin/env python3
"""Compare offline skill outputs with pinned JSON oracles; never run or approve a skill."""
import argparse
import json
import sys

import skill_builder as sb


def snapshot(relative):
    raw = sb.read_bytes(sb.within_project(relative))
    return sb.parse_json(raw), sb.digest(raw)


def sha(obj, key):
    value = sb.field(obj, key, maxlen=64)
    if not sb.HEX.fullmatch(value):
        raise sb.GateError("invalid SHA256")
    return value


def reference(ref, *, as_json=False):
    sb.require_keys(ref, {"path", "sha256"}, "artifact reference")
    path = sb.field(ref, "path", maxlen=300)
    raw = sb.read_bytes(sb.within_project(path))
    if sb.digest(raw) != sha(ref, "sha256"):
        raise sb.GateError("artifact SHA256 mismatch")
    return sb.parse_json(raw) if as_json else None


def indexed(rows):
    result = {}
    for row in rows:
        eid = sb.field(row, "id", maxlen=3)
        if not sb.CASE.fullmatch(eid) or eid in result:
            raise sb.GateError("invalid or duplicate case ID")
        result[eid] = row
    return result


def canonical(data):
    # Preserve Decimal precision and distinguish booleans, integers and decimals.
    if isinstance(data, dict):
        return (dict, tuple(sorted((key, canonical(value)) for key, value in data.items())))
    if isinstance(data, list):
        return (list, tuple(canonical(value) for value in data))
    return (type(data), data)


def load_suite(path, expected_sha256=None):
    suite, suite_hash = snapshot(path)
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not sb.HEX.fullmatch(expected_sha256):
            raise sb.GateError("invalid reviewer suite SHA256")
        if suite_hash != expected_sha256:
            raise sb.GateError("suite differs from reviewer pin")
    sb.require_keys(suite, {"schema_version", "cases"}, "suite")
    if type(suite["schema_version"]) is not int or suite["schema_version"] != 1:
        raise sb.GateError("unsupported suite version")
    cases = indexed(sb.items(suite, "cases", 16))
    expected = {}
    for eid, case in cases.items():
        sb.require_keys(case, {"id", "kind", "step_ids", "input", "expected"}, "suite case")
        if case["kind"] not in ("positive", "negative"):
            raise sb.GateError("invalid case kind")
        steps = sb.items(case, "step_ids", 16)
        if any(not isinstance(s, str) or not sb.STEP.fullmatch(s) for s in steps) or len(set(steps)) != len(steps):
            raise sb.GateError("invalid or duplicate step mapping")
        reference(case["input"])
        expected[eid] = canonical(reference(case["expected"], as_json=True))
    return cases, expected, suite_hash


def check_run(path, cases, expected, suite_hash, required_name=None):
    run, run_hash = snapshot(path)
    sb.require_keys(run, {"schema_version", "name", "method_sha256", "skill_sha256", "suite_sha256", "cases"}, "run")
    if type(run["schema_version"]) is not int or run["schema_version"] != 1:
        raise sb.GateError("unsupported run version")
    name = sb.field(run, "name", maxlen=64)
    if required_name is not None and name != required_name:
        raise sb.GateError("run belongs to another draft")
    method, audit = sb.inspect_draft(name)
    if audit["structural_gate"] != "PASS":
        raise sb.GateError("draft failed structural audit")
    for key in ("method_sha256", "skill_sha256"):
        if sha(run, key) != audit[key]:
            raise sb.GateError("run is stale or belongs to another draft version")
    if sha(run, "suite_sha256") != suite_hash:
        raise sb.GateError("run uses a different suite")
    declared = {e["id"]: e["kind"] for e in method["evals"]}
    if declared != {eid: case["kind"] for eid, case in cases.items()}:
        raise sb.GateError("suite must match every methodology case and kind")
    mapped = {s for case in cases.values() for s in case["step_ids"]}
    if mapped != {step["id"] for step in method["steps"]}:
        raise sb.GateError("suite must map all and only methodology steps")
    outputs = indexed(sb.items(run, "cases", 16))
    if set(outputs) != set(cases):
        raise sb.GateError("run must supply all and only suite cases")
    results = []
    passing_steps = set()
    for eid, case in cases.items():
        observed = outputs[eid]
        sb.require_keys(observed, {"id", "input_sha256", "output"}, "run case")
        if sha(observed, "input_sha256") != case["input"]["sha256"]:
            raise sb.GateError("run input differs from suite fixture")
        actual = canonical(reference(observed["output"], as_json=True))
        passed = actual == expected[eid]
        if passed:
            passing_steps.update(case["step_ids"])
        results.append({"id": eid, "kind": case["kind"], "output_gate": "PASS" if passed else "FAIL",
                        "step_ids": case["step_ids"], "input": case["input"],
                        "expected": case["expected"], "output": observed["output"]})
    return {"name": name, "run_sha256": run_hash, "method_sha256": audit["method_sha256"],
            "skill_sha256": audit["skill_sha256"], "steps_required": len(method["steps"]),
            "steps_with_passing_outputs": sorted(passing_steps), "cases": results}


def evaluate(name, suite_file, run_file, baseline_file=None, *, suite_sha256=None):
    cases, expected, suite_hash = load_suite(suite_file, suite_sha256)
    current = check_run(run_file, cases, expected, suite_hash, name)
    regression = {"state": "NOT_COMPARED", "regressions": [], "improvements": []}
    if baseline_file is not None:
        baseline = check_run(baseline_file, cases, expected, suite_hash)
        previous = {c["id"]: c["output_gate"] for c in baseline["cases"]}
        regressions = [c["id"] for c in current["cases"] if previous[c["id"]] == "PASS" and c["output_gate"] == "FAIL"]
        improvements = [c["id"] for c in current["cases"] if previous[c["id"]] == "FAIL" and c["output_gate"] == "PASS"]
        regression = {"state": "FAIL" if regressions else "PASS", "baseline_name": baseline["name"],
                      "baseline_run_sha256": baseline["run_sha256"],
                      "baseline_method_sha256": baseline["method_sha256"],
                      "baseline_skill_sha256": baseline["skill_sha256"],
                      "regressions": regressions, "improvements": improvements,
                      "persistent_failures": [c["id"] for c in current["cases"]
                                              if previous[c["id"]] == "FAIL" and c["output_gate"] == "FAIL"],
                      "baseline_outputs_passed": sum(value == "PASS" for value in previous.values()),
                      "baseline_outputs_evaluated": len(previous)}
    passed = sum(c["output_gate"] == "PASS" for c in current["cases"])
    return {**current, "state": "REVIEW" if passed == len(cases) else "FAILED",
            "structural_gate": "PASS", "output_gate": "PASS" if passed == len(cases) else "FAIL",
            "suite_sha256": suite_hash,
            "suite_pin": "MATCH" if suite_sha256 is not None else "NOT_PROVIDED",
            "verifier_sha256": {p.name: sb.digest(sb.read_bytes(p)) for p in
                                (sb.BASE / "skill_builder.py", sb.BASE / "skill_evaluator.py")},
            "outputs_evaluated": len(cases), "outputs_passed": passed,
            "evals_required": len(cases), "evals_executed": 0, "behavioral_gate": "NOT_RUN",
            "human_approved": False, "promotable": False, "regression": regression,
            "limitations": "Exact JSON output comparison only. Oracles and step mappings require independent review. "
                           "Hashes are consistency checks, not authenticity or proof of agent execution. "
                           "No runtime traces, network behavior or human approval are verified."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="candidate draft name")
    parser.add_argument("suite", help="project-relative suite JSON")
    parser.add_argument("run", help="project-relative observed-output bundle JSON")
    parser.add_argument("--baseline", help="recheck a baseline bundle against the identical suite")
    parser.add_argument("--suite-sha256", help="suite digest supplied separately by the reviewer")
    args = parser.parse_args()
    try:
        report = evaluate(args.name, args.suite, args.run, args.baseline, suite_sha256=args.suite_sha256)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return int(report["output_gate"] != "PASS")
    except (sb.GateError, OSError, ValueError, UnicodeError, RecursionError):
        # Input-derived paths or output content may contain secrets; keep diagnostics generic.
        print(json.dumps({"state": "BLOCKED", "error": "Invalid, unsafe or inconsistent evaluation inputs"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
