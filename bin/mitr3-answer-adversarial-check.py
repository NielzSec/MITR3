#!/usr/bin/env python3
"""Independent offline adverse-input reviewer for MITR3 answer gate.

Synthetic development cases only. Imports the gate/plan_gate functions but
never invokes providers, bridge subprocesses or the hidden blind evaluation.
"""
from __future__ import annotations
import argparse
import copy
import importlib.util
import json
import pathlib
import sys

HERE=pathlib.Path(__file__).resolve().parents[1]
CASES=HERE/"tests/fixtures/answer-gate-adversarial-dev-v1.json"
DEFAULT_TARGET=pathlib.Path.home()/"MITR3/bin/mitr3-answer.py"

def load_target(path:pathlib.Path):
    if not path.is_file():
        raise FileNotFoundError("target file does not exist")
    spec=importlib.util.spec_from_file_location("mitr3_qa_target",path)
    mod=importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    if not hasattr(mod,"gate") or not hasattr(mod,"plan_gate"):
        raise ValueError("target has no gate or plan_gate")
    return mod

def grade_gate(m,case):
    evidence=[]
    for obj in case.get("evidence",[]):
        evidence.append({
            "id":obj["id"],
            "namespace":"attack" if obj.get("namespace")=="attack" else "local",
            "kind":"document",
            "snippet":obj["text"],
            "source_url":obj["source_url"],
            "sha256":obj["sha256"],
        })
    try:
        result=m.gate(copy.deepcopy(case["candidate"]),evidence)
        if not isinstance(result,dict):
            return "invalid_return","INVALID_RETURN"
        return ("abstain" if result.get("abstain") else "pending_human_semantic_review",
            str(result.get("error_code") or result.get("status") or "unknown"))
    except m.AnswerError as ex:
        return "abstain",str(ex)

def grade_plan(m,case):
    plan=copy.deepcopy(case["proposed_plan"])
    # Translate development language label into one supported by implementation,
    # WITHOUT changing entities, query text, expected outcome, or author fixture.
    if plan.get("intent")=="ctf-analysis":
        plan["intent"]="technique"
    try:
        m.plan_gate(plan,case["question"])
        return "accept_query_plan_only","accepted"
    except m.AnswerError as ex:
        return "reject",str(ex)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--target",type=pathlib.Path,default=DEFAULT_TARGET)
    ap.add_argument("--fixture",type=pathlib.Path,default=CASES)
    ap.add_argument("--json",action="store_true")
    args=ap.parse_args()
    mod=load_target(args.target)
    fixture=json.loads(args.fixture.read_text(encoding="utf8"))
    if fixture.get("kind")!="synthetic_development_fixture" or not fixture.get("independent_of_blind_fixture"):
        ap.error("Only the independent synthetic fixture is allowed")
    results=[]
    for case in fixture["cases"]:
        actual,reason=(grade_plan(mod,case) if case["stage"]=="plan" else grade_gate(mod,case))
        passed=actual==case["expected_gate"]
        results.append({"id":case["id"],"stage":case["stage"],
            "expected":case["expected_gate"],"actual":actual,"pass":passed,"reason":reason})
    summary={"total":len(results),"passed":sum(x["pass"] for x in results),
        "failed":sum(not x["pass"] for x in results),
        "fixture_kind":"synthetic_development_fixture",
        "blind_evaluation_used":False,
        "notes":"Semantic entailment is NOT approved by this suite; pending_human_semantic_review requires independent judge.",
        "results":results}
    if args.json:
        print(json.dumps(summary,ensure_ascii=False,indent=2))
    else:
        for row in results:
            print(row["id"],"PASS" if row["pass"] else "FAIL",
                "expected",row["expected"],"actual",row["actual"],"reason",row["reason"])
        print("RESULT:",summary["passed"],"/",summary["total"],"PASS")
    return 0 if summary["failed"]==0 else 1

if __name__=="__main__":
    try:
        raise SystemExit(main())
    except (OSError,ValueError,KeyError,AssertionError) as exc:
        print("ERROR:",type(exc).__name__,str(exc)[:150],file=sys.stderr)
        raise SystemExit(2)

