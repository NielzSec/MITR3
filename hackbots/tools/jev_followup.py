"""JEV follow-up queue: actionable review without weakening semantic evidence gates.

No network requests, shell execution, approvals or automatic exploitation.
"""
import argparse
import hashlib
import json
from pathlib import Path

def plan(report, *, lab_mode=False):
    """Lab mode is a caller setting, never inferred from the agent's report."""
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    state = report.get("classification", "INSUFFICIENT_EVIDENCE")
    if state not in {"CONSISTENT", "EXTERNAL_VERIFICATION_REQUIRED", "INSUFFICIENT_EVIDENCE",
                     "CONTRADICTORY", "STRUCTURALLY_INVALID"}:
        raise ValueError("invalid classification")
    steps = []
    def add(code, owner, action, gate):
        if code not in {x["code"] for x in steps}:
            steps.append({"code": code, "owner": owner, "action": action, "exit_criterion": gate,
                          "execution": "NOT_STARTED"})
    if report.get("structural_gate") != "PASS" or state == "STRUCTURALLY_INVALID":
        add("REPAIR_CONTRACT", "JEV", "Reconcile mission/result/schema and immutable source hashes",
            "Contract validates and exact source pins match")
    else:
        if report.get("source_authorization_gate") == "BLOCKED" or report.get("unauthorized_evidence_ids"):
            add("PROVENANCE", "REVIEWER", "Independently pin source bytes and authorize sources",
                "Reviewer-controlled manifest SHA256 and independently verified bytes")
        if report.get("unmapped_claims") or not report.get("assertions"):
            add("MAP_CLAIMS", "RESEARCH", "Map each claim to testable typed assertions and independent evidence",
                "Every claim covered by a supported assertion")
        if any(x.get("unchecked_evidence_ids") for x in report.get("claim_evidence_coverage", [])):
            add("COVER_EVIDENCE", "QA", "Evaluate all cited evidence, including contradictions",
                "No unchecked evidence ids remain")
        if state == "CONTRADICTORY":
            add("RESOLVE_CONTRADICTION", "QA", "Preserve counterexamples and rerun controlled local checks",
                "Contradictions explained by independent source and recorded outcome")
        if state in {"EXTERNAL_VERIFICATION_REQUIRED", "INSUFFICIENT_EVIDENCE"} or report.get("execution_verification") != "VERIFIED":
            add("REPRODUCE_CONTROLLED", "LAB", "Reproduce claim in owned/synthetic lab and record positive/negative controls",
                "Reproducible request/response or execution trace with independent hash and environment version")
        if report.get("text_entailment") != "VERIFIED" or report.get("observation_entailment") != "VERIFIED":
            add("VERIFY_IMPACT", "INDEPENDENT_QA", "Compare observed effect to claimed impact and plausible alternatives",
                "Reviewer confirms data/authorization boundary crossed, not status code alone")
        if not lab_mode and not report.get("human_approved"):
            add("HUMAN_GATE", "OPERATOR", "Approve any state-changing production test with object ownership and rollback",
                "Explicit approval for exact target, test identities, object and recovery plan")
    return {
        "schema_version": 1,
        "origin": "JEV_ACTION_QUEUE_V1",
        "source_classification": state,
        "review_status": "ACTION_REQUIRED" if steps else "REVIEW_COMPLETE",
        "semantic_gate_unchanged": report.get("semantic_gate", "UNKNOWN"),
        "promotable": False,
        "auto_execute": False,
        "next_actions": steps,
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("report", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--lab-mode", action="store_true", help="Operator-selected isolated lab or CTF workflow")
    a = p.parse_args()
    b = a.report.read_bytes()
    if len(b) > 1_000_000:
        raise SystemExit("oversize report")
    output = plan(json.loads(b), lab_mode=a.lab_mode)
    output["source_sha256"] = hashlib.sha256(b).hexdigest()
    s = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
    if a.output:
        a.output.write_text(s)
    else:
        print(s, end="")

if __name__ == "__main__":
    main()
