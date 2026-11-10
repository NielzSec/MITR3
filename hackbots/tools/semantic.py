"""Offline typed-evidence gate v1. No NLP entailment, execution or promotion.

Review sidecars are untrusted interpretations, not authenticated approvals.
CONSISTENT refers only to a typed proposition checked against pinned source bytes.
"""
import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path

from . import validate as v

SCHEMA = Path(__file__).resolve().parents[1] / "contracts/semantic-assertions.schema.json"
SOURCES_SCHEMA = SCHEMA.with_name("semantic-sources.schema.json")
ORDER = ["CONSISTENT", "EXTERNAL_VERIFICATION_REQUIRED", "INSUFFICIENT_EVIDENCE",
         "CONTRADICTORY", "STRUCTURALLY_INVALID"]
EXTERNAL = {
    "jwt_unsigned_accepted": "server_signature_validation_and_controlled_session",
    "cookie_transport_exposure": "actual_cookie_transport_hsts_and_network_context",
    "session_theft_confirmed": "cookie_storage_script_access_and_session_replay",
    "csrf_confirmed": "browser_cookie_policy_origin_and_server_csrf_behavior",
    "http_request_executed": "independent_request_response_receipt",
    "sqli_confirmed": "controlled_query_effect_and_alternative_explanations",
    "endpoint_exists": "authorized_server_observation",
    "browser_xss_confirmed": "reachable_dom_sink_and_browser_execution",
    "server_ssrf_confirmed": "authorized_runtime_request_and_egress_observation",
    "binary_analyzed": "binary_bytes_tool_identity_and_independent_execution_receipt",
    "tool_executed": "supervisor_owned_tool_execution_receipt",
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def combine(values):
    return max(values, key=ORDER.index) if values else "INSUFFICIENT_EVIDENCE"


def outcome(classification, reason):
    return {"classification": classification, "reason": reason}


def equal(left, right):
    # JSON has booleans distinct from numbers; recursively retain that distinction.
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    return left == right


def pointer(data, path):
    if path == "":
        return data
    if not path.startswith("/") or any(
            "~" in token.replace("~0", "").replace("~1", "") for token in path[1:].split("/")):
        raise v.ContractError("invalid JSON pointer")
    for token in path[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(data, dict) and token in data:
            data = data[token]
        elif isinstance(data, list) and token.isascii() and token.isdigit() and (
                token == "0" or not token.startswith("0")) and int(token) < len(data):
            data = data[int(token)]
        else:
            raise LookupError()
    return data


def object_json(raw):
    obj = v.parse_json(raw, exact_numbers=True)
    if not isinstance(obj, dict):
        raise v.ContractError("object required")
    return obj


def jwt_part(obj, key):
    encoded = obj[key]
    if not isinstance(encoded, str) or not encoded or len(encoded) > 16384:
        raise ValueError()
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in encoded):
        raise ValueError()
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    return object_json(raw)


def decide(rule, params, raw, result):
    if rule in EXTERNAL:
        return outcome("EXTERNAL_VERIFICATION_REQUIRED", EXTERNAL[rule])
    if rule == "analysis_complete":
        complete = result["status"] != "blocked" and (
            result["coverage"]["expected"] == result["coverage"]["analyzed"])
        return outcome("CONSISTENT" if complete and result["coverage"]["expected"] > 0
                       else "CONTRADICTORY" if not complete else "INSUFFICIENT_EVIDENCE",
                       "delivery_status_and_declared_coverage_only_not_observed_execution")
    if rule == "text_span":
        parts = raw.split(b"\n")
        lines = [part + b"\n" for part in parts[:-1]]
        if parts[-1]:
            lines.append(parts[-1])
        start, end = params["start_line"], params["end_line"]
        if not 1 <= start <= end <= len(lines):
            return outcome("INSUFFICIENT_EVIDENCE", "span_outside_source")
        try:
            actual = b"".join(lines[start-1:end]).decode("utf-8")
        except UnicodeDecodeError:
            return outcome("INSUFFICIENT_EVIDENCE", "source_not_utf8")
        return outcome("CONSISTENT" if actual == params["quote"] else "CONTRADICTORY",
                       "exact_source_span_only_not_dataflow_or_exploitability")
    try:
        obj = object_json(raw)
        if rule == "json_equals":
            actual = pointer(obj, params["pointer"])
            return outcome("CONSISTENT" if equal(actual, params["value"]) else "CONTRADICTORY",
                           "typed_value_at_explicit_json_pointer")
        if rule == "jwt_alg_none":
            actual = jwt_part(obj, "jwt_header")
            if "alg" not in actual:
                raise KeyError()
            return outcome("CONSISTENT" if actual["alg"] == "none" else "CONTRADICTORY",
                           "decoded_header_only_not_server_acceptance")
        if rule == "jwt_exp_absent":
            payload = jwt_part(obj, "jwt_payload")
            return outcome("CONSISTENT" if "exp" not in payload else "CONTRADICTORY",
                           "decoded_payload_only_not_lifetime_policy")
        if rule == "jwt_unlimited_lifetime":
            return outcome("INSUFFICIENT_EVIDENCE", "expiration_revocation_and_server_policy_unknown")
        if rule == "cookie_http_only_disabled":
            actual = obj["cookie_attributes"]["http_only"]
            if type(actual) is not bool:
                raise ValueError()
            return outcome("CONSISTENT" if actual is False else "CONTRADICTORY",
                           "declared_flag_only_not_cookie_storage_or_theft")
        if rule == "cookie_cross_site_sent":
            cookies = obj["cookie_attributes"]
            if not isinstance(cookies.get("same_site"), str) or type(cookies.get("secure")) is not bool:
                return outcome("INSUFFICIENT_EVIDENCE", "cookie_attributes_missing_or_invalid")
            if (params.get("browser_policy") == "none_requires_secure"
                    and cookies["same_site"].casefold() == "none" and cookies["secure"] is False):
                return outcome("CONTRADICTORY", "explicit_browser_policy_rejects_none_without_secure")
            return outcome("EXTERNAL_VERIFICATION_REQUIRED",
                           "browser_version_origin_acceptance_and_send_context_unknown")
        if rule == "openapi_security_absent":
            return outcome("INSUFFICIENT_EVIDENCE", "deprecated_ambiguous_predicate_use_scoped_components_check")
        if rule == "openapi_components_security_schemes_key_absent":
            version, info = obj.get("openapi"), obj.get("info")
            if (not isinstance(version, str) or not re.fullmatch(r"3\.[0-9]+\.[0-9]+", version)
                    or not isinstance(info, dict) or not isinstance(obj.get("paths"), dict)
                    or any(not isinstance(info.get(k), str) or not info[k].strip()
                           for k in ("title", "version"))):
                return outcome("INSUFFICIENT_EVIDENCE", "minimum_openapi_document_not_supplied")
            components = obj.get("components")
            if not isinstance(components, dict):
                return outcome("INSUFFICIENT_EVIDENCE", "openapi_components_not_supplied")
            return outcome("CONSISTENT" if "securitySchemes" not in components else "CONTRADICTORY",
                           "components_key_absence_only_not_absence_of_authorization")
        if rule == "http_200_declared":
            actual = obj["observed_response"]["status"]
            return outcome("CONSISTENT" if type(actual) is int and actual == 200 else "CONTRADICTORY",
                           "fixture_declaration_only_not_verified_http_request")
    except (v.ContractError, KeyError, LookupError, ValueError, TypeError, UnicodeError, binascii.Error):
        return outcome("INSUFFICIENT_EVIDENCE", "required_source_fact_missing_or_unreadable")
    raise v.ContractError("unknown predicate")


def validate_parameters(rule, params):
    keys = {"json_equals": {"pointer", "value"}, "text_span": {"start_line", "end_line", "quote"}}
    if not isinstance(params, dict):
        raise v.ContractError("invalid parameters")
    if rule == "cookie_cross_site_sent":
        if params not in ({}, {"browser_policy": "none_requires_secure"}):
            raise v.ContractError("unsupported browser policy")
    elif set(params) != keys.get(rule, set()):
        raise v.ContractError("unexpected parameters")
    if rule == "json_equals":
        if not isinstance(params["pointer"], str) or len(params["pointer"]) > 500:
            raise v.ContractError("invalid JSON pointer")
        try:
            pointer({}, params["pointer"])
        except LookupError:
            pass
    if rule == "text_span":
        if (any(type(params[k]) is not int or not 1 <= params[k] <= 10000
                for k in ("start_line", "end_line")) or params["start_line"] > params["end_line"]
                or not isinstance(params["quote"], str) or not 1 <= len(params["quote"]) <= 65536):
            raise v.ContractError("invalid span")


def allowed_sources(mission, mission_sha256, manifest_path, manifest_pin):
    """The reviewer supplies the pin independently; the assertion sidecar cannot authorize sources."""
    authorized = {mission["artifact"]["path"]: mission["artifact"]["sha256"]}
    if manifest_path is None and manifest_pin is None:
        return authorized, None
    if (manifest_path is None or not isinstance(manifest_pin, str)
            or not re.fullmatch(r"[a-f0-9]{64}", manifest_pin)):
        raise v.ContractError("reviewer manifest and pin required together")
    raw = v.read_local(manifest_path, 1_000_000)
    if digest(raw) != manifest_pin:
        raise v.ContractError("manifest differs from reviewer pin")
    manifest = v.parse_json(raw)
    if (v.check_schema(manifest, v.load_json(SOURCES_SCHEMA))
            or type(manifest["schema_version"]) is not int
            or manifest["mission_sha256"] != mission_sha256 or len(manifest["sources"]) > 31):
        raise v.ContractError("invalid source authorization manifest")
    seen = set()
    for ref in manifest["sources"]:
        path, sha = ref["path"], ref["sha256"]
        if path in seen or (path in authorized and authorized[path] != sha) or v.artifact(path, sha):
            raise v.ContractError("invalid auxiliary source or conflicting pin")
        seen.add(path)
        authorized[path] = sha
    return authorized, digest(raw)


def evaluate(result_path, mission_path, assertions_path=None, *,
             sources_manifest_path=None, sources_manifest_sha256=None):
    report = {
        "schema_version": 1, "gate_revision": "r2", "classification_scope": "TYPED_ASSERTIONS_ONLY",
        "structural_gate": "FAIL", "semantic_gate": "BLOCKED",
        "classification": "STRUCTURALLY_INVALID", "assertions": [], "unmapped_claims": [],
        "claim_evidence_coverage": [], "unauthorized_evidence_ids": [],
        "source_authorization_gate": "NOT_RUN", "numeric_policy": "evaluator_strict_int_decimal_v1",
        "text_entailment": "NOT_VERIFIED", "observation_entailment": "NOT_VERIFIED",
        "execution_verification": "NOT_VERIFIED", "behavioral_gate": "NOT_RUN",
        "independent_review": "NOT_RUN", "human_approved": False, "promotable": False,
    }
    try:
        result_raw = v.read_local(result_path, 1_000_000)
        mission_raw = v.read_local(mission_path, 1_000_000)
        result, mission = v.parse_json(result_raw), v.parse_json(mission_raw)
        if isinstance(result, dict) and any(isinstance(result.get(k), list) and len(result[k]) > 256
                                            for k in ("evidence", "claims")):
            raise v.ContractError("result budget exceeded")
        if v.validate("mission", mission) or v.validate("result", result, mission):
            raise v.ContractError("structural failure")
        blocked = result["status"] == "blocked"
        report.update(result_sha256=digest(result_raw), mission_sha256=digest(mission_raw),
                      completion="BLOCKED" if blocked else "REVIEW_PENDING", structural_gate="PASS")
        authorized, manifest_hash = allowed_sources(mission, digest(mission_raw),
                                                    sources_manifest_path, sources_manifest_sha256)
        if manifest_hash is not None:
            report["sources_manifest_sha256"] = manifest_hash
        evidence = {e["id"]: e for e in result["evidence"]}
        unauthorized = sorted(e["id"] for e in evidence.values()
                              if authorized.get(e["source"]) != e["sha256"])
        report.update(unauthorized_evidence_ids=unauthorized,
                      source_authorization_gate="BLOCKED" if unauthorized else "PASS")
        sources, total_bytes = {}, 0
        # Immutable byte snapshots. Self-pinned evidence never grants mission provenance.
        for ev in evidence.values():
            if ev["source"] not in sources:
                if len(sources) >= 32:
                    raise v.ContractError("source count budget exceeded")
                raw = v.read_local(v.ROOT / ev["source"], 25 * 1024 * 1024)
                total_bytes += len(raw)
                if total_bytes > 25 * 1024 * 1024:
                    raise v.ContractError("source byte budget exceeded")
                sources[ev["source"]] = raw
            if digest(sources[ev["source"]]) != ev["sha256"]:
                raise v.ContractError("source changed")
        schema_raw = v.read_local(SCHEMA, 1_000_000)
        schema = v.parse_json(schema_raw)
        report["runtime_sha256"] = {p.name: digest(v.read_local(p, 1_000_000))
                                    for p in (Path(__file__), Path(v.__file__))}
        report["runtime_sha256"][SCHEMA.name] = digest(schema_raw)
        report["runtime_hash_scope"] = "DISK_FILES_OBSERVED_NOT_LOADED_CODE_ATTESTATION"
        report["source_sha256"] = {e["id"]: e["sha256"] for e in evidence.values()}
        assertions = []
        if assertions_path is not None:
            plan_raw = v.read_local(assertions_path, 1_000_000)
            plan = v.parse_json(plan_raw, exact_numbers=True)
            if v.check_schema(plan, schema) or type(plan["schema_version"]) is not int:
                raise v.ContractError("invalid assertion contract")
            if (plan["result_sha256"] != digest(result_raw)
                    or plan["mission_sha256"] != digest(mission_raw) or len(plan["assertions"]) > 256):
                raise v.ContractError("stale assertion contract")
            assertions = plan["assertions"]
            report["assertions_sha256"] = digest(plan_raw)
        rows, mapped, seen = [], set(), []
        evaluated = {i: set() for i in range(len(result["claims"]))}
        contradictions = {i: set() for i in evaluated}
        for assertion in assertions:
            idx, rule, refs = (assertion[k] for k in ("claim_index", "predicate", "evidence_ids"))
            if type(idx) is not int or not 0 <= idx < len(result["claims"]):
                raise v.ContractError("invalid claim index")
            params = assertion["parameters"]
            validate_parameters(rule, params)
            if len(refs) != len(set(refs)) or not set(refs) <= set(result["claims"][idx]["evidence_ids"]):
                raise v.ContractError("uncited evidence")
            if any(equal(assertion, previous) for previous in seen):
                raise v.ContractError("duplicate assertion")
            seen.append(assertion)
            mapped.add(idx)
            decisions = []
            for ref in refs:
                if ref in unauthorized:
                    decision = outcome("INSUFFICIENT_EVIDENCE", "source_not_authorized")
                else:
                    decision = decide(rule, params, sources[evidence[ref]["source"]], result)
                    evaluated[idx].add(ref)
                    if decision["classification"] == "CONTRADICTORY":
                        contradictions[idx].add(ref)
                decisions.append({"evidence_id": ref, **decision})
            rows.append({"claim_index": idx, "claim_text_sha256": digest(result["claims"][idx]["text"].encode()),
                         "predicate": rule, "evidence_ids": refs,
                         "classification": combine([d["classification"] for d in decisions]), "checks": decisions})
        coverage = []
        for idx, claim in enumerate(result["claims"]):
            cited = set(claim["evidence_ids"])
            coverage.append({"claim_index": idx, "claim_text_sha256": digest(claim["text"].encode()),
                             "cited_evidence_ids": sorted(cited),
                             "evaluated_evidence_ids": sorted(evaluated[idx]),
                             "unchecked_evidence_ids": sorted(cited - evaluated[idx]),
                             "unauthorized_evidence_ids": sorted(cited.intersection(unauthorized)),
                             "contradictory_evidence_ids": sorted(contradictions[idx])})
        unmapped = sorted(set(range(len(result["claims"]))) - mapped)
        classes = [r["classification"] for r in rows]
        if unmapped or not rows or blocked or unauthorized or any(c["unchecked_evidence_ids"] for c in coverage):
            classes.append("INSUFFICIENT_EVIDENCE")
        report.update(assertions=rows, unmapped_claims=unmapped, claim_evidence_coverage=coverage,
                      classification=combine(classes), semantic_gate="BLOCKED" if
                      blocked or unauthorized or "CONTRADICTORY" in classes else "REVIEW_REQUIRED")
    except (v.ContractError, OSError, ValueError, UnicodeError, RecursionError, KeyError, TypeError):
        report.update(classification="STRUCTURALLY_INVALID", semantic_gate="BLOCKED",
                      error="invalid_unsafe_or_inconsistent_inputs")
    return report


def main():
    parser = v.SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("result")
    parser.add_argument("--mission", required=True)
    parser.add_argument("--assertions")
    parser.add_argument("--sources-manifest")
    parser.add_argument("--sources-manifest-sha256")
    args = parser.parse_args()
    report = evaluate(args.result, args.mission, args.assertions,
                      sources_manifest_path=args.sources_manifest,
                      sources_manifest_sha256=args.sources_manifest_sha256)
    print(json.dumps(report, sort_keys=True, indent=2))
    # No exit-zero approval path: even consistent typed facts need text review.
    return 2 if report["classification"] == "STRUCTURALLY_INVALID" else 1


if __name__ == "__main__":
    raise SystemExit(main())
