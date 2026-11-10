"""R2 regressions. The reviewer manifest pin is outside the agent sidecar."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from hackbots.tools import semantic as sem
import test_semantic as fixtures


class HardeningR2Tests(unittest.TestCase):
    setUp = fixtures.SemanticTests.setUp
    put = fixtures.SemanticTests.put
    sha = fixtures.SemanticTests.sha
    update_artifact = fixtures.SemanticTests.update_artifact

    def row(self, rule="jwt_alg_none", refs=None, params=None, idx=0):
        return {"claim_index": idx, "predicate": rule, "evidence_ids": refs or ["E1"],
                "parameters": {} if params is None else params}

    def add_source(self, name="aux.json", artifact=None, eid="E2"):
        self.put(name, self.artifact if artifact is None else artifact)
        self.result["evidence"].append({**self.result["evidence"][0], "id": eid,
                                       "source": name, "sha256": self.sha(name)})
        return {"path": name, "sha256": self.sha(name)}

    def run_rows(self, rows=None, sources=None, manifest_change=None, pin_change=None):
        self.put("mission.json", self.mission)
        self.put("result.json", self.result)
        args = {}
        if sources is not None:
            manifest = {"schema_version": 1, "mission_sha256": self.sha("mission.json"), "sources": sources}
            if manifest_change:
                manifest_change(manifest)
            self.put("sources.json", manifest)
            args = {"sources_manifest_path": self.root / "sources.json",
                    "sources_manifest_sha256": self.sha("sources.json")}
            if pin_change:
                args["sources_manifest_sha256"] = pin_change
        sidecar = None
        if rows is not None:
            self.put("assertions.json", {"schema_version": 1, "result_sha256": self.sha("result.json"),
                                        "mission_sha256": self.sha("mission.json"), "assertions": rows})
            sidecar = self.root / "assertions.json"
        return sem.evaluate(self.root / "result.json", self.root / "mission.json", sidecar, **args)

    def test_d1_trivial_true_fact_cannot_unblock_result(self):
        self.result.update(status="blocked", coverage={"expected": 7, "analyzed": 4})
        report = self.run_rows([self.row("http_200_declared")])
        self.assertEqual(report["completion"], "BLOCKED")
        self.assertEqual(report["semantic_gate"], "BLOCKED")
        self.assertEqual(report["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(report["assertions"][0]["classification"], "CONSISTENT")

    def test_d1_blocked_without_sidecar(self):
        self.result["status"] = "blocked"
        report = self.run_rows()
        self.assertEqual(report["semantic_gate"], "BLOCKED")

    def test_d2_self_pinned_source_is_not_authorized(self):
        self.put("other.json", self.artifact)
        self.result["evidence"][0].update(source="other.json", sha256=self.sha("other.json"))
        report = self.run_rows([self.row()])
        self.assertEqual(report["semantic_gate"], "BLOCKED")
        self.assertEqual(report["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(report["unauthorized_evidence_ids"], ["E1"])
        self.assertEqual(report["assertions"][0]["checks"][0]["reason"], "source_not_authorized")
        self.assertEqual(report["claim_evidence_coverage"][0]["unchecked_evidence_ids"], ["E1"])

    def test_d2_auxiliary_source_pinned_by_reviewer(self):
        source = self.add_source()
        self.result["claims"][0]["evidence_ids"] = ["E1", "E2"]
        report = self.run_rows([self.row(refs=["E1", "E2"])], [source])
        self.assertEqual(report["classification"], "CONSISTENT")
        self.assertEqual(report["source_authorization_gate"], "PASS")

    def test_d2_manifest_rejects_wrong_pin_mission_and_conflicting_digest(self):
        source = self.add_source()
        changes = [
            {"pin_change": "0"*64},
            {"manifest_change": lambda m: m.update(mission_sha256="0"*64)},
            {"manifest_change": lambda m: m.update(schema_version=True)},
            {"manifest_change": lambda m: m["sources"].append(copy.deepcopy(source))},
            {"manifest_change": lambda m: m["sources"][0].update(sha256="0"*64)},
            {"manifest_change": lambda m: m.update(approved=True)},
            {"manifest_change": lambda m: m["sources"][0].update(path="../escape")},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assertEqual(self.run_rows([self.row()], [copy.deepcopy(source)], **change)["classification"],
                                 "STRUCTURALLY_INVALID")

    def test_d2_manifest_requires_explicit_external_pin(self):
        self.run_rows()
        self.put("sources.json", {"schema_version": 1, "mission_sha256": self.sha("mission.json"), "sources": []})
        report = sem.evaluate(self.root/"result.json", self.root/"mission.json",
                              sources_manifest_path=self.root/"sources.json")
        self.assertEqual(report["classification"], "STRUCTURALLY_INVALID")

    def test_d3_authorized_contradiction_omitted_is_visible(self):
        source = self.add_source(artifact={**self.artifact, "jwt_header": "eyJhbGciOiJIUzI1NiJ9"})
        self.result["claims"][0]["evidence_ids"] = ["E1", "E2"]
        report = self.run_rows([self.row()], [source])
        self.assertEqual(report["classification"], "INSUFFICIENT_EVIDENCE")
        coverage = report["claim_evidence_coverage"][0]
        self.assertEqual(coverage["evaluated_evidence_ids"], ["E1"])
        self.assertEqual(coverage["unchecked_evidence_ids"], ["E2"])
        self.assertEqual(coverage["contradictory_evidence_ids"], [])
        # Once evaluated, E2 is contradictory, not merely unchecked.
        report = self.run_rows([self.row(refs=["E1", "E2"])], [source])
        self.assertEqual(report["classification"], "CONTRADICTORY")
        self.assertEqual(report["claim_evidence_coverage"][0]["contradictory_evidence_ids"], ["E2"])

    def test_d2_d3_combined_unauthorized_unselected_source_is_not_hidden(self):
        self.add_source(artifact={**self.artifact, "jwt_header": "eyJhbGciOiJIUzI1NiJ9"})
        self.result["claims"][0]["evidence_ids"] = ["E1", "E2"]
        report = self.run_rows([self.row()])
        self.assertEqual(report["semantic_gate"], "BLOCKED")
        self.assertEqual(report["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(report["unauthorized_evidence_ids"], ["E2"])
        self.assertEqual(report["claim_evidence_coverage"][0]["unchecked_evidence_ids"], ["E2"])

    def test_d3_coverage_is_per_claim_not_global(self):
        source = self.add_source()
        self.result["claims"].append({"text": "other", "evidence_ids": ["E2"]})
        report = self.run_rows([self.row(refs=["E1"]), self.row(refs=["E2"], idx=1)], [source])
        self.assertEqual(report["classification"], "CONSISTENT")
        self.result["claims"][0]["evidence_ids"].append("E2")
        report = self.run_rows([self.row(), self.row(refs=["E2"], idx=1)], [source])
        self.assertEqual(report["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(report["claim_evidence_coverage"][0]["unchecked_evidence_ids"], ["E2"])

    def test_d3_union_of_assertions_covers_claim_evidence(self):
        source = self.add_source()
        self.result["claims"][0]["evidence_ids"] = ["E1", "E2"]
        report = self.run_rows([self.row(), self.row(refs=["E2"])], [source])
        self.assertEqual(report["classification"], "CONSISTENT")
        self.assertEqual(report["claim_evidence_coverage"][0]["unchecked_evidence_ids"], [])

    def openapi(self):
        self.artifact = {"openapi": "3.1.0", "info": {"title": "Synthetic", "version": "1"},
                         "paths": {}, "components": {}}
        self.update_artifact()

    def test_d4_explicit_scoped_predicate_and_deprecated_alias(self):
        self.openapi()
        self.artifact["security"] = [{"apiKey": []}]
        self.update_artifact()
        new = "openapi_components_security_schemes_key_absent"
        self.assertEqual(self.run_rows([self.row(new)])["assertions"][0]["classification"], "CONSISTENT")
        self.assertEqual(self.run_rows([self.row("openapi_security_absent")])["classification"],
                         "INSUFFICIENT_EVIDENCE")

    def test_d4_malformed_or_incomplete_openapi_not_certified(self):
        for doc in [{"openapi": "3.", "components": {}}, {"openapi": "3.1.0", "components": {}},
                    {"openapi": "3.1.0", "info": {"title": "x", "version": "1"}, "paths": []}]:
            self.artifact = doc
            self.update_artifact()
            report = self.run_rows([self.row("openapi_components_security_schemes_key_absent")])
            self.assertEqual(report["classification"], "INSUFFICIENT_EVIDENCE")

    def test_d5_same_numeric_policy_as_evaluator(self):
        # Evaluator intentionally distinguishes integers and Decimal, unlike JSON-value equality.
        builder = Path(sem.__file__).resolve().parents[1] / "skill-builder"
        with patch.object(sys, "path", [str(builder), *sys.path]):
            import skill_evaluator as evaluator
            import skill_builder as sb
            for left, right in [(b"1", b"1.0"), (b"1.0", b"1e0"), (b"true", b"1"),
                                (b"9007199254740992.0", b"9007199254740993.0")]:
                a, b = sb.parse_json(left), sb.parse_json(right)
                self.assertEqual(sem.equal(a, b), evaluator.canonical(a) == evaluator.canonical(b))

    def test_d5_decimal_precision_is_not_lost_in_source_or_sidecar(self):
        self.artifact["n"] = 1.0
        self.update_artifact()
        report = self.run_rows([self.row("json_equals", params={"pointer": "/n", "value": 1})])
        self.assertEqual(report["classification"], "CONTRADICTORY")
        # Both are decimals but different beyond IEEE-754 precision.
        (self.root/"fixture.json").write_bytes(b'{"n":9007199254740992.0}')
        self.mission["artifact"]["sha256"] = self.result["evidence"][0]["sha256"] = self.sha("fixture.json")
        self.run_rows([self.row("json_equals", params={"pointer": "/n", "value": 0.0})])
        raw = (self.root/"assertions.json").read_text().replace('"value": 0.0', '"value": 9007199254740993.0')
        (self.root/"assertions.json").write_text(raw)
        report = sem.evaluate(self.root/"result.json", self.root/"mission.json", self.root/"assertions.json")
        self.assertEqual(report["classification"], "CONTRADICTORY")

    def test_d6_invalid_utf8_is_local_and_valid_claim_survives(self):
        (self.root/"bytes.bin").write_bytes(b"\xff\xfe\n")
        self.result["evidence"].append({**self.result["evidence"][0], "id": "E2", "source": "bytes.bin",
                                       "sha256": self.sha("bytes.bin")})
        self.result["claims"].append({"text": "span", "evidence_ids": ["E2"]})
        source = {"path": "bytes.bin", "sha256": self.sha("bytes.bin")}
        report = self.run_rows([self.row(), self.row("text_span", ["E2"],
                               {"start_line": 1, "end_line": 1, "quote": "x"}, 1)], [source])
        self.assertEqual(report["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual([r["classification"] for r in report["assertions"]], ["CONSISTENT", "INSUFFICIENT_EVIDENCE"])
        self.assertEqual(report["assertions"][1]["checks"][0]["reason"], "source_not_utf8")

    def test_d7_samesite_case_normalized_without_coercion_or_policy_guess(self):
        for same_site in ["none", "None", "NONE", "nOnE"]:
            self.artifact["cookie_attributes"]["same_site"] = same_site
            self.update_artifact()
            self.assertEqual(self.run_rows([self.row("cookie_cross_site_sent",
                             params={"browser_policy": "none_requires_secure"})])["classification"],
                             "CONTRADICTORY")
            self.assertEqual(self.run_rows([self.row("cookie_cross_site_sent")])["classification"],
                             "EXTERNAL_VERIFICATION_REQUIRED")
        self.artifact["cookie_attributes"]["same_site"] = None
        self.update_artifact()
        self.assertEqual(self.run_rows([self.row("cookie_cross_site_sent",
                         params={"browser_policy": "none_requires_secure"})])["classification"],
                         "INSUFFICIENT_EVIDENCE")

    def test_invariants_and_claim_hash_without_disclosing_text(self):
        report = self.run_rows([self.row()])
        self.assertFalse(report["human_approved"])
        self.assertFalse(report["promotable"])
        self.assertEqual(report["text_entailment"], "NOT_VERIFIED")
        self.assertEqual(report["execution_verification"], "NOT_VERIFIED")
        self.assertEqual(report["assertions"][0]["claim_text_sha256"],
                         hashlib.sha256(self.result["claims"][0]["text"].encode()).hexdigest())
        self.assertNotIn("UNTRUSTED", json.dumps(report))

    def test_duplicate_assertion_with_reordered_parameters_rejected(self):
        a = self.row("json_equals", params={"pointer": "/endpoint", "value": "/example"})
        b = self.row("json_equals", params={"value": "/example", "pointer": "/endpoint"})
        self.assertEqual(self.run_rows([a, b])["classification"], "STRUCTURALLY_INVALID")

    def test_exact_numeric_parser_rejects_impossible_exponent(self):
        with self.assertRaises(sem.v.ContractError):
            sem.v.parse_json(b'{"n":1e999999999999999999999999999999}', exact_numbers=True)

    def test_d2_d3_full_regression_without_sidecar(self):
        source = self.add_source()
        self.result["claims"][0]["evidence_ids"] = ["E1", "E2"]
        report = self.run_rows(sources=[source])
        self.assertEqual(report["source_authorization_gate"], "PASS")
        self.assertEqual(report["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(report["claim_evidence_coverage"][0]["unchecked_evidence_ids"], ["E1", "E2"])

    def test_d2_source_in_sidecar_cannot_grant_authority(self):
        self.run_rows([self.row()])
        plan = json.loads((self.root/"assertions.json").read_text())
        plan["sources"] = [{"path": "fixture.json", "sha256": self.sha("fixture.json")}]
        self.put("assertions.json", plan)
        report = sem.evaluate(self.root/"result.json", self.root/"mission.json", self.root/"assertions.json")
        self.assertEqual(report["classification"], "STRUCTURALLY_INVALID")

    def test_d2_external_manifest_pin_is_verified_before_authorization(self):
        source = self.add_source()
        self.result["claims"][0]["evidence_ids"] = ["E1", "E2"]
        self.run_rows([self.row(refs=["E1", "E2"])], [source])
        old_pin = self.sha("sources.json")
        self.put("sources.json", {"schema_version": 1, "mission_sha256": self.sha("mission.json"),
                                  "sources": []})
        report = sem.evaluate(self.root/"result.json", self.root/"mission.json", self.root/"assertions.json",
                              sources_manifest_path=self.root/"sources.json", sources_manifest_sha256=old_pin)
        self.assertEqual(report["classification"], "STRUCTURALLY_INVALID")
