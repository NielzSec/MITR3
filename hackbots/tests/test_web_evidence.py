"""Web evidence QA is offline metadata consistency, never a real exploit gate."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hackbots.tools import web_evidence

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples/web/portswigger-sqli-manual-20261023.json"


class WebEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_port_swigger_manual_record_is_coherent_not_authenticated(self):
        result = web_evidence.evaluate(self.record)
        self.assertEqual(result["baseline_count"], 3)
        self.assertEqual(result["poc_count"], 20)
        self.assertEqual(result["additional_id_count"], 17)
        self.assertTrue(result["baseline_subset_of_poc"])
        self.assertTrue(result["operator_reported_lab_solved"])
        self.assertEqual(result["evidence_state"], "DIFFERENTIAL_RECORDED_NOT_AUTHENTICATED")
        self.assertEqual(result["behavioral_gate"], "NOT_RUN")
        self.assertFalse(result["promotable"])
        self.assertEqual(result["source_authenticity"], "NOT_VERIFIED_RAW_BODIES_UNAVAILABLE")

    def test_no_increase_never_counts_as_positive(self):
        self.record["responses"][1]["product_ids"] = list(
            self.record["responses"][0]["product_ids"])
        output = web_evidence.evaluate(self.record)
        self.assertEqual(output["evidence_state"], "NO_DIFFERENTIAL_RECORDED")

    def test_mixed_product_sets_are_not_monotonic(self):
        self.record["responses"][1]["product_ids"] = ["99", "100"]
        output = web_evidence.evaluate(self.record)
        self.assertFalse(output["baseline_subset_of_poc"])
        self.assertNotEqual(output["evidence_state"], "DIFFERENTIAL_RECORDED_NOT_AUTHENTICATED")

    def test_non_200_response_is_inconclusive(self):
        self.record["responses"][1]["http_status"] = 403
        out = web_evidence.evaluate(self.record)
        self.assertEqual(out["evidence_state"], "INCONCLUSIVE_RESPONSE_STATUS")

    def test_reject_duplicate_product_ids_and_malformed_hash(self):
        self.record["responses"][1]["product_ids"].append("1")
        with self.assertRaises(web_evidence.EvidenceRejected):
            web_evidence.evaluate(self.record)
        self.record = json.loads(FIXTURE.read_text())
        self.record["responses"][1]["body_sha256"] = "bad"
        with self.assertRaises(web_evidence.EvidenceRejected):
            web_evidence.evaluate(self.record)

    def test_bool_is_not_integer_and_unknown_keys_block(self):
        self.record["responses"][1]["http_status"] = True
        with self.assertRaises(web_evidence.EvidenceRejected):
            web_evidence.evaluate(self.record)
        self.record = json.loads(FIXTURE.read_text())
        self.record["unreviewed_approval"] = True
        with self.assertRaises(web_evidence.EvidenceRejected):
            web_evidence.evaluate(self.record)

    def test_reject_unknown_phases_and_extra_response(self):
        self.record["responses"][0]["phase"] = "poc"
        with self.assertRaises(web_evidence.EvidenceRejected):
            web_evidence.evaluate(self.record)
        self.record = json.loads(FIXTURE.read_text())
        self.record["responses"].append(dict(self.record["responses"][1]))
        with self.assertRaises(web_evidence.EvidenceRejected):
            web_evidence.evaluate(self.record)

    def test_file_read_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source = folder / "record.json"
            source.write_text(FIXTURE.read_text())
            self.assertEqual(web_evidence.evaluate(web_evidence.load_record(source))["baseline_count"], 3)
            link = folder / "link.json"
            link.symlink_to(source)
            with self.assertRaises(web_evidence.EvidenceRejected):
                web_evidence.load_record(link)
            hard = folder / "hard.json"
            os.link(source, hard)
            with self.assertRaises(web_evidence.EvidenceRejected):
                web_evidence.load_record(source)

    def test_file_read_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / "duplicated.json"
            f.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(web_evidence.EvidenceRejected):
                web_evidence.load_record(f)

    def test_sha256_cannot_validate_unavailable_raw_bodies(self):
        out = web_evidence.evaluate(self.record)
        self.assertEqual(out["trace_gate"], "NOT_RUN")
        self.assertEqual(out["independent_review"], "NOT_RUN")
        self.assertFalse(out["human_approved_for_skill"])


if __name__ == "__main__":
    unittest.main()
