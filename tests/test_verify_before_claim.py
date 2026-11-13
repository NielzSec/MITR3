"""Verify-before-claim: a bulletin confirms a finding only with a saved verified bundle."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidence.gate import render_bulletin, report
from evidence.store import OUTPUT_NAME, EvidenceError, EvidenceStore


class Clock:
    def __init__(self):
        self.tick = 0

    def __call__(self):
        self.tick += 1
        return dt.datetime(2026, 11, 13, 4, 0, self.tick, tzinfo=dt.timezone.utc)


class VerifyBeforeClaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, now=Clock())

    def test_claim_without_evidence_is_downgraded(self):
        claimed = self.store.claim(
            category="injection", target="lab.example/items",
            summary="error body differs from the baseline",
        )
        decision = report(self.store, claimed.record.id)
        text = render_bulletin(decision)

        self.assertFalse(decision["confirmed"])
        self.assertEqual(decision["disposition"], "downgraded")
        self.assertEqual(decision["label"], "unverified_lead")
        self.assertEqual(decision["status"], "claimed")
        self.assertNotIn("FINDING CONFIRMED", text)
        self.assertIn(f"UNVERIFIED LEAD {claimed.record.id}", text)

        with self.assertRaises(EvidenceError) as caught:
            self.store.verify(claimed.record.id)
        self.assertEqual(str(caught.exception), "reproduction_incomplete")
        self.assertEqual(self.store.get(claimed.record.id).status, "claimed")

    def test_missing_record_is_rejected(self):
        decision = report(self.store, "evd-" + "ab" * 10)
        text = render_bulletin(decision)
        self.assertFalse(decision["confirmed"])
        self.assertEqual(decision["disposition"], "rejected")
        self.assertEqual(decision["reason"], "no_evidence_record")
        self.assertNotIn("FINDING CONFIRMED", text)

    def test_claim_with_valid_evidence_passes(self):
        claimed = self.store.claim(
            category="injection", target="lab.example/items",
            summary="error body differs from the baseline",
        )
        saved = self.store.save_reproduction(
            claimed.record.id,
            steps=("record the baseline response", "record the response that includes the marker"),
            command="recorded local comparison",
            output="marker present in the saved error body",
            artifacts=(("notes.txt", b"baseline-and-marker\n"),),
        )
        self.assertEqual(saved.status, "claimed")
        held = report(self.store, saved.id)
        self.assertFalse(held["confirmed"])
        self.assertEqual(held["disposition"], "downgraded")

        verified = self.store.verify(saved.id)
        decision = report(self.store, verified.id)
        text = render_bulletin(decision)

        self.assertEqual(verified.status, "verified")
        self.assertTrue(decision["confirmed"])
        self.assertEqual(decision["disposition"], "accepted")
        self.assertEqual(decision["evidence_id"], verified.id)
        self.assertIn(f"FINDING CONFIRMED {verified.id}", text)
        self.assertNotIn("marker present in the saved error body", text)
        self.assertEqual(decision["artifact_refs"], [f"{verified.id}/{OUTPUT_NAME}", f"{verified.id}/notes.txt"])
        self.assertEqual(self.store.artifact_path(verified.id, "notes.txt").read_bytes(), b"baseline-and-marker\n")
        self.assertEqual(os.stat(self.store.artifact_path(verified.id, OUTPUT_NAME)).st_mode & 0o777, 0o600)

    def test_stable_id_and_dedup(self):
        first = self.store.claim(
            category="Injection", target="Lab.Example/items/",
            summary="Error   body differs from the baseline",
        )
        second = EvidenceStore(self.root, now=Clock()).claim(
            category="injection", target="lab.example/items",
            summary="error body differs from the baseline",
        )
        other = self.store.claim(
            category="injection", target="lab.example/other",
            summary="error body differs from the baseline",
        )

        self.assertEqual(first.record.id, second.record.id)
        self.assertTrue(second.deduped)
        self.assertFalse(first.deduped)
        self.assertNotEqual(other.record.id, first.record.id)
        self.assertEqual(len(list((self.root / "records").glob("evd-*.json"))), 2)
        again = self.store.save_reproduction(
            first.record.id, steps=("record the baseline response",), output="marker present",
        )
        same = self.store.save_reproduction(
            first.record.id, steps=("record the baseline response",), output="marker present",
        )
        self.assertEqual(again.id, same.id)
        self.assertEqual(again.output_sha256, same.output_sha256)
        with self.assertRaises(EvidenceError) as caught:
            self.store.save_reproduction(
                first.record.id, steps=("record the baseline response",), output="different saved body",
            )
        self.assertEqual(str(caught.exception), "evidence_conflict")
        self.assertEqual(self.store.get(first.record.id).output, "marker present")

    def test_tampered_or_rejected_record_is_not_confirmed(self):
        claimed = self.store.claim(
            category="injection", target="lab.example/items", summary="error body differs from the baseline",
        )
        self.store.save_reproduction(
            claimed.record.id, steps=("record the baseline response",), output="marker present",
        )
        verified = self.store.verify(claimed.record.id)
        self.store.artifact_path(verified.id, OUTPUT_NAME).write_bytes(b"replaced body")
        downgraded = report(self.store, verified.id)
        self.assertFalse(downgraded["confirmed"])
        self.assertEqual(downgraded["disposition"], "downgraded")

        fresh = self.store.claim(
            category="auth", target="lab.example/session", summary="session marker was not checked",
        )
        path = self.store.record_path(fresh.record.id)
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["status"] = "verified"
        payload["verified_at"] = payload["created_at"]
        path.write_text(json.dumps(payload), encoding="utf-8")
        flagged = report(self.store, fresh.record.id)
        self.assertFalse(flagged["confirmed"])
        self.assertEqual(flagged["disposition"], "downgraded")

        rejected = self.store.reject(fresh.record.id, "operator withdrew the lead")
        decision = report(self.store, rejected.id)
        self.assertFalse(decision["confirmed"])
        self.assertEqual(decision["disposition"], "rejected")
        self.assertEqual(decision["reason"], "operator withdrew the lead")
        self.assertEqual(self.store.get(rejected.id).status, "rejected")
        self.assertNotIn("FINDING CONFIRMED", render_bulletin(decision))

    def test_cli_bulletin_downgrades_then_confirms(self):
        script = ROOT / "bin" / "mitr3-evidence.py"
        store = self.root / "cli"

        def run(*args):
            return subprocess.run(
                [sys.executable, str(script), "--store", str(store), *args],
                check=False, capture_output=True, text=True,
            )

        claimed = run(
            "claim", "--category", "injection", "--target", "lab.example/items",
            "--summary", "error body differs from the baseline",
        )
        self.assertEqual(claimed.returncode, 0, claimed.stderr)
        evidence_id = json.loads(claimed.stdout)["id"]

        lead = run("report", evidence_id)
        self.assertEqual(lead.returncode, 2)
        self.assertIn(f"UNVERIFIED LEAD {evidence_id}", lead.stdout)
        self.assertNotIn("FINDING CONFIRMED", lead.stdout)

        saved = run(
            "save", evidence_id, "--step", "record the baseline response",
            "--output", "marker present in the saved error body",
        )
        self.assertEqual(saved.returncode, 0, saved.stderr)
        still = run("report", evidence_id)
        self.assertEqual(still.returncode, 2)

        verified = run("verify", evidence_id)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        bulletin = run("report", evidence_id)
        self.assertEqual(bulletin.returncode, 0, bulletin.stderr)
        self.assertIn(f"FINDING CONFIRMED {evidence_id}", bulletin.stdout)
        self.assertNotIn("marker present in the saved error body", bulletin.stdout)

        duplicate = run(
            "claim", "--category", "Injection", "--target", "lab.example/items/",
            "--summary", "error   body differs from the baseline",
        )
        body = json.loads(duplicate.stdout)
        self.assertEqual(body["id"], evidence_id)
        self.assertTrue(body["deduped"])
        self.assertEqual(len(list((store / "records").glob("evd-*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
