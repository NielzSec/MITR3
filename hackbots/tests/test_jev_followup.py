import unittest
from hackbots.tools.jev_followup import plan

class FollowupTests(unittest.TestCase):
    def base(self, **kw):
        return dict(structural_gate="PASS", classification="INSUFFICIENT_EVIDENCE",
                    semantic_gate="REVIEW_REQUIRED", source_authorization_gate="PASS",
                    assertions=[{"predicate":"text_span"}], unmapped_claims=[],
                    claim_evidence_coverage=[], text_entailment="NOT_VERIFIED",
                    observation_entailment="NOT_VERIFIED", execution_verification="NOT_VERIFIED",
                    human_approved=False, **kw)

    def test_pending_becomes_actionable(self):
        p = plan(self.base())
        self.assertEqual(p["review_status"], "ACTION_REQUIRED")
        self.assertIn("REPRODUCE_CONTROLLED", [x["code"] for x in p["next_actions"]])
        self.assertFalse(p["promotable"])
        self.assertFalse(p["auto_execute"])

    def test_blocked_never_becomes_promotable(self):
        p = plan({"classification":"STRUCTURALLY_INVALID","semantic_gate":"BLOCKED"})
        self.assertEqual([x["code"] for x in p["next_actions"]], ["REPAIR_CONTRACT"])
        self.assertFalse(p["promotable"])

    def test_contradictions_exposed(self):
        p = plan({"classification":"CONTRADICTORY","structural_gate":"PASS",
                  "claim_evidence_coverage":[{"unchecked_evidence_ids":["E2"]}]})
        self.assertIn("RESOLVE_CONTRADICTION", [x["code"] for x in p["next_actions"]])
        self.assertIn("COVER_EVIDENCE", [x["code"] for x in p["next_actions"]])

    def test_lab_mode_skips_human_execution_gate_but_keeps_review(self):
        report = self.base()
        local = plan(report, lab_mode=True)
        production = plan(report, lab_mode=False)
        self.assertNotIn("HUMAN_GATE", [s["code"] for s in local["next_actions"]])
        self.assertIn("HUMAN_GATE", [s["code"] for s in production["next_actions"]])
        self.assertIn("VERIFY_IMPACT", [s["code"] for s in local["next_actions"]])
        self.assertFalse(local["promotable"])

    def test_unknown_classification_rejected(self):
        with self.assertRaises(ValueError):
            plan({"classification":"CONFIRMED_RCE"})

if __name__ == "__main__":
    unittest.main()
