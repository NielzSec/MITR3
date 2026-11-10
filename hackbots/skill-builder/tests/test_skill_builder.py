import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sb_module", BASE / "skill_builder.py")
sb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sb)


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="skill-builder-test-", dir=BASE / "drafts")
        self.old_drafts = sb.DRAFTS
        sb.DRAFTS = Path(self.tmp.name)
        self.data = json.loads((BASE / "examples/js-inventory.method.json").read_text())
        self.data["name"] = "mitr3-hb-fixture"
        self.method = sb.DRAFTS / "fixture.method.json"

    def tearDown(self):
        sb.DRAFTS = self.old_drafts
        self.tmp.cleanup()

    def save(self):
        self.method.write_text(json.dumps(self.data,ensure_ascii=False),encoding="utf8")
        return self.method.relative_to(PROJECT).as_posix()

    def test_happy_path_is_review_not_approved(self):
        outcome = sb.new_draft(self.save())
        self.assertEqual(outcome["state"],"REVIEW")
        self.assertEqual(outcome["checks_required"],4)
        self.assertEqual(outcome["checks_present"],4)
        self.assertEqual(outcome["evals_required"],3)
        self.assertEqual(outcome["evals_executed"],0)
        self.assertFalse(outcome["human_approved"])
        self.assertFalse(outcome["promotable"])
        self.assertLessEqual(len((sb.DRAFTS/self.data["name"]/"SKILL.md").read_text().splitlines()),200)

    def test_fresh_checkout_can_create_and_audit_first_draft(self):
        # Copy only distributable files, never the existing ignored candidate.
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            base = project / "hackbots/skill-builder"
            (base / "drafts").mkdir(parents=True)
            for relative in ("skill_builder.py", "drafts/.gitkeep",
                             "examples/js-inventory.method.json"):
                target = base / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(BASE / relative, target)
            source = project / self.data["source"]["path"]
            source.parent.mkdir(parents=True)
            shutil.copy2(PROJECT / self.data["source"]["path"], source)
            for arguments in (["new", "hackbots/skill-builder/examples/js-inventory.method.json"],
                              ["audit", "mitr3-hb-js-inventory-candidate"]):
                result = subprocess.run([sys.executable, str(base / "skill_builder.py"), *arguments],
                                        cwd=project, capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["state"], "REVIEW")

    def test_prevents_overwrite(self):
        path = self.save()
        sb.new_draft(path)
        with self.assertRaises(sb.GateError):
            sb.new_draft(path)

    def test_detects_skill_tampering(self):
        sb.new_draft(self.save())
        p = sb.DRAFTS/self.data["name"]/"SKILL.md"
        p.write_text(p.read_text().replace("M02","M99"),encoding="utf8")
        outcome = sb.audit(self.data["name"])
        self.assertEqual(outcome["state"],"FAILED")

    def test_detects_manifest_forged_approval(self):
        sb.new_draft(self.save())
        p=sb.DRAFTS/self.data["name"]/"manifest.json"
        data=json.loads(p.read_text())
        data["human_approval"]="self-approved-by-model"
        p.write_text(json.dumps(data))
        self.assertEqual(sb.audit(self.data["name"])["state"],"FAILED")

    def test_missing_negative_eval_blocked(self):
        self.data["evals"]=[self.data["evals"][0]]
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_duplicate_steps_blocked(self):
        self.data["steps"][1]["id"]=self.data["steps"][0]["id"]
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_mismatch_provenance_hash_blocked(self):
        self.data["source"]["sha256"]="0"*64
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_illegal_tool_blocked(self):
        self.data["allowed_tools"]=["shell_root"]
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_path_traversal_blocked(self):
        with self.assertRaises(sb.GateError):
            sb.new_draft("../etc/passwd")
        with self.assertRaises(sb.GateError):
            sb.new_draft("/etc/passwd")

    def test_source_symlink_blocked(self):
        target = PROJECT / self.data["source"]["path"]
        link=sb.DRAFTS/"linked-method.json"
        link.symlink_to(target)
        with self.assertRaises(sb.GateError):
            sb.within_project(link.relative_to(PROJECT).as_posix())

    def test_unknown_methodology_fields_blocked(self):
        self.data["execute_shell"]="yes"
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_approval_not_allowed_in_methodology(self):
        self.data["source"]["approved_by_operator"]=True
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_draft_extra_file_blocked(self):
        sb.new_draft(self.save())
        p=sb.DRAFTS/self.data["name"]/"payload.sh"
        p.write_text("#!/bin/sh\necho unsafe\n")
        with self.assertRaises(sb.GateError):
            sb.audit(self.data["name"])

    def test_name_injection_blocked(self):
        self.data["name"]="../../oops"
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_missing_evidence_field_blocked(self):
        del self.data["steps"][0]["evidence"]
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_parent_drafts_symlink_blocked(self):
        old=sb.DRAFTS
        link=Path(self.tmp.name)/"link"
        link.symlink_to(Path(self.tmp.name),target_is_directory=True)
        sb.DRAFTS=link
        try:
            with self.assertRaises(sb.GateError):
                sb.new_draft(self.save())
        finally:
            sb.DRAFTS=old

    def test_unhashable_tool_is_gate_error(self):
        self.data["allowed_tools"] = [{}]
        with self.assertRaises(sb.GateError):
            sb.new_draft(self.save())

    def test_all_rendered_text_must_be_single_line(self):
        for key in ("inputs", "stop_conditions"):
            for separator in ("\r", "\n", "\u2028", "\x00", "\ud800"):
                with self.subTest(key=key, separator=repr(separator)):
                    data = copy.deepcopy(self.data)
                    data[key] = ["before" + separator + "after"]
                    with self.assertRaises(sb.GateError):
                        sb.validate_spec(data)

    def test_strict_json_rejects_ambiguous_and_nonfinite_values(self):
        for raw in (b'{"x":1,"x":2}', b'{"nested":{"x":1,"x":2}}',
                    b'NaN', b'Infinity', b'-Infinity', b'\xff', b'[' * 2000):
            with self.subTest(raw=raw[:40]), self.assertRaises(sb.GateError):
                sb.parse_json(raw)

    def test_invalid_manifest_shape_blocked(self):
        sb.new_draft(self.save())
        path = sb.DRAFTS / self.data["name"] / "manifest.json"
        original = json.loads(path.read_text())
        for malformed in ([], None, {}, {**original, "approved": True}):
            with self.subTest(manifest=type(malformed)):
                path.write_text(json.dumps(malformed))
                with self.assertRaises(sb.GateError):
                    sb.audit(self.data["name"])

    def test_boolean_eval_runs_is_not_integer_zero(self):
        sb.new_draft(self.save())
        path = sb.DRAFTS / self.data["name"] / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["eval_runs"] = False
        path.write_text(json.dumps(manifest))
        self.assertEqual(sb.audit(self.data["name"])["structural_gate"], "FAIL")

    def test_oversized_draft_file_blocked(self):
        sb.new_draft(self.save())
        (sb.DRAFTS / self.data["name"] / "SKILL.md").write_bytes(b"x" * (sb.MAX_BYTES + 1))
        with self.assertRaises(sb.GateError):
            sb.audit(self.data["name"])

    def test_special_draft_file_does_not_block_reader(self):
        sb.new_draft(self.save())
        path = sb.DRAFTS / self.data["name"] / "SKILL.md"
        path.unlink()
        os.mkfifo(path)
        script = ("import sys; sys.path.insert(0, sys.argv[1]); import skill_builder as sb; "
                  "sb.read_bytes(sb.PROJECT / sys.argv[2])")
        result = subprocess.run([sys.executable, "-c", script, str(BASE), str(path.relative_to(PROJECT))],
                                capture_output=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"GateError", result.stderr)

    def test_draft_directory_cannot_replace_file(self):
        sb.new_draft(self.save())
        path = sb.DRAFTS / self.data["name"] / "manifest.json"
        path.unlink()
        path.mkdir()
        with self.assertRaises(sb.GateError):
            sb.audit(self.data["name"])

    def test_symlink_ancestor_draft_root_blocked(self):
        old = sb.DRAFTS
        (old / "real" / "nested").mkdir(parents=True)
        (old / "alias").symlink_to(old / "real", target_is_directory=True)
        method = self.save()
        sb.DRAFTS = old / "alias" / "nested"
        try:
            with self.assertRaises(sb.GateError):
                sb.new_draft(method)
        finally:
            sb.DRAFTS = old

    def test_safe_reader_rejects_parent_symlink(self):
        target = sb.DRAFTS / "real"
        target.mkdir()
        (target / "input.json").write_text("{}")
        (sb.DRAFTS / "alias").symlink_to(target, target_is_directory=True)
        with self.assertRaises(sb.GateError):
            sb.read_bytes(sb.DRAFTS / "alias" / "input.json")

    def test_original_draft_hashes_stay_pinned(self):
        result = sb.new_draft(self.save())
        directory = sb.DRAFTS / self.data["name"]
        self.assertEqual(result["method_sha256"], hashlib.sha256(self.method.read_bytes()).hexdigest())
        self.assertEqual(result["skill_sha256"], hashlib.sha256((directory / "SKILL.md").read_bytes()).hexdigest())

    def test_cli_malformed_json_returns_blocked_without_traceback(self):
        self.method.write_text('{"allowed_tools":NaN}')
        result = subprocess.run([sys.executable, str(BASE / "skill_builder.py"), "new",
                                 str(self.method.relative_to(PROJECT))], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["state"], "BLOCKED")
        self.assertNotIn("Traceback", result.stderr)


if __name__=="__main__":
    unittest.main()
