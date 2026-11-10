import copy
import importlib.util
import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hb_validator", BASE/"tools"/"validate.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mission = json.loads((BASE/"examples"/"mission-offline.json").read_text())
        cls.result = json.loads((BASE/"examples"/"result-review-pending.json").read_text())

    def test_valid_mission(self):
        self.assertEqual(module.validate("mission", self.mission), [])

    def test_valid_pending_result(self):
        self.assertEqual(module.validate("result", self.result, self.mission), [])

    def test_tampered_artifact(self):
        task = copy.deepcopy(self.mission)
        task["artifact"]["sha256"] = "0"*64
        self.assertTrue(module.validate("mission", task))

    def test_path_escape(self):
        task = copy.deepcopy(self.mission)
        task["artifact"]["path"] = "../../etc/passwd"
        self.assertTrue(module.validate("mission", task))

    def test_no_fake_citations(self):
        answer = copy.deepcopy(self.result)
        answer["claims"][0]["evidence_ids"] = ["MISSING"]
        self.assertTrue(module.validate("result", answer))

    def test_no_fake_acceptance(self):
        answer = copy.deepcopy(self.result)
        answer["status"] = "accepted"
        self.assertTrue(module.validate("result", answer))

    def test_coverage_cannot_exceed_total(self):
        answer = copy.deepcopy(self.result)
        answer["coverage"]["analyzed"] = 2
        self.assertTrue(module.validate("result", answer))

    def test_result_mission_mismatch(self):
        answer = copy.deepcopy(self.result)
        answer["mission_id"] = "HB-WRONG"
        self.assertTrue(module.validate("result", answer, self.mission))

    def test_unknown_fields_forbidden(self):
        task = copy.deepcopy(self.mission)
        task["execute_live"] = True
        self.assertTrue(module.validate("mission", task))

    def test_null_authorization_is_not_approval(self):
        self.assertIsNone(self.mission["scope_ref"])
        self.assertEqual(self.mission["mode"], "offline")

    def test_json_rejects_duplicates_nonfinite_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "input.json"
            for payload in (b'{"mode":"online","mode":"offline"}', b'{"x":NaN}',
                            b'{"x":1e9999}', b' ' * 1_000_001):
                with self.subTest(payload=payload[:50]):
                    file.write_bytes(payload)
                    with self.assertRaises(module.ContractError):
                        module.load_json(file)

    def test_contract_fifo_is_rejected_without_hang(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "fifo.json"
            os.mkfifo(file)
            done = subprocess.run([sys.executable, str(BASE / "tools/validate.py"),
                                   "mission", str(file)], capture_output=True, timeout=2)
            self.assertEqual(done.returncode, 1)
            self.assertNotIn(b'Traceback', done.stderr)

    def test_artifact_parent_symlink_hardlink_and_traversal_rejected(self):
        with tempfile.TemporaryDirectory(dir=BASE / "examples") as directory:
            root = Path(directory)
            (root / "real").mkdir()
            file = root / "real/input"
            file.write_bytes(b'a')
            (root / "alias").symlink_to(root / "real")
            sha = hashlib.sha256(b'a').hexdigest()
            rel = root.relative_to(module.ROOT)
            self.assertEqual(module.artifact(str(rel / "real/input"), sha), [])
            self.assertTrue(module.artifact(str(rel / "alias/input"), sha))
            self.assertTrue(module.artifact(str(rel / "real/../real/input"), sha))
            os.link(file, root / "hard")
            self.assertTrue(module.artifact(str(rel / "real/input"), sha))

    def test_falsey_related_mission_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "mission.json"
            file.write_text('{}')
            done = subprocess.run([sys.executable, str(BASE / "tools/validate.py"),
                                   "result", str(BASE / "examples/result-review-pending.json"),
                                   "--mission", str(file)], capture_output=True, timeout=2)
            self.assertEqual(done.returncode, 1)

    def test_unknown_fields_do_not_leak_in_cli_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "input.json"
            file.write_text(json.dumps({**self.mission, 'PRIVATE_CANARY': True}))
            done = subprocess.run([sys.executable, str(BASE / "tools/validate.py"),
                                   "mission", str(file)], capture_output=True, timeout=2)
            self.assertEqual(done.returncode, 1)
            self.assertNotIn(b'PRIVATE_CANARY', done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
