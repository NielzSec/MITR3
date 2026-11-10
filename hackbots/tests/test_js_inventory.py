import importlib.util
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hb_js", BASE / "tools" / "js_inventory.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "hackbots").mkdir()

    def scan(self, relative, **kwargs):
        with patch.object(module, "ROOT", self.root):
            return module.scan(relative, **kwargs)

    def test_static_literal(self):
        data = module.scan("hackbots/examples/sample.js")
        self.assertEqual(len(data["references"]), 1)
        self.assertEqual(data["references"][0]["path"], "/{route-1}")
        self.assertEqual(data["references"][0]["line"], 3)

    def test_line_numbers_use_only_lf_like_execution_verifier(self):
        (self.root / "input.js").write_text("// synthetic\rfetch('/one');\u2028fetch('/two');\nfetch('/three');")
        result = self.scan("input.js")
        self.assertEqual([r["line"] for r in result["references"]], [1, 1, 2])

    def test_denies_outside_workspace(self):
        with self.assertRaises(ValueError):
            module.scan("../../etc/passwd")

    def test_abs_path_forbidden(self):
        with self.assertRaises(ValueError):
            module.scan("/etc/passwd")

    def test_symlink_file_and_parent_are_rejected(self):
        folder = self.root / "real"
        folder.mkdir()
        (folder / "input.js").write_text("fetch('/synthetic')")
        (self.root / "alias").symlink_to(folder, target_is_directory=True)
        (self.root / "link.js").symlink_to(folder / "input.js")
        for name in ("alias/input.js", "link.js"):
            with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                self.scan(name)

    def test_invalid_paths(self):
        for name in ("", ".", "\x00", None, "../input.js"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.scan(name)

    def test_directory_and_missing_file_are_rejected(self):
        (self.root / "folder").mkdir()
        for name in ("folder", "missing.js"):
            with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                self.scan(name)

    def test_limit_and_original_byte_hash(self):
        raw = b"fetch('/synthetic?private=value#fragment');\r\n"
        (self.root / "input.js").write_bytes(raw)
        with patch.object(module, "MAX_BYTES", len(raw)):
            result = self.scan("input.js", save_private=True)
            private = json.loads((self.root / "hackbots/private" / (result["report_id"] + ".json")).read_text())
            self.assertEqual(private["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(private["references"][0]["path"], "/synthetic")
        with patch.object(module, "MAX_BYTES", len(raw) - 1), self.assertRaises(ValueError):
            self.scan("input.js")

    def test_growth_after_stat_is_bounded(self):
        (self.root / "input.js").write_bytes(b" " * 65)
        real_fstat = os.fstat
        def stale_size(fd):
            info = list(real_fstat(fd))
            info[6] = 1
            return os.stat_result(info)
        with patch.object(module, "MAX_BYTES", 64), patch.object(module.os, "fstat", stale_size):
            with self.assertRaises(ValueError):
                self.scan("input.js")

    def test_invalid_utf8_is_rejected(self):
        (self.root / "input.js").write_bytes(b"\xff")
        with self.assertRaises(UnicodeError):
            self.scan("input.js")

    def test_fifo_does_not_hang(self):
        os.mkfifo(self.root / "input.js")
        code = ("import sys; from pathlib import Path; "
                "sys.path.insert(0, sys.argv[1]); import js_inventory as m; "
                "m.ROOT = Path(sys.argv[2]); sys.argv = ['js_inventory', 'input.js']; "
                "sys.exit(m.main())")
        result = subprocess.run([sys.executable, "-c", code, str(BASE / "tools"), str(self.root)],
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_does_not_echo_sensitive_path(self):
        result = subprocess.run([sys.executable, str(BASE / "tools/js_inventory.py"),
                                 "missing-SYNTHETIC_SECRET.js"], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("SYNTHETIC_SECRET", result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_does_not_echo_unknown_arguments(self):
        result = subprocess.run([sys.executable, str(BASE / "tools/js_inventory.py"),
                                 "hackbots/examples/sample.js", "--SYNTHETIC_SECRET"],
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("SYNTHETIC_SECRET", result.stdout + result.stderr)

    def test_shared_view_redacts_all_path_text_and_source_metadata(self):
        locations = ["/api/users/email@exemplo.com/orders/12345", "/reset/SYNTHETIC_SECRET",
                     "/encoded/%65%6d%61%69%6c", "/matrix;token=SECRET", "/plain-secret"]
        raw = "\n".join(f"fetch('{location}');" for location in locations + locations[:1])
        (self.root / "sensitive-name.js").write_text(raw)
        shared = self.scan("sensitive-name.js", save_private=True)
        serialized = json.dumps(shared)
        for value in locations + ["sensitive-name", hashlib.sha256(raw.encode()).hexdigest()]:
            self.assertNotIn(value, serialized)
        self.assertEqual(shared["visibility"], "shared")
        self.assertEqual(shared["references"][0]["route_id"], shared["references"][-1]["route_id"])
        self.assertEqual(len({r["evidence_id"] for r in shared["references"]}), len(locations) + 1)
        private_path = self.root / "hackbots/private" / (shared["report_id"] + ".json")
        self.assertEqual(private_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(private_path.parent.stat().st_mode & 0o777, 0o700)
        private = json.loads(private_path.read_text())
        self.assertEqual(private["report_id"], shared["report_id"])
        for local, exported in zip(private["references"], shared["references"]):
            self.assertEqual(local["evidence_id"], exported["evidence_id"])
            self.assertEqual(local["route_id"], exported["route_id"])
        self.assertEqual(private["references"][0]["path"], locations[0])

    def test_default_does_not_write_and_report_ids_are_per_run(self):
        (self.root / "input.js").write_text("fetch('/synthetic');")
        first, second = self.scan("input.js"), self.scan("input.js")
        self.assertNotEqual(first["report_id"], second["report_id"])
        self.assertFalse((self.root / "hackbots/private").exists())

    def test_private_report_cannot_overwrite_existing_file(self):
        (self.root / "input.js").write_text("fetch('/synthetic');")
        with patch.object(module.secrets, "token_hex", return_value="a" * 32):
            first = self.scan("input.js", save_private=True)
            path = self.root / "hackbots/private" / (first["report_id"] + ".json")
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                self.scan("input.js", save_private=True)
            self.assertEqual(path.read_bytes(), original)

    def test_private_directory_must_not_be_shared_or_symlinked(self):
        (self.root / "input.js").write_text("fetch('/synthetic');")
        folder = self.root / "hackbots/private"
        folder.mkdir(mode=0o755)
        folder.chmod(0o755)
        with self.assertRaises(ValueError):
            self.scan("input.js", save_private=True)
        folder.rmdir()
        folder.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.scan("input.js", save_private=True)


if __name__ == "__main__":
    unittest.main()
