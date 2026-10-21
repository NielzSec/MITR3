import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwlab import diff as diffmod, extract as extractmod, formats, ghidra, inventory as invmod, report  # noqa: E402


def make_tar(path, entries):
    with tarfile.open(path, "w:") as tf:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            tf.addfile(info, io.BytesIO(data))


class TestFormats(unittest.TestCase):
    def test_gzip(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "a.gz")
            with open(p, "wb") as fh:
                fh.write(b"\x1f\x8b\x08\x00rest")
            self.assertEqual(formats.detect(p)["type"], "gzip")

    def test_tar(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "a.tar")
            make_tar(p, [("x.txt", b"hi", 0o644)])
            self.assertEqual(formats.detect(p)["type"], "tar")

    def test_zip(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "a.zip")
            with zipfile.ZipFile(p, "w") as zf:
                zf.writestr("a.txt", "hi")
            self.assertEqual(formats.detect(p)["type"], "zip")

    def test_elf(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "a.bin")
            with open(p, "wb") as fh:
                fh.write(b"\x7fELF" + b"\x00" * 60)
            self.assertEqual(formats.detect(p)["type"], "elf")

    def test_unknown_is_reported(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "a.bin")
            with open(p, "wb") as fh:
                fh.write(b"random bytes here")
            info = formats.detect(p)
            self.assertEqual(info["type"], "unknown")
            self.assertEqual(info["confidence"], "none")


class TestExtract(unittest.TestCase):
    def test_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "evil.tar")
            make_tar(p, [("../escape.txt", b"x", 0o644)])
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertIn("error", res)
            self.assertFalse(os.path.exists(os.path.join(td, "escape.txt")))

    def test_absolute_path_sanitized(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "abs.tar")
            make_tar(p, [("/etc/passwd", b"x", 0o644)])
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertEqual(res.get("error"), None)
            self.assertFalse(os.path.exists("/etc/passwd.lab"))
            self.assertTrue(any("etc/passwd" in w for w in res["written"]))

    def test_symlink_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "link.tar")
            with tarfile.open(p, "w:") as tf:
                info = tarfile.TarInfo("link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/shadow"
                tf.addfile(info)
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertEqual(res.get("written"), [])

    def test_budget_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "big.tar")
            make_tar(p, [(f"f{i}.txt", b"z" * 1000, 0o644) for i in range(5)])
            budget = extractmod.Budget({"max_files": 2})
            res = extractmod.extract(p, os.path.join(td, "out"), budget)
            self.assertIn("error", res)

    def test_nested_gzip_extracted(self):
        import gzip
        with tempfile.TemporaryDirectory() as td:
            inner = os.path.join(td, "note.txt.gz")
            with gzip.open(inner, "wb") as fh:
                fh.write(b"nested")
            p = os.path.join(td, "outer.tar")
            with open(inner, "rb") as fh:
                blob = fh.read()
            make_tar(p, [("note.txt.gz", blob, 0o644)])
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertEqual(res["count"], 1)
            self.assertTrue(res["nested"])
            self.assertTrue(os.path.exists(os.path.join(td, "out", "note.txt.gz.extracted", "note.txt")))


class TestInventoryAndQueue(unittest.TestCase):
    def _tree(self, td):
        root = os.path.join(td, "root")
        os.makedirs(os.path.join(root, "www", "cgi-bin"))
        os.makedirs(os.path.join(root, "etc", "init.d"))
        cgi = os.path.join(root, "www", "cgi-bin", "status.cgi")
        with open(cgi, "wb") as fh:
            fh.write(b"\x7fELF" + b"\x00" * 60)
        os.chmod(cgi, 0o755)
        with open(os.path.join(root, "etc", "init.d", "rcS"), "w") as fh:
            fh.write("#!/bin/sh\necho ok\n")
        return root

    def test_inventory_hashes_and_flags(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td)
            inv = invmod.inventory(root)
            paths = {e["path"]: e for e in inv["entries"]}
            self.assertIn("www/cgi-bin/status.cgi", paths)
            self.assertTrue(paths["www/cgi-bin/status.cgi"]["exec"])
            self.assertEqual(len(paths["www/cgi-bin/status.cgi"]["sha256"]), 64)
            self.assertTrue(paths["etc/init.d/rcS"].get("script"))

    def test_queue_prioritizes_web_elf(self):
        with tempfile.TemporaryDirectory() as td:
            inv = invmod.inventory(self._tree(td))
            q = ghidra.build_queue(inv, min_score=10)
            self.assertEqual(q[0]["path"], "www/cgi-bin/status.cgi")
            self.assertIn("in_web_root", q[0]["reasons"])

    def test_diff_detects_modified(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._tree(td)
            old = invmod.inventory(root)
            with open(os.path.join(root, "www", "cgi-bin", "status.cgi"), "ab") as fh:
                fh.write(b"\x01")
            new = invmod.inventory(root)
            d = diffmod.diff(old, new)
            self.assertEqual(d["counts"]["modified"], 1)
            self.assertEqual(d["modified"][0]["path"], "www/cgi-bin/status.cgi")


class TestReport(unittest.TestCase):
    def test_report_renders_sections(self):
        md = report.build("T", {"path": "/x", "type": "tar", "size": 1},
                          {"root": "/r", "files": 1, "elf_count": 0, "by_ext": {".txt": 1}, "entries": []},
                          [{"score": 40, "path": "a", "arch": "x86_64", "class": "64", "stripped": True, "reasons": ["in_web_root"]}],
                          {"counts": {"added": 0, "removed": 0, "modified": 1}, "modified": [{"path": "a"}]})
        self.assertIn("## Container", md)
        self.assertIn("## Ghidra queue", md)
        self.assertIn("## Version delta", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
