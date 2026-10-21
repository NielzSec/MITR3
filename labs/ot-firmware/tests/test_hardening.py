"""Adversarial hardening tests for fwlab extraction and ELF parsing.

This file is additive: it does not modify the implementation under test.
Tests decorated with ``expectedFailure`` reproduce confirmed defects that are
documented in ``docs/REVIEW.md``; the assertions are the *desired* behaviour
and must not be weakened.
"""
import gzip
import io
import os
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwlab import extract as extractmod, formats, inventory as invmod  # noqa: E402

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


# --------------------------------------------------------------------------
# fixture builders
# --------------------------------------------------------------------------

def make_tar(path, entries):
    """entries: iterable of (name, bytes, mode)."""
    with tarfile.open(path, "w:") as tf:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            tf.addfile(info, io.BytesIO(data))


def make_tar_link(path, linkname, target, extra=()):
    with tarfile.open(path, "w:") as tf:
        info = tarfile.TarInfo(linkname)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        tf.addfile(info)
        for name, data, mode in extra:
            finfo = tarfile.TarInfo(name)
            finfo.size = len(data)
            finfo.mode = mode
            tf.addfile(finfo, io.BytesIO(data))


def nest_tars(levels):
    """A tar inside a tar ... *levels* deep, innermost holds leaf.txt."""
    data, name = b"leaf", "leaf.txt"
    for _ in range(levels):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:") as tf:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
        data, name = buf.getvalue(), "inner.tar"
    return data


def _ident(cls, data):
    return b"\x7fELF" + bytes([cls, data, 1]) + b"\x00" * 9


def elf32(e_type=2, machine=40, big=False, shoff=0, shnum=0, shstrndx=0):
    end = ">" if big else "<"
    return _ident(1, 2 if big else 1) + struct.pack(
        end + "HHIIIIIHHHHHH",
        e_type, machine, 1, 0, 52, shoff, 0, 52, 32, 0, 40, shnum, shstrndx,
    )


def elf64(e_type=2, machine=62, big=False, shoff=0, shnum=0, shstrndx=0):
    end = ">" if big else "<"
    return _ident(2, 2 if big else 1) + struct.pack(
        end + "HHIQQQIHHHHHH",
        e_type, machine, 1, 0, 64, shoff, 0, 64, 56, 0, 64, shnum, shstrndx,
    )


def elf32_with_symtab(machine=40, big=False, names=b"\x00.shstrtab\x00.symtab\x00"):
    end = ">" if big else "<"
    shoff = 52
    strtab_off = shoff + 2 * 40
    return (
        elf32(2, machine, big, shoff=shoff, shnum=2, shstrndx=1)
        + b"\x00" * 40
        + struct.pack(end + "IIIIIIIIII", 0, 3, 0, 0, strtab_off, len(names), 0, 0, 1, 0)
        + names
    )


def elf64_with_symtab(machine=62, big=False, names=b"\x00.shstrtab\x00.symtab\x00"):
    end = ">" if big else "<"
    shoff = 64
    strtab_off = shoff + 2 * 64
    return (
        elf64(2, machine, big, shoff=shoff, shnum=2, shstrndx=1)
        + b"\x00" * 64
        + struct.pack(end + "IIQQQQIIQQ", 0, 3, 0, 0, strtab_off, len(names), 0, 0, 1, 0)
        + names
    )


def write(path, blob):
    with open(path, "wb") as fh:
        fh.write(blob)
    return path


# --------------------------------------------------------------------------
# traversal and member-name handling
# --------------------------------------------------------------------------

class TestArchiveTraversal(unittest.TestCase):
    def test_tar_dotdot_inside_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "evil.tar")
            make_tar(p, [("a/../../escape", b"x", 0o644)])
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertIn("traversal", res.get("error", ""))
            self.assertFalse(os.path.exists(os.path.join(td, "escape")))

    def test_tar_backslash_dotdot_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "evil.tar")
            make_tar(p, [("..\\..\\escape", b"x", 0o644)])
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertIn("traversal", res.get("error", ""))
            self.assertFalse(os.path.exists(os.path.join(td, "escape")))

    def test_zip_dotdot_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "evil.zip")
            with zipfile.ZipFile(p, "w") as zf:
                zf.writestr("../escape.txt", "owned")
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertIn("traversal", res.get("error", ""))
            self.assertFalse(os.path.exists(os.path.join(td, "escape.txt")))

    def test_zip_absolute_path_is_contained(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "abs.zip")
            with zipfile.ZipFile(p, "w") as zf:
                zf.writestr("/etc/fwlab-abs-test", "contained")
            dest = os.path.join(td, "out")
            res = extractmod.extract(p, dest)
            self.assertIsNone(res.get("error"))
            self.assertEqual(len(res["written"]), 1)
            self.assertEqual(os.path.commonpath([dest, res["written"][0]]), dest)
            self.assertFalse(os.path.exists("/etc/fwlab-abs-test"))

    def test_zip_symlink_entry_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "link.zip")
            with zipfile.ZipFile(p, "w") as zf:
                info = zipfile.ZipInfo("link")
                info.external_attr = 0o120777 << 16
                zf.writestr(info, "/etc/passwd")
                zf.writestr("real.txt", "ok")
            dest = os.path.join(td, "out")
            res = extractmod.extract(p, dest)
            self.assertEqual(res["written"], [os.path.join(dest, "real.txt")])
            self.assertFalse(os.path.lexists(os.path.join(dest, "link")))


# --------------------------------------------------------------------------
# depth and size budgets
# --------------------------------------------------------------------------

class TestBudgets(unittest.TestCase):
    def test_nested_depth_cap_terminates(self):
        with tempfile.TemporaryDirectory() as td:
            p = write(os.path.join(td, "deep.tar"), nest_tars(8))
            budget = extractmod.Budget({"max_depth": 2})
            res = extractmod.extract(p, os.path.join(td, "out"), budget)

            depth = 1
            node = res
            while node.get("nested"):
                node = node["nested"][0]["result"]
                depth += 1
            self.assertLessEqual(depth, 4)  # depth 0..2 extracted, then one skip node
            self.assertEqual(node.get("skip"), "max depth")
            self.assertEqual(budget.files, 3)  # no payload written past the cap

    def test_gzip_bomb_bounded_by_byte_budget(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "bomb.gz")
            with gzip.open(p, "wb") as fh:
                fh.write(b"\x00" * (4 * 1024 * 1024))
            self.assertLess(os.path.getsize(p), 64 * 1024)  # the bomb is small on disk

            dest = os.path.join(td, "out")
            res = extractmod.extract(p, dest, extractmod.Budget({"max_bytes": 4096}))
            self.assertIn("byte budget", res.get("error", ""))
            self.assertEqual(res["written"], [])
            out = os.path.join(dest, "bomb")
            written = os.path.getsize(out) if os.path.exists(out) else 0
            self.assertLessEqual(written, 4096 + 64 * 1024)  # at most one chunk of overshoot

    def test_file_budget_shared_across_nesting(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "many.tar")
            make_tar(p, [(f"f{i}.gz", gzip.compress(b"x"), 0o644) for i in range(3)])
            res = extractmod.extract(p, os.path.join(td, "out"),
                                      extractmod.Budget({"max_files": 2}))
            self.assertIn("file budget", res.get("error", ""))


# --------------------------------------------------------------------------
# ELF header parsing (synthetic headers, no compiler required)
# --------------------------------------------------------------------------

class TestElfHeaders(unittest.TestCase):
    def _header(self, td, blob):
        return invmod.elf_header(write(os.path.join(td, "bin"), blob))

    def test_elf32_little_endian(self):
        with tempfile.TemporaryDirectory() as td:
            h = self._header(td, elf32(e_type=2, machine=40, big=False))
            self.assertEqual(h["class"], "32")
            self.assertEqual(h["endian"], "little")
            self.assertEqual(h["type"], "exec")
            self.assertEqual(h["machine"], "arm")
            self.assertTrue(h["stripped"])

    def test_elf64_little_endian_with_symtab(self):
        with tempfile.TemporaryDirectory() as td:
            h = self._header(td, elf64_with_symtab(machine=62, big=False))
            self.assertEqual(h["class"], "64")
            self.assertEqual(h["endian"], "little")
            self.assertEqual(h["machine"], "x86_64")
            self.assertFalse(h["stripped"])

    def test_elf32_big_endian_with_symtab(self):
        with tempfile.TemporaryDirectory() as td:
            h = self._header(td, elf32_with_symtab(machine=20, big=True))
            self.assertEqual(h["class"], "32")
            self.assertEqual(h["endian"], "big")
            self.assertEqual(h["machine"], "ppc")  # not byte-swapped (20 -> 5120)
            self.assertFalse(h["stripped"])

    def test_elf64_big_endian_machine(self):
        with tempfile.TemporaryDirectory() as td:
            h = self._header(td, elf64(e_type=3, machine=21, big=True))
            self.assertEqual(h["class"], "64")
            self.assertEqual(h["endian"], "big")
            self.assertEqual(h["type"], "dyn")
            self.assertEqual(h["machine"], "ppc64")
            self.assertTrue(h["stripped"])

    def test_section_headers_absent_means_stripped(self):
        with tempfile.TemporaryDirectory() as td:
            h = self._header(td, elf32(shoff=0, shnum=0, shstrndx=0))
            self.assertTrue(h["stripped"])
            # section-name table exists but does not name .symtab
            h = self._header(td, elf64_with_symtab(names=b"\x00.shstrtab\x00"))
            self.assertTrue(h["stripped"])

    def test_elf_garbage_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(self._header(td, b"not an elf at all"))
            self.assertIsNone(self._header(td, b"\x7fELF" + b"\x00" * 8))
            # section header offset far past EOF must not crash
            h = self._header(td, elf64(shoff=10 ** 9, shnum=2, shstrndx=1))
            self.assertTrue(h["stripped"])


# --------------------------------------------------------------------------
# filesystem edge cases
# --------------------------------------------------------------------------

class TestFilesystemEdges(unittest.TestCase):
    def test_symlink_in_tree_recorded_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "root")
            os.makedirs(root)
            with open(os.path.join(root, "real.txt"), "w") as fh:
                fh.write("hi")
            os.symlink("/etc/passwd", os.path.join(root, "link.txt"))
            os.symlink("/etc", os.path.join(root, "dirlink"))

            inv = invmod.inventory(root)
            by_path = {e["path"]: e for e in inv["entries"]}
            self.assertEqual(by_path["link.txt"]["type"], "symlink")
            self.assertEqual(by_path["link.txt"]["target"], "/etc/passwd")
            self.assertNotIn("sha256", by_path["link.txt"])
            self.assertFalse(any(p.startswith("dirlink/") for p in by_path))

    def test_empty_file_is_unknown_and_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "empty.bin")
            open(p, "wb").close()
            info = formats.detect(p)
            self.assertEqual((info["type"], info["size"], info["confidence"]),
                             ("unknown", 0, "none"))
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertEqual(res["skip"], "not an archive")
            self.assertIsNone(res.get("error"))

    def test_empty_zip_archive_is_clean_noop(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "empty.zip")
            with zipfile.ZipFile(p, "w"):
                pass
            info = formats.detect(p)
            self.assertEqual(info["type"], "zip")
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertEqual(res["written"], [])
            self.assertEqual(res["nested"], [])
            self.assertIsNone(res.get("error"))


# --------------------------------------------------------------------------
# confirmed defects (documented in docs/REVIEW.md)
# --------------------------------------------------------------------------

class TestConfirmedDefects(unittest.TestCase):
    def test_preexisting_symlink_in_dest_does_not_escape(self):
        """H1: containment is lexical; a symlink already in dest redirects writes."""
        with tempfile.TemporaryDirectory() as td:
            outside = os.path.join(td, "outside")
            dest = os.path.join(td, "out")
            os.makedirs(outside)
            os.makedirs(dest)
            os.symlink(outside, os.path.join(dest, "sub"))

            p = os.path.join(td, "plant.tar")
            make_tar(p, [("sub/evil.txt", b"pwn", 0o644)])
            res = extractmod.extract(p, dest)
            self.assertIsNone(res.get("error"))
            self.assertFalse(os.path.exists(os.path.join(outside, "evil.txt")))

    def test_corrupt_containers_return_error(self):
        """H2: zip/gzip/tar parse errors escape as tracebacks, not {'error': ...}."""
        cases = {}

        with tempfile.TemporaryDirectory() as td:
            zp = os.path.join(td, "trunc.zip")
            with zipfile.ZipFile(zp, "w") as zf:
                zf.writestr("a.txt", "hello" * 100)
            with open(zp, "rb") as f:
                cases["zip"] = write(os.path.join(td, "trunc2.zip"), f.read(30))
            cases["gzip"] = write(os.path.join(td, "bad.gz"),
                                  b"\x1f\x8b\x08" + b"garbagegarbage")
            bad_tar = bytearray(1024)
            bad_tar[0:8] = b"notzero!"
            bad_tar[148:156] = b"0000000\x00"
            bad_tar[257:262] = b"ustar"
            cases["tar"] = write(os.path.join(td, "bad.tar"), bytes(bad_tar))

            failures = []
            for label, path in cases.items():
                out = os.path.join(td, "out-" + label)
                try:
                    res = extractmod.extract(path, out)
                except Exception as exc:  # noqa: BLE001 - the defect under test
                    failures.append(f"{label}: raised {type(exc).__name__}: {exc}")
                    continue
                if "error" not in res:
                    failures.append(f"{label}: returned {res!r}")
            self.assertEqual(failures, [], "\n".join(failures))

    def test_relative_symlink_with_dotdot_does_not_abort(self):
        """H3: a benign '../' symlink aborts the archive instead of being skipped."""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "links.tar")
            make_tar_link(p, "lib/link", "../shared/libc.so", extra=[("keep.txt", b"ok", 0o644)])
            dest = os.path.join(td, "out")
            res = extractmod.extract(p, dest)
            self.assertIsNone(res.get("error"))
            self.assertTrue(os.path.exists(os.path.join(dest, "keep.txt")))

    @unittest.skipIf(IS_ROOT, "root can read mode-0100 files")
    def test_execute_only_member_does_not_crash_extract(self):
        """H4a: mode 0100 survives extraction, then nested detect() raises."""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "xonly.tar")
            make_tar(p, [("helper", b"\x7fELF" + b"\x00" * 60, 0o100)])
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertIsNone(res.get("error"))

    @unittest.skipIf(IS_ROOT, "root can read mode-0000 files")
    def test_unreadable_file_inventory_does_not_crash(self):
        """H4b: sha256_file() raises PermissionError and aborts the inventory."""
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "root")
            os.makedirs(root)
            write(os.path.join(root, "readable.txt"), b"ok")
            locked = write(os.path.join(root, "locked.bin"), b"secret")
            os.chmod(locked, 0)
            inv = invmod.inventory(root)
            self.assertEqual(inv["files"], 2)

    def test_conflicting_member_paths_return_error(self):
        """H5: file-then-child paths raise FileExistsError instead of an error dict."""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "collide.tar")
            make_tar(p, [("a", b"x", 0o644), ("a/b", b"y", 0o644)])
            res = extractmod.extract(p, os.path.join(td, "out"))
            self.assertIn("error", res)

    def test_empty_tar_detected_as_tar(self):
        """H6: an all-zero (empty) tar matches the 'zeroes' signature first."""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "empty.tar")
            with tarfile.open(p, "w:"):
                pass
            self.assertEqual(formats.detect(p)["type"], "tar")


if __name__ == "__main__":
    unittest.main(verbosity=2)
