"""Independent adversarial QA; sockets are forbidden and fixtures are synthetic."""
import io
import json
import signal
import socket
import ssl
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from test_js_lab import SITE, entry, lab, scope, scope_data, sourcemap


class IndependentJSLabQA(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        network = patch("socket.create_connection", side_effect=AssertionError("QA forbids sockets"))
        network.start()
        self.addCleanup(network.stop)

    def response(self, body, mime="text/html"):
        response = Mock(status=200)
        response.getheader.side_effect = lambda name, default=None: {"Content-Type": mime}.get(name, default)
        stream = io.BytesIO(body)
        response.read.side_effect = stream.read
        response.read1.side_effect = stream.read
        connection = Mock()
        connection.getresponse.return_value = response
        return connection

    def run_main(self, command, source, limits=None, maps=False):
        scope_file = self.directory / "scope.json"
        scope_file.write_bytes(lab.packed(scope_data(**({"limits": limits} if limits else {}))))
        out = self.directory / "evidence"
        args = [command, str(source), "--scope", str(scope_file), "--out", str(out)]
        if maps:
            args.append("--maps")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            status = lab.main(args)
        return status, json.loads((out / "manifest.json").read_bytes()), out

    def test_dns_rejects_multicast_and_reserved_translation_ranges(self):
        for address in ("224.0.0.1", "239.255.255.250", "ff02::1",
                        "::ffff:0:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe"):
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            answers = [(family, socket.SOCK_STREAM, 6, "", (address, 443))]
            with self.subTest(address=address), patch("socket.getaddrinfo", return_value=answers):
                with patch.object(lab, "PinnedHTTPS", return_value=self.response(b"")) as connection:
                    with self.assertRaisesRegex(lab.LabError, "dns-address-denied"):
                        lab.Fetcher(scope()).get(SITE)
                    connection.assert_not_called()

    def test_numeric_pin_keeps_hostname_verification_and_closes_failed_tls(self):
        connection = lab.PinnedHTTPS("fixture.invalid", 443, "8.8.8.8", 1)
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, ssl.CERT_REQUIRED)
        context = Mock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError("synthetic mismatch")
        connection._context = context
        raw = Mock()
        with patch("socket.create_connection", return_value=raw) as create:
            with self.assertRaises(ssl.SSLCertVerificationError):
                connection.connect()
        create.assert_called_once_with(("8.8.8.8", 443), 1)
        context.wrap_socket.assert_called_once_with(raw, server_hostname="fixture.invalid")
        raw.close.assert_called_once()

    def test_partial_download_keeps_attempt_and_received_byte_counters(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        connection = self.response(b"x" * 30)
        with patch("socket.getaddrinfo", return_value=answers), patch.object(lab, "PinnedHTTPS", return_value=connection):
            status, manifest, out = self.run_main("collect", SITE, limits={"max_file_bytes": 10})
        self.assertEqual(status, 1)
        self.assertIn("download-byte-quota", manifest["gaps"])
        self.assertEqual(manifest["network_requests"], 1)
        self.assertEqual(manifest["network_bytes"], 11)
        self.assertTrue((out / "SHA256SUMS").is_file())

    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "CLI hard deadline requires POSIX")
    def test_cli_deadline_interrupts_stalled_dns_without_connect(self):
        def stalled_dns(*args, **kwargs):
            time.sleep(3)
            return []
        started = time.monotonic()
        with patch("socket.getaddrinfo", side_effect=stalled_dns), patch.object(lab, "PinnedHTTPS") as connection:
            status, manifest, _ = self.run_main("collect", SITE, limits={"max_seconds": 1})
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(status, 1)
        self.assertIn("time-quota", manifest["gaps"])
        self.assertEqual(manifest["network_requests"], 1)
        connection.assert_not_called()

    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "CLI hard deadline requires POSIX")
    def test_deadline_during_audit_write_never_seals_broken_chain(self):
        create = lab.Run.create

        class SlowAudit:
            def __init__(self, stream):
                self.stream = stream

            def __getattr__(self, name):
                return getattr(self.stream, name)

            def write(self, data):
                if json.loads(data)["event"] == "get-requested":
                    time.sleep(3)
                return self.stream.write(data)

        def slow_audit(run, name):
            stream = create(run, name)
            return SlowAudit(stream) if name == "audit.jsonl" else stream

        scope_file = self.directory / "scope.json"
        scope_file.write_bytes(lab.packed(scope_data(limits={"max_seconds": 1})))
        out = self.directory / "evidence"
        with patch.object(lab.Run, "create", slow_audit), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            status = lab.main(["collect", SITE, "--scope", str(scope_file), "--out", str(out)])
        if status == 2:
            self.assertFalse((out / "SHA256SUMS").exists())
            return
        previous = "0" * 64
        for line in (out / "audit.jsonl").read_bytes().splitlines():
            item = json.loads(line)
            sha = item.pop("sha256")
            self.assertEqual(item["previous_sha256"], previous)
            self.assertEqual(lab.digest(lab.packed(item)), sha)
            previous = sha
        self.assertEqual(json.loads((out / "manifest.json").read_bytes())["audit_head_sha256"], previous)

    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "CLI hard deadline requires POSIX")
    def test_deadline_during_artifact_write_never_seals_untracked_file(self):
        create = lab.Run.create

        class SlowArtifact:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def __getattr__(self, name):
                return getattr(self.stream, name)

            def write(self, data):
                self.stream.write(data[:1])
                time.sleep(3)
                return self.stream.write(data[1:])

        def slow_artifact(run, name):
            stream = create(run, name)
            return SlowArtifact(stream) if name.startswith("raw/html-") else stream

        scope_file = self.directory / "scope.json"
        scope_file.write_bytes(lab.packed(scope_data(limits={"max_seconds": 1})))
        out = self.directory / "evidence"
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch.object(lab.Run, "create", slow_artifact), patch("socket.getaddrinfo", return_value=answers):
            with patch.object(lab, "PinnedHTTPS", return_value=self.response(b"<html></html>")):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    status = lab.main(["collect", SITE, "--scope", str(scope_file), "--out", str(out)])
        self.assertEqual(status, 2)
        self.assertFalse((out / "manifest.json").exists())
        self.assertFalse((out / "SHA256SUMS").exists())

    def test_secret_source_map_header_is_denied_and_not_copied_to_metadata(self):
        secret = "SYNTHETIC_MAP_SECRET"
        script = entry("/bundle.js", "gsap.timeline();")
        script["response"]["headers"] = [{"name": "SourceMap", "value": "/map?access_token=" + secret}]
        har = self.directory / "capture.har"
        har.write_bytes(lab.packed({"log": {"entries": [script]}}))
        status, manifest, out = self.run_main("import-har", har, maps=True)
        self.assertEqual(status, 1)
        self.assertEqual([a["kind"] for a in manifest["artifacts"]], ["script"])
        self.assertIn("credential-query-denied", manifest["gaps"])
        for path in out.rglob("*"):
            if path.is_file():
                self.assertNotIn(secret.encode(), path.read_bytes())

    def test_original_byte_budget_keeps_map_and_partial_evidence(self):
        source_map = sourcemap(contents=["x" * 80, "y" * 80], sources=["/a.js", "../../b.js"])
        map_raw = json.dumps(source_map)
        script = "//# sourceMappingURL=a.map"
        body_bytes = len(script.encode()) + len(map_raw.encode())
        budget = 2 * body_bytes + 80
        har = self.directory / "capture.har"
        har.write_bytes(lab.packed({"log": {"entries": [
            entry("/a.js", script), entry("/a.map", map_raw, "application/json")]}}))
        status, manifest, out = self.run_main("import-har", har, limits={"max_bytes": budget}, maps=True)
        self.assertEqual(status, 1)
        self.assertEqual([a["kind"] for a in manifest["artifacts"]], ["script", "map", "original"])
        self.assertEqual(manifest["bytes_written"], body_bytes + 80)
        self.assertEqual(manifest["input_body_bytes"], body_bytes)
        self.assertIn("artifact-byte-quota", manifest["gaps"])
        self.assertEqual(manifest["network_requests"], 0)
        for line in (out / "SHA256SUMS").read_text().splitlines():
            sha, filename = line.split("  ")
            self.assertEqual(lab.digest((out / filename).read_bytes()), sha)


if __name__ == "__main__":
    unittest.main()
