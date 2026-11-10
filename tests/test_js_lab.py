"""Offline boundary and end-to-end tests; no external connections or JS execution."""
import base64
import importlib.util
import io
import json
import os
import socket
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("js_lab", ROOT / "bin/mitr3-js-lab.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
SITE = "https://fixture.invalid"


def scope_data(**changes):
    data = {"case_id": "js-lab-test", "operator": "synthetic-fixture",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "allowed_origins": [SITE], "allowed_paths": {SITE: ["/"]},
            "allow_source_maps": True, "retention_days": 7}
    data.update(changes)
    return data


def scope(**changes):
    return lab.Scope(lab.packed(scope_data(**changes)))


def entry(path, text, mime="application/javascript", encoding=None):
    content = {"mimeType": mime, "text": text}
    if encoding:
        content["encoding"] = encoding
    return {"request": {"method": "GET", "url": SITE + path, "headers": [], "cookies": []},
            "response": {"status": 200, "headers": [], "cookies": [], "content": content}}


def sourcemap(contents=None, **changes):
    data = {"version": 3, "sources": ["../../escape.js"], "mappings": "",
            "names": [], "sourcesContent": ["gsap.to('.fixture', {x: 10});"] if contents is None else contents}
    data.update(changes)
    return data


class JSLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.network = patch("socket.create_connection", side_effect=AssertionError("offline tests forbid sockets"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def run_har(self, entries, maps=True, limits=None):
        scope_file = self.directory / "scope.json"
        scope_file.write_bytes(lab.packed(scope_data(**({"limits": limits} if limits else {}))))
        har = self.directory / "capture.har"
        har.write_bytes(lab.packed({"log": {"entries": entries}}))
        out = self.directory / "evidence"
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ["import-har", str(har), "--scope", str(scope_file), "--out", str(out)]
        if maps:
            args.append("--maps")
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = lab.main(args)
        return result, json.loads((out / "manifest.json").read_bytes()), out

    def test_scope_requires_identity_and_expiry(self):
        for data in ({}, scope_data(operator=""), scope_data(case_id="../../x"),
                     scope_data(expires_at="2099-01-01"), scope_data(expires_at="2000-01-01T00:00:00Z")):
            with self.subTest(data=data), self.assertRaises(lab.LabError):
                lab.Scope(lab.packed(data))

    def test_scope_rejects_invalid_limits_and_paths(self):
        for changes in ({"limits": {"max_requests": True}}, {"limits": {"max_bytes": -1}},
                        {"limits": {"max_requests": 999999}}, {"limits": {"unknown": 3}},
                        {"allowed_origins": [SITE + "/some/path"]}):
            with self.subTest(changes=changes), self.assertRaises(lab.LabError):
                scope(**changes)

    def test_url_policy_exact_origin_and_secret_query(self):
        allowed = scope()
        self.assertEqual(allowed.url(SITE.upper() + ":443/a?v=1#fragment"), SITE + "/a?v=1")
        for url in ("http://fixture.invalid/a", "file:///etc/passwd", "javascript:alert(1)",
                    "https://fixture.invalid.attacker.invalid/a", "https://sub.fixture.invalid/a",
                    SITE + ":444/a", SITE + ":0/a", "https://user:pass@fixture.invalid/a", "https://fixture.invalid./",
                    "https://fixture.invalid\\@evil.invalid/a", "https://fixture.invalid/\n",
                    SITE + "/a?access_token=FAKE_SECRET", "https://2130706433/", "https://[::1]/",
                    "https://fíxture.invalid/"):
            with self.subTest(url=url), self.assertRaises(lab.LabError):
                allowed.url(url)

    def test_dns_rebinding_and_private_addresses_rejected_before_connect(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1", "::ffff:8.8.8.8"):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                       (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
            with self.subTest(address=address), patch("socket.getaddrinfo", return_value=answers):
                with patch.object(lab, "PinnedHTTPS") as conn:
                    with self.assertRaisesRegex(lab.LabError, "dns-address-denied"):
                        lab.Fetcher(scope()).get(SITE + "/")
                    conn.assert_not_called()

    def mock_connection(self, status=200, body=b"ok", headers=None):
        values = headers or {"Content-Type": "application/javascript"}
        response = unittest.mock.Mock()
        response.status = status
        response.getheader.side_effect = lambda key, default=None: values.get(key, default)
        stream = io.BytesIO(body)
        response.read1.side_effect = stream.read
        connection = unittest.mock.Mock()
        connection.getresponse.return_value = response
        return connection

    def fetch(self, connection, policy=None):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch("socket.getaddrinfo", return_value=answers), patch.object(lab, "PinnedHTTPS", return_value=connection) as cls:
            result = lab.Fetcher(policy or scope()).get(SITE + "/bundle.js?v=42")
        return result, cls

    def test_fetch_pins_ip_and_sends_no_credentials(self):
        conn = self.mock_connection()
        result, cls = self.fetch(conn)
        self.assertEqual(result[0], b"ok")
        self.assertEqual(cls.call_args.args[:3], ("fixture.invalid", 443, "8.8.8.8"))
        args, kwargs = conn.request.call_args
        self.assertEqual(args, ("GET", "/bundle.js?v=42"))
        self.assertEqual(set(kwargs["headers"]), {"User-Agent", "Accept-Encoding"})
        conn.close.assert_called_once()

    def test_redirects_errors_and_compression_never_followed(self):
        for status in (301, 302, 307, 308, 404, 500):
            conn = self.mock_connection(status=status)
            with self.subTest(status=status), self.assertRaises(lab.LabError):
                self.fetch(conn)
            self.assertEqual(conn.request.call_count, 1)
            conn.close.assert_called_once()
        with self.assertRaisesRegex(lab.LabError, "content-encoding-denied"):
            self.fetch(self.mock_connection(headers={"Content-Encoding": "gzip"}))

    def test_download_and_request_limits(self):
        with self.assertRaises(lab.StopRun):
            self.fetch(self.mock_connection(body=b"x" * 20), scope(limits={"max_file_bytes": 10}))
        fetcher = lab.Fetcher(scope(limits={"max_requests": 1}))
        fetcher.requests = 1
        with self.assertRaisesRegex(lab.StopRun, "request-quota"):
            fetcher.get(SITE + "/")

    def test_expiry_rechecked(self):
        policy = scope()
        policy.expires = datetime.now(timezone.utc) - timedelta(seconds=1)
        with self.assertRaisesRegex(lab.StopRun, "scope-expired"):
            policy.url(SITE)
        policy = scope()
        policy.deadline = 0
        with self.assertRaisesRegex(lab.StopRun, "time-quota"):
            policy.check()

    def test_html_inline_base_preload_types_and_dedup(self):
        html = b'''<base href="/assets/"><script src="app.js?v=1"></script>
        <script src="app.js?v=1"></script><link rel="modulepreload" href="chunk.mjs">
        <script type="application/ld+json">{"ignore": 1}</script>
        <script type="module">gsap.timeline();</script><script src="https://outside.invalid/a.js"></script>'''
        data = {SITE + "/": (html, {"Content-Type": "text/html"}),
                SITE + "/assets/app.js?v=1": (b"gsap.to('.x', {});", {"Content-Type": "text/javascript"}),
                SITE + "/assets/chunk.mjs": (b"export const x=1;", {"Content-Type": "application/javascript"})}
        calls = []
        def get(url):
            calls.append(url)
            return data[url]
        run = lab.Run(self.directory / "html", scope(), "collect", False)
        with patch.object(lab.Fetcher, "get", side_effect=get):
            lab.collect(run, SITE + "/")
        self.assertEqual(run.finish(), 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual([a["kind"] for a in run.artifacts], ["html", "script", "script", "inline"])
        self.assertIn("origin-denied", run.gaps)

    def test_full_har_maps_dependency_gsap_and_checksums(self):
        js = "import('./lazy.js'); gsap.timeline(); ScrollTrigger.create({});\n//# sourceMappingURL=app.js.map"
        result, manifest, out = self.run_har([
            entry("/app.js?cache=SECRET_QUERY_SENTINEL", js),
            entry("/app.js.map", json.dumps(sourcemap()), "application/json"),
            entry("/lazy.js", "export const lazy=1;")])
        self.assertEqual(result, 0)
        self.assertEqual(manifest["network_requests"], 0)
        self.assertEqual([a["kind"] for a in manifest["artifacts"]], ["script", "map", "original", "script"])
        self.assertEqual(len(manifest["artifacts"][0]["gsap_candidates"]), 2)
        self.assertEqual(manifest["dependency_candidates"][0]["resolution"], "in-scope-candidate")
        self.assertNotIn(b"SECRET_QUERY_SENTINEL", (out / "manifest.json").read_bytes())
        self.assertFalse((self.directory / "escape.js").exists())
        for line in (out / "SHA256SUMS").read_text().splitlines():
            sha, name = line.split("  ")
            self.assertEqual(lab.digest((out / name).read_bytes()), sha)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o700)
        for path in out.rglob("*"):
            expected = 0o500 if path.is_dir() else 0o400 if path.parent.name in {"raw", "derived"} else 0o600
            self.assertEqual(os.stat(path).st_mode & 0o777, expected)

    def test_audit_chain_and_no_raw_headers(self):
        _, manifest, out = self.run_har([entry("/app.js", "gsap.to('.x', {});")])
        previous = "0" * 64
        for line in (out / "audit.jsonl").read_bytes().splitlines():
            item = json.loads(line)
            sha = item.pop("sha256")
            self.assertEqual(item["previous_sha256"], previous)
            self.assertEqual(lab.digest(lab.packed(item)), sha)
            previous = sha
        self.assertEqual(previous, manifest["audit_head_sha256"])

    def test_har_session_entries_excluded_without_exposing_values(self):
        entries = []
        for name in ("Authorization", "Cookie", "X-Api-Key"):
            e = entry("/" + name + ".js", "PRIVATE_BODY_SENTINEL")
            e["request"]["headers"] = [{"name": name, "value": "PRIVATE_HEADER_SENTINEL"}]
            entries.append(e)
        e = entry("/cookies.js", "PRIVATE_BODY_SENTINEL")
        e["response"]["cookies"] = [{"name": "id", "value": "PRIVATE_HEADER_SENTINEL"}]
        entries.append(e)
        e = entry("/set-cookie.js", "PRIVATE_BODY_SENTINEL")
        e["response"]["headers"] = [{"name": "Set-Cookie", "value": "PRIVATE_HEADER_SENTINEL"}]
        entries.append(e)
        result, manifest, out = self.run_har(entries)
        self.assertEqual(result, 1)
        self.assertFalse(manifest["artifacts"])
        for path in out.iterdir():
            if path.is_dir():
                continue
            self.assertNotIn(b"PRIVATE_BODY_SENTINEL", path.read_bytes())
            self.assertNotIn(b"PRIVATE_HEADER_SENTINEL", path.read_bytes())

    def test_har_denied_origins_malformed_body_and_no_fetch(self):
        external = entry("/external.js", "NEVER_COPY")
        external["request"]["url"] = "https://outside.invalid/external.js"
        malformed = entry("/bad.js", "%%%", encoding="base64")
        missing = entry("/missing.js", "")
        del missing["response"]["content"]["text"]
        result, manifest, _ = self.run_har([external, malformed, missing])
        self.assertEqual(result, 1)
        self.assertFalse(manifest["artifacts"])
        self.assertIn("origin-denied", manifest["gaps"])
        self.assertIn("invalid-har-base64", manifest["gaps"])
        self.assertIn("har-body-missing", manifest["gaps"])

    def test_base64_har_and_inline_map(self):
        data = base64.b64encode(lab.packed(sourcemap())).decode()
        text = "gsap.timeline();\n//# sourceMappingURL=data:application/json;base64," + data
        result, manifest, _ = self.run_har([entry("/inline.js", base64.b64encode(text.encode()).decode(), encoding="base64")])
        self.assertEqual(result, 0)
        self.assertEqual(len(manifest["artifacts"]), 3)

    def test_map_header_precedes_annotation(self):
        result, manifest, _ = self.run_har([
            entry("/app.js", "//# sourceMappingURL=missing.map"),
            entry("/chosen.map", json.dumps(sourcemap()), "application/json")])
        self.assertEqual(result, 1)
        self.assertIn("map-not-in-har", manifest["gaps"])
        self.assertEqual(lab.map_url("//# sourceMappingURL=missing.map", {"SourceMap": "chosen.map"}), "chosen.map")

    def test_missing_sources_not_fetched_and_originals_never_executed(self):
        sm = sourcemap([None], sources=["https://outside.invalid/original.js"])
        result, manifest, _ = self.run_har([
            entry("/app.js", "//# sourceMappingURL=a.map"),
            entry("/a.map", json.dumps(sm), "application/json")])
        self.assertEqual(result, 1)
        self.assertEqual(len(manifest["artifacts"]), 2)
        self.assertIn("missing-sourcesContent", manifest["gaps"])

    def test_index_map_embedded_and_malformed(self):
        data = {"version": 3, "sections": [{"offset": {"line": 0, "column": 0}, "map": sourcemap()},
                                            {"offset": {"line": 10, "column": 0}, "url": "https://outside.invalid/no.map"}]}
        sources, gaps = lab.original_sources(data)
        self.assertEqual(len(sources), 1)
        self.assertIn("external-or-missing-map-section", gaps)
        for invalid in ({"version": 2}, sourcemap([42]), sourcemap(sources="not-list"),
                        sourcemap(version=True), sourcemap(sections={})):
            with self.subTest(invalid=invalid), self.assertRaises(lab.LabError):
                lab.original_sources(invalid)

    def test_artifact_quota_preserves_partial_manifest(self):
        result, manifest, out = self.run_har([entry("/a.js", "const x=1;"), entry("/b.js", "const y=2;")],
                                              limits={"max_artifacts": 1})
        self.assertEqual(result, 1)
        self.assertEqual(len(manifest["artifacts"]), 1)
        self.assertIn("artifact-quota", manifest["gaps"])
        self.assertTrue((out / "SHA256SUMS").is_file())

    def test_refuses_output_reuse_and_symlink_input(self):
        self.run_har([entry("/a.js", "const x=1;")])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(lab.main(["import-har", str(self.directory / "capture.har"),
                                      "--scope", str(self.directory / "scope.json"),
                                      "--out", str(self.directory / "evidence")]), 2)
        link = self.directory / "link"
        link.symlink_to(self.directory / "scope.json")
        with self.assertRaises(OSError):
            lab.read_local(link, lab.MIB)

    def test_audit_failure_prevents_any_request(self):
        run = lab.Run(self.directory / "audit-failure", scope(), "collect", False)
        try:
            with patch.object(run, "event", side_effect=OSError("synthetic audit failure")):
                with patch.object(lab.Fetcher, "get") as get:
                    with self.assertRaises(OSError):
                        lab.collect(run, SITE)
                    get.assert_not_called()
        finally:
            run.audit.close()

    def test_map_size_and_data_type_limits(self):
        for value in ("data:text/javascript,alert(1)", "data:application/json;base64,%%%",
                      "data:application/json," + "x" * 100):
            with self.subTest(value=value), self.assertRaises(lab.LabError):
                lab.inline_map(value, 10)

    def test_body_never_appears_in_report_or_stdout(self):
        _, _, out = self.run_har([entry("/a.js", "const secret='PRIVATE_SOURCE_SENTINEL';")])
        for name in ("report.txt", "manifest.json", "audit.jsonl"):
            self.assertNotIn(b"PRIVATE_SOURCE_SENTINEL", (out / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
