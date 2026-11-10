"""Contract/schema tests and real TLS cryptography via in-memory BIO (no sockets)."""
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_js_lab import SITE, lab, scope, sourcemap


class ContractTests(unittest.TestCase):
    def test_paths_are_explicit_and_canonical(self):
        allowed = scope(allowed_paths={SITE: ["/assets/"]})
        self.assertEqual(allowed.url(SITE + "/assets/app.js?v=1"), SITE + "/assets/app.js?v=1")
        for path in ("/elsewhere.js", "/assets-fake/a.js", "/assets/../x.js", "/assets/%2e%2e/x",
                     "/assets/%252e%252e/x", "/assets//x", "/assets/%5cx", "/assets/%ff"):
            with self.subTest(path=path), self.assertRaises(lab.LabError):
                allowed.url(SITE + path)

    def test_json_depth_and_constants(self):
        for data in (b"[" * 65 + b"0" + b"]" * 65, b'{"x":NaN}', b"\xff"):
            with self.subTest(data=data[:30]), self.assertRaises(lab.LabError):
                lab.parse_json(data)
        self.assertEqual(lab.parse_json(b'{"x":"[[[{}]]]"}'), {"x": "[[[{}]]]"})

    def test_source_map_schema_and_section_order(self):
        for sm in (sourcemap(names=[5]), sourcemap(mappings=[]), sourcemap(sourceRoot=4),
                   sourcemap(ignoreList=[True]), sourcemap(ignoreList=[4]),
                   {"version": 3, "sections": [{"offset": {"line": -1, "column": 0}, "map": sourcemap()}]},
                   {"version": 3, "sections": [{"offset": {"line": 0, "column": 0}, "map": sourcemap()}] * 2}):
            with self.subTest(sm=sm), self.assertRaises(lab.LabError):
                lab.original_sources(sm)
        sources, gaps = lab.original_sources({"version": 3, "sections": [
            {"offset": {"line": 1, "column": 0}, "map": sourcemap([None, "export const x=1;"], sources=[None, "x.js"])}]})
        self.assertEqual(sources, [([0, 1], b"export const x=1;")])
        self.assertEqual(gaps, ["missing-sourcesContent"])

    def test_html_or_binary_cannot_masquerade_as_javascript(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = lab.Run(Path(tmp) / "evidence", scope(), "import-har", False)
            for data in (b"<!DOCTYPE html><html>error</html>", b"a\x00b", b"\xff"):
                with self.subTest(data=data), self.assertRaises(lab.LabError):
                    run.script(data, SITE + "/a.js", {}, lambda url: None)
            run.finish()
            self.assertFalse(run.artifacts)

    def test_maps_require_explicit_policy_consent(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = lab.Run(Path(tmp) / "evidence", scope(allow_source_maps=False), "import-har", True)
            with self.assertRaisesRegex(lab.LabError, "source-maps-not-authorized"):
                run.script(b"//# sourceMappingURL=private.map", SITE + "/a.js", {}, lambda url: self.fail("must not fetch map"))
            run.finish()
            self.assertEqual([x["kind"] for x in run.artifacts], ["script"])


class RealTLSMemoryBIOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.cert, cls.key = cls.root / "cert.pem", cls.root / "key.pem"
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(cls.key), "-out", str(cls.cert), "-subj", "/CN=fixture.invalid",
                        "-addext", "subjectAltName=DNS:fixture.invalid", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def exchange(self, host):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.cert, self.key)
        client_context = ssl.create_default_context(cafile=str(self.cert))
        ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
        client = client_context.wrap_bio(ci, co, server_hostname=host)
        server = server_context.wrap_bio(si, so, server_side=True)
        done = [False, False]
        for _ in range(32):
            for index, peer in enumerate((client, server)):
                try:
                    peer.do_handshake()
                    done[index] = True
                except ssl.SSLWantReadError:
                    pass
            if co.pending:
                si.write(co.read())
            if so.pending:
                ci.write(so.read())
            if all(done):
                break
        self.assertEqual(done, [True, True])
        client.write(b"GET /public.js HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n")
        si.write(co.read())
        request = server.read(4096)
        body = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\ngsap.timeline();"
        server.write(body)
        ci.write(so.read())
        self.assertEqual(client.read(4096), body)
        return request

    def test_real_tls_handshake_and_http_without_auth(self):
        request = self.exchange("fixture.invalid")
        self.assertIn(b"Host: fixture.invalid", request)
        self.assertNotIn(b"Cookie:", request)
        self.assertNotIn(b"Authorization:", request)

    def test_real_certificate_hostname_mismatch_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.exchange("wrong.invalid")


if __name__ == "__main__":
    unittest.main()
