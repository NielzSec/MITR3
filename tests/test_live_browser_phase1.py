#!/usr/bin/env python3
"""
Unit tests for MITR3 Live Browser Phase 1 (Scope, Sanitization, Indicators, and Local Evidence Sealing).
These tests run strictly offline with no live browser or external network connections.
"""

import json
import os
import re
import stat
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from tools.mitr3_live_browser import (
    ScopePolicy,
    EventSanitizer,
    IndicatorDetector,
    LiveBrowserFeedSession,
    inspect_session,
    tail_feed,
    find_latest_session,
    SAFE_REPLAY_METHODS,
    load_human_request,
    run_probe,
    run_replay,
    _write_phase2_evidence,
    _preflight_phase2_evidence,
    _parse_mod,
)


class TestScopePolicy(unittest.TestCase):
    def setUp(self):
        self.scope = ScopePolicy(
            allowed_origins=["https://target.corp:8443", "http://internal.lab"],
            allowed_hosts=["api.target.corp"],
        )

    def test_allowed_origin_direct(self):
        allowed, reason = self.scope.is_allowed("https://target.corp:8443/dashboard")
        self.assertTrue(allowed)
        self.assertEqual(reason, "ORIGIN_MATCH")

        allowed_lab, reason_lab = self.scope.is_allowed("http://internal.lab/login")
        self.assertTrue(allowed_lab)
        self.assertEqual(reason_lab, "ORIGIN_MATCH")

    def test_allowed_host_direct(self):
        allowed, reason = self.scope.is_allowed("https://api.target.corp/v1/users")
        self.assertTrue(allowed)
        self.assertEqual(reason, "HOST_MATCH")

    def test_disallowed_schemes(self):
        allowed, reason = self.scope.is_allowed("file:///etc/passwd")
        self.assertFalse(allowed)
        self.assertIn("UNSUPPORTED_SCHEME", reason)

        allowed_js, reason_js = self.scope.is_allowed("javascript:alert(1)")
        self.assertFalse(allowed_js)
        self.assertIn("UNSUPPORTED_SCHEME", reason_js)

        allowed_ftp, reason_ftp = self.scope.is_allowed("ftp://internal.lab/resource")
        self.assertFalse(allowed_ftp)
        self.assertIn("UNSUPPORTED_SCHEME", reason_ftp)

    def test_userinfo_rejection(self):
        allowed, reason = self.scope.is_allowed("https://admin:pass@target.corp:8443/")
        self.assertFalse(allowed)
        self.assertEqual(reason, "USERINFO_PROHIBITED")

    def test_out_of_scope_origins(self):
        allowed_evil, reason_evil = self.scope.is_allowed("https://evil.com/steal")
        self.assertFalse(allowed_evil)
        self.assertIn("OUT_OF_SCOPE_DESTINATION", reason_evil)

        # Port mismatch
        allowed_port, reason_port = self.scope.is_allowed("https://target.corp/path")
        self.assertFalse(allowed_port)
        self.assertIn("OUT_OF_SCOPE_DESTINATION", reason_port)

        # Scheme mismatch
        allowed_scheme, reason_scheme = self.scope.is_allowed("http://target.corp:8443/")
        self.assertFalse(allowed_scheme)
        self.assertIn("OUT_OF_SCOPE_DESTINATION", reason_scheme)

    def test_redirect_enforcement(self):
        # Redirect target validation using is_allowed
        allowed, reason = self.scope.is_allowed("https://evil.attacker.com/oauth/callback")
        self.assertFalse(allowed)
        self.assertIn("OUT_OF_SCOPE_DESTINATION", reason)

        allowed_ok, reason_ok = self.scope.is_allowed("https://target.corp:8443/home")
        self.assertTrue(allowed_ok)
        self.assertEqual(reason_ok, "ORIGIN_MATCH")

    def test_subresource_filtering(self):
        allowed, reason = self.scope.is_allowed("https://cdn.thirdparty.com/library.js")
        self.assertFalse(allowed)
        self.assertIn("OUT_OF_SCOPE_DESTINATION", reason)


class TestEventSanitizer(unittest.TestCase):
    def test_query_values_redacted(self):
        raw_url = "https://app.target.com/search?q=secret_token_12345&filter=admin&order=desc"
        origin, path, param_names = EventSanitizer.sanitize_url(raw_url)
        self.assertEqual(origin, "https://app.target.com")
        self.assertEqual(path, "/search")
        self.assertEqual(param_names, ["filter", "order", "q"])

        # Ensure no query values leaked in serialized format
        data = {"origin": origin, "path": path, "param_names": param_names}
        self.assertNotIn("secret_token_12345", json.dumps(data))
        self.assertNotIn("admin", json.dumps(data))
        self.assertNotIn("desc", json.dumps(data))

    def test_sensitive_headers_filtered(self):
        raw_headers = {
            "Cookie": "session=a89f41b3; remember=true",
            "Authorization": "Bearer super_secret_jwt_token",
            "X-Api-Key": "my-secret-key",
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": "128",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 Sanitized",
        }
        filtered = EventSanitizer.sanitize_headers(raw_headers)
        self.assertNotIn("cookie", filtered)
        self.assertNotIn("authorization", filtered)
        self.assertNotIn("x-api-key", filtered)
        self.assertIn("content-type", filtered)
        self.assertEqual(filtered["content-type"], "application/json")
        self.assertIn("content-length", filtered)
        self.assertEqual(filtered["_omitted_sensitive_headers_count"], 3)

    def test_post_field_names_json(self):
        payload = json.dumps({"username": "admin", "password": "supersecretpassword", "action": "auth"})
        fields = EventSanitizer.extract_field_names(payload, "application/json")
        self.assertIn("username", fields)
        self.assertIn("password", fields)
        self.assertIn("action", fields)
        self.assertNotIn("admin", fields)
        self.assertNotIn("supersecretpassword", fields)

    def test_post_field_names_form(self):
        payload = "csrf_token=998877&user=root&pass=toor"
        fields = EventSanitizer.extract_field_names(payload, "application/x-www-form-urlencoded")
        self.assertEqual(fields, ["csrf_token", "pass", "user"])
        self.assertNotIn("root", fields)
        self.assertNotIn("toor", fields)


class TestIndicatorDetector(unittest.TestCase):
    def test_parameter_candidate_identification(self):
        indicators = IndicatorDetector.check_param_indicators(["cmd", "redirect", "file", "user_id"])
        types = [i["type"] for i in indicators]
        self.assertIn("param_rce_candidate", types)
        self.assertIn("param_ssrf_candidate", types)
        self.assertIn("param_lfi_candidate", types)
        self.assertIn("param_idor_candidate", types)

        for ind in indicators:
            self.assertEqual(ind["category"], "candidate_indicator")
            self.assertIn(ind["severity"], ["LOW", "MEDIUM", "INFO"])
            self.assertIn("candidate", ind["detail"].lower())

    def test_diagnostic_indicators(self):
        diag = IndicatorDetector.check_response_diagnostics(
            "Fatal error: Uncaught Error in /var/www/html/app.php on line 42"
        )
        self.assertTrue(len(diag) > 0)
        self.assertEqual(diag[0]["type"], "php_fatal_pattern")
        self.assertEqual(diag[0]["category"], "diagnostic_indicator")
        self.assertIn("requires independent verification", diag[0]["detail"])

        diag_db = IndicatorDetector.check_response_diagnostics(
            "ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
        )
        self.assertTrue(len(diag_db) > 0)
        self.assertEqual(diag_db[0]["type"], "sql_syntax_error_pattern")


class TestSessionStorageAndPermissions(unittest.TestCase):
    def test_directory_and_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = LiveBrowserFeedSession(
                allowed_origins=["https://target.local"],
                out_dir=tmpdir,
                human_raw_capture=True,
                quiet=True,
            )

            # Check directory permissions (0700)
            dir_mode = stat.S_IMODE(os.stat(session.out_dir).st_mode)
            self.assertEqual(dir_mode, 0o700, f"Expected 0700, got {oct(dir_mode)}")

            # Ingest an event and verify record
            raw_req = {
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "100.1",
                    "request": {
                        "url": "https://target.local/api/items?id=123",
                        "method": "GET",
                        "headers": {"Accept": "application/json", "Cookie": "auth=1"}
                    },
                    "type": "XHR"
                }
            }
            session._on_cdp_event(raw_req)

            raw_resp = {
                "method": "Network.responseReceived",
                "params": {
                    "requestId": "100.1",
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "headers": {"Content-Type": "application/json", "Set-Cookie": "track=1"},
                        "mimeType": "application/json",
                        "encodedDataLength": 256
                    }
                }
            }
            session._on_cdp_event(raw_resp)

            raw_finish = {
                "method": "Network.loadingFinished",
                "params": {
                    "requestId": "100.1",
                    "encodedDataLength": 256
                }
            }
            session._on_cdp_event(raw_finish)

            summary = session.export_sealed_summary()

            # Verify files exist and have mode 0600
            feed_mode = stat.S_IMODE(os.stat(session.feed_path).st_mode)
            summary_mode = stat.S_IMODE(os.stat(session.summary_path).st_mode)
            self.assertEqual(feed_mode, 0o600, f"Feed mode expected 0600, got {oct(feed_mode)}")
            self.assertEqual(summary_mode, 0o600, f"Summary mode expected 0600, got {oct(summary_mode)}")

            # Check SHA-256 seal integrity
            self.assertTrue(Path(session.feed_path).is_file())
            self.assertTrue(Path(session.summary_path).is_file())
            self.assertIn("agent_feed_sha256", summary)
            self.assertEqual(len(summary["agent_feed_sha256"]), 64)

            # Human raw capture dir check (0700 and files 0600)
            if session.human_raw_dir and os.path.exists(session.human_raw_dir):
                raw_dir_mode = stat.S_IMODE(os.stat(session.human_raw_dir).st_mode)
                self.assertEqual(raw_dir_mode, 0o700)
                if session.human_raw_path and os.path.exists(session.human_raw_path):
                    raw_file_mode = stat.S_IMODE(os.stat(session.human_raw_path).st_mode)
                    self.assertEqual(raw_file_mode, 0o600)


class TestEventCorrelation(unittest.TestCase):
    def test_mock_cdp_correlation_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = LiveBrowserFeedSession(
                allowed_origins=["https://target.local"],
                out_dir=tmpdir,
                human_raw_capture=False,
                quiet=True,
            )

            # 1. Normal Request -> Response -> Finish
            session._on_cdp_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "req_normal",
                    "request": {
                        "url": "https://target.local/profile?tab=security",
                        "method": "GET",
                        "headers": {"Accept": "*/*"}
                    },
                    "type": "Document"
                }
            })
            session._on_cdp_event({
                "method": "Network.responseReceived",
                "params": {
                    "requestId": "req_normal",
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "headers": {"Content-Type": "text/html"},
                        "mimeType": "text/html",
                        "encodedDataLength": 1024
                    }
                }
            })
            session._on_cdp_event({
                "method": "Network.loadingFinished",
                "params": {
                    "requestId": "req_normal",
                    "encodedDataLength": 1024
                }
            })

            # 2. Scope Blocked Request
            session._on_cdp_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "req_blocked",
                    "request": {
                        "url": "https://evil.tracker.com/beacon",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json"}
                    },
                    "type": "Ping"
                }
            })

            # 3. Failed Request
            session._on_cdp_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "req_fail",
                    "request": {
                        "url": "https://target.local/dead_endpoint",
                        "method": "GET",
                        "headers": {}
                    },
                    "type": "Fetch"
                }
            })
            session._on_cdp_event({
                "method": "Network.loadingFailed",
                "params": {
                    "requestId": "req_fail",
                    "errorText": "net::ERR_NAME_NOT_RESOLVED",
                    "canceled": False
                }
            })

            summary = session.export_sealed_summary()
            self.assertEqual(summary["total_requests"], 3)
            self.assertEqual(summary["scope_blocked_count"], 1)

            with open(session.feed_path, "r", encoding="utf-8") as f:
                feed_events = [json.loads(line) for line in f]

            # Verify feed events
            req_normal_events = [e for e in feed_events if e.get("request_id") == "req_normal"]
            self.assertTrue(len(req_normal_events) >= 2)
            req_ev = req_normal_events[0]
            self.assertEqual(req_ev["event"], "request")
            self.assertEqual(req_ev["path"], "/profile")
            self.assertEqual(req_ev["param_names"], ["tab"])
            self.assertTrue(req_ev["scope_allowed"])

            blocked_events = [e for e in feed_events if e.get("request_id") == "req_blocked"]
            self.assertTrue(len(blocked_events) >= 1)
            self.assertEqual(blocked_events[0]["event"], "scope_blocked")
            self.assertFalse(blocked_events[0]["scope_allowed"])

            failed_events = [e for e in feed_events if e.get("request_id") == "req_fail"]
            self.assertTrue(any(e.get("event") == "failed" for e in failed_events))
            failed_ev = next(e for e in failed_events if e.get("event") == "failed")
            self.assertEqual(failed_ev["error"], "net::ERR_NAME_NOT_RESOLVED")


class TestInspectAndTailSubcommands(unittest.TestCase):
    def test_inspect_session_and_integrity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = LiveBrowserFeedSession(
                allowed_origins=["https://target.local"],
                out_dir=tmpdir,
                human_raw_capture=False,
                quiet=True,
            )
            # Ingest request with candidates
            session._on_cdp_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "inspect_1",
                    "request": {
                        "url": "https://target.local/api/eval?cmd=whoami&redirect=http://test",
                        "method": "POST",
                        "headers": {"Content-Type": "application/json"}
                    },
                    "type": "XHR"
                }
            })
            summary = session.export_sealed_summary()

            # Inspect via directory
            res_dir = inspect_session(tmpdir)
            self.assertTrue(res_dir["sha256_verified"])
            self.assertEqual(res_dir["unique_endpoints_count"], 1)
            self.assertEqual(res_dir["candidate_indicators_count"], 2)
            self.assertFalse(res_dir["security_model"]["raw_bodies_exposed_to_agents"])
            self.assertFalse(res_dir["security_model"]["cookies_exposed_to_agents"])

            # Inspect via summary path
            res_sum = inspect_session(session.summary_path)
            self.assertTrue(res_sum["sha256_verified"])

            # Inspect via feed path
            res_feed = inspect_session(session.feed_path)
            self.assertTrue(res_feed["sha256_verified"])
            self.assertEqual(len(res_feed["candidates"]), 2)

    def test_tail_feed_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = LiveBrowserFeedSession(
                allowed_origins=["https://target.local"],
                out_dir=tmpdir,
                human_raw_capture=False,
                quiet=True,
            )
            session._on_cdp_event({
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "tail_1",
                    "request": {
                        "url": "https://target.local/search?q=test",
                        "method": "GET",
                        "headers": {"Accept": "application/json"}
                    },
                    "type": "XHR"
                }
            })
            session.export_sealed_summary()

            # Ensure tail runs without raising errors
            try:
                tail_feed(session.feed_path, lines=10)
            except Exception as e:
                self.fail(f"tail_feed raised an unexpected exception: {e}")


class TestPhase2ReplayAndProbe(unittest.TestCase):
    def setUp(self):
        self.scope = ScopePolicy(allowed_origins=["https://target.example", "https://oast.example"])
        self.request = {
            "raw_event": "request", "request_id": "req.1", "method": "GET",
            "url": "https://target.example/run?cmd=whoami", "headers": {"Cookie": "session=secret"}
        }

    def test_rce_probe_uses_fixed_canary_and_redacts_response_body(self):
        sent = []
        def transport(url, method, headers):
            sent.append((url, method, headers))
            body = "ok" if len(sent) == 1 else "ok " + re.search(r"MITR3_[a-f0-9]{16}", urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["cmd"][0]).group(0)
            return {"status": 200, "content_type": "text/plain", "body_bytes": len(body),
                    "body_sha256": str(len(sent)) * 64, "body": body}

        result = run_probe(self.request, self.scope, "rce", "cmd", transport=transport)
        self.assertEqual(len(sent), 2)
        self.assertTrue(all(method == "GET" for _, method, _ in sent))
        self.assertIn("mitr3_control_", urllib.parse.parse_qs(urllib.parse.urlsplit(sent[0][0]).query)["cmd"][0])
        payload = urllib.parse.parse_qs(urllib.parse.urlsplit(sent[1][0]).query)["cmd"][0]
        self.assertTrue(payload.startswith(";printf '%s' 'MITR3_"))
        self.assertIn("whoami", self.request["url"])
        self.assertNotIn("whoami", sent[0][0] + sent[1][0])
        self.assertEqual(sent[0][2]["Cookie"], "session=secret")
        self.assertTrue(result["response_diff"]["marker_observed"])
        self.assertNotIn("body", result["response_diff"])
        self.assertNotIn("session=secret", json.dumps(result))

    def test_probe_requires_exactly_one_query_parameter(self):
        request = dict(self.request, url="https://target.example/run?cmd=x&mode=y")
        calls = []
        with self.assertRaisesRegex(ValueError, "exactly one query parameter"):
            run_probe(request, self.scope, "rce", "cmd", transport=lambda *args: calls.append(args))
        self.assertEqual(calls, [])

    def test_probe_rejects_out_of_scope_origin_before_transport(self):
        request = dict(self.request, url="https://evil.example/run?cmd=x")
        calls = []
        with self.assertRaises(PermissionError):
            run_probe(request, self.scope, "rce", "cmd", transport=lambda *args: calls.append(args))
        self.assertEqual(calls, [])

    def test_probe_rejects_side_effecting_methods_before_transport(self):
        request = dict(self.request, method="POST")
        calls = []
        with self.assertRaises(PermissionError):
            run_probe(request, self.scope, "rce", "cmd", transport=lambda *args: calls.append(args))
        self.assertEqual(calls, [])
        self.assertEqual(SAFE_REPLAY_METHODS, {"GET", "HEAD", "OPTIONS"})

    def test_ssrf_probe_uses_scoped_https_canary_and_reserved_control(self):
        request = dict(self.request, url="https://target.example/fetch?url=previous")
        sent = []
        def transport(url, method, headers):
            sent.append(url)
            return {"status": 200, "content_type": "text/plain", "body_bytes": 0,
                    "body_sha256": "a" * 64, "body": ""}

        result = run_probe(request, self.scope, "ssrf", "url", "https://oast.example/callback", transport)
        self.assertEqual(len(sent), 2)
        values = [urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["url"][0] for url in sent]
        self.assertIn(".invalid", values[0])
        canary = urllib.parse.urlsplit(values[1])
        self.assertEqual(canary.scheme, "https")
        self.assertEqual(canary.hostname, "oast.example")
        self.assertIn("mitr3_probe", urllib.parse.parse_qs(canary.query))
        self.assertIn(result["canary_correlation"], canary.query)
        self.assertNotIn("body", result["response_diff"])

    def test_ssrf_probe_requires_scoped_public_canary(self):
        request = dict(self.request, url="https://target.example/fetch?url=previous")
        calls = []
        for canary in ("http://oast.example/callback", "https://127.0.0.1/callback", "https://oast.example.internal/callback", "https://target.example/callback"):
            with self.subTest(canary=canary), self.assertRaises(ValueError):
                run_probe(request, self.scope, "ssrf", "url", canary, lambda *args: calls.append(args))
        with self.assertRaises(PermissionError):
            run_probe(request, ScopePolicy(allowed_origins=["https://target.example"]), "ssrf", "url",
                      "https://oast.example/callback", lambda *args: calls.append(args))
        self.assertEqual(calls, [])

    def test_replay_is_one_scoped_read_only_request_and_returns_fingerprint_only(self):
        sent = []
        def transport(url, method, headers):
            sent.append((url, method))
            return {"status": 200, "content_type": "application/json", "body_bytes": 4,
                    "body_sha256": "b" * 64, "body": "secret"}
        result = run_replay(self.request, self.scope, transport)
        self.assertEqual(sent, [(self.request["url"], "GET")])
        self.assertEqual(result["response"]["body_sha256"], "b" * 64)
        self.assertNotIn("secret", json.dumps(result))

    def test_replay_rejects_post_and_bad_scope_before_transport(self):
        calls = []
        with self.assertRaises(PermissionError):
            run_replay(dict(self.request, method="POST"), self.scope, lambda *args: calls.append(args))
        with self.assertRaises(PermissionError):
            run_replay(dict(self.request, url="https://evil.example/run?cmd=x"), self.scope,
                       lambda *args: calls.append(args))
        self.assertEqual(calls, [])

    def test_phase2_evidence_is_private_and_sha256_sealed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = Path(tmpdir) / "human-only"
            raw_dir.mkdir(mode=0o700)
            capture = raw_dir / "session.raw.jsonl"
            capture.write_text("{}\n", encoding="utf-8")
            os.chmod(capture, 0o600)
            result = {"event": "replay_result", "response": {"body_sha256": "a" * 64}}
            path, digest = _write_phase2_evidence(str(capture), result)
            evidence = Path(path)
            self.assertEqual(stat.S_IMODE(evidence.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)
            stored = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(stored["evidence_sha256"], digest)
            self.assertEqual(digest, __import__("hashlib").sha256(
                json.dumps(result, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest())

    def test_capture_loader_requires_private_human_only_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = Path(tmpdir) / "human-only"
            raw_dir.mkdir(mode=0o700)
            capture = raw_dir / "session.raw.jsonl"
            capture.write_text(json.dumps(self.request) + "\n", encoding="utf-8")
            os.chmod(capture, 0o600)
            self.assertEqual(load_human_request(str(capture), "req.1")["request_id"], "req.1")
            outside = Path(tmpdir) / "outside.jsonl"
            outside.write_text(json.dumps(self.request) + "\n", encoding="utf-8")
            os.chmod(outside, 0o600)
            (raw_dir / "linked.raw.jsonl").symlink_to(outside)
            with self.assertRaises(PermissionError):
                load_human_request(str(raw_dir / "linked.raw.jsonl"), "req.1")
            os.chmod(capture, 0o644)
            with self.assertRaises(PermissionError):
                load_human_request(str(capture), "req.1")

    def test_preflight_phase2_evidence_fails_closed_on_bad_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_dir = Path(tmpdir) / "human-only"
            raw_dir.mkdir(mode=0o755)  # insecure permissions (must be 0700)
            capture = raw_dir / "session.raw.jsonl"
            capture.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(PermissionError):
                _preflight_phase2_evidence(str(capture))


class TestPhase3Intercept(unittest.TestCase):
    """Phase 3: CDP Fetch intercept — hold/modify/forward with scope enforcement. Offline only."""

    class FakeWs:
        def __init__(self):
            self.calls = []

        def call(self, method, params=None, timeout=10.0):
            self.calls.append((method, params))
            return {}

    def _session(self, tmpdir, mode=None):
        session = LiveBrowserFeedSession(
            allowed_origins=["https://target.local"],
            out_dir=tmpdir,
            human_raw_capture=False,
            quiet=True,
        )
        session.ws = self.FakeWs()
        if mode:
            session.intercept_enable(mode)
        return session

    def _paused(self, fetch_id, url, method="GET", headers=None, post_data=None):
        params = {"requestId": fetch_id, "request": {"url": url, "method": method, "headers": headers or {}},
                  "resourceType": "Document"}
        if post_data is not None:
            params["request"]["postData"] = post_data
        return {"method": "Fetch.requestPaused", "params": params}

    def test_build_continue_params_minimal_and_full(self):
        self.assertEqual(LiveBrowserFeedSession._build_continue_params("f1"), {"requestId": "f1"})
        full = LiveBrowserFeedSession._build_continue_params(
            "f2", url="https://x.local/", method="POST",
            headers={"X-A": "1"}, post_data="a=1")
        self.assertEqual(full, {"requestId": "f2", "url": "https://x.local/", "method": "POST",
                                "headers": {"X-A": "1"}, "postData": "a=1"})

    def test_observe_mode_records_and_auto_continues(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="observe")
            session._on_cdp_event(self._paused("f1", "https://target.local/page?q=1"))
            self.assertEqual(session.ws.calls[-1], ("Fetch.continueRequest", {"requestId": "f1"}))
            self.assertTrue(session.held["f1"]["released"])
            self.assertEqual(session.held_summary(), [])

    def test_hold_mode_queues_until_released(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/admin", method="POST",
                                               post_data="user=admin"))
            self.assertFalse(session.held["f1"]["released"])
            self.assertEqual(len(session.held_summary()), 1)
            # no CDP call must have been made for the held request
            self.assertNotIn("Fetch.continueRequest", [c[0] for c in session.ws.calls])
            session.intercept_release("f1")
            self.assertEqual(session.held_summary(), [])
            self.assertEqual(session.ws.calls[-1], ("Fetch.continueRequest", {"requestId": "f1"}))

    def test_out_of_scope_paused_request_dropped_not_continued(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f9", "https://evil.tracker.com/beacon"))
            self.assertEqual(session.ws.calls[-1], ("Fetch.failRequest",
                                                    {"requestId": "f9", "errorReason": "BlockedByClient"}))
            self.assertTrue(session.held["f9"]["released"])
            self.assertEqual(len(session.blocked_events), 1)

    def test_modified_url_revalidates_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/"))
            with self.assertRaises(PermissionError):
                session.intercept_release("f1", url="https://evil.tracker.com/x")
            # still held after failed modification
            self.assertFalse(session.held["f1"]["released"])

    def test_modified_release_merges_headers_and_body(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/login",
                                               method="POST", headers={"Content-Type": "application/json"}))
            session.intercept_release("f1", post_data='{"user":"x"}', headers={"X-Injected": "1"})
            method, params = session.ws.calls[-1]
            self.assertEqual(method, "Fetch.continueRequest")
            self.assertEqual(params["postData"], '{"user":"x"}')
            self.assertEqual(params["headers"], {"Content-Type": "application/json", "X-Injected": "1"})

    def test_double_release_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/"))
            session.intercept_release("f1")
            with self.assertRaises(KeyError):
                session.intercept_release("f1")

    def test_parse_mod_tokens(self):
        kwargs = _parse_mod("f3 url=https://t.local/a header=X-A: val ue header=X-B: 2 body=a=1")
        self.assertEqual(kwargs["fetch_id"], "f3")
        self.assertEqual(kwargs["url"], "https://t.local/a")
        self.assertEqual(kwargs["headers"], {"X-A": "val ue", "X-B": "2"})
        self.assertEqual(kwargs["post_data"], "a=1")
        self.assertEqual(_parse_mod("f7"), {"fetch_id": "f7"})

    def test_intercept_disable_clears_mode_and_stop_is_safe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session.intercept_disable()
            self.assertIsNone(session.intercept_mode)
            self.assertIn("Fetch.disable", [c[0] for c in session.ws.calls])


if __name__ == "__main__":
    unittest.main()
