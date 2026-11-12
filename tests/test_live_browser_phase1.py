#!/usr/bin/env python3
"""
Unit tests for MITR3 Live Browser Phase 1 (Scope, Sanitization, Indicators, and Local Evidence Sealing).
These tests run strictly offline with no live browser or external network connections.
"""

import json
import os
import re
import http.server
import stat
import tempfile
import threading
import unittest
import unittest.mock
import secrets
import urllib.parse
import urllib.request
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
    load_intruder_payloads,
    run_intruder,
    _NoRedirectHandler,
    CanaryListener,
    _validate_ssrf_canary,
    _confirm_phase2,
    phase2_cli,
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

    # --- testes complementares (held / fwd / mod revalidação / drop) ---

    def test_hold_fifo_order_and_partial_drop(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/a"))
            session._on_cdp_event(self._paused("f2", "https://target.local/b"))
            self.assertEqual([h["fetch_id"] for h in session.held_summary()], ["f1", "f2"])
            session.intercept_drop("f1", reason="operator_choice")
            self.assertEqual([h["fetch_id"] for h in session.held_summary()], ["f2"])
            # the survivor is still releasable
            session.intercept_release("f2")
            self.assertEqual(session.held_summary(), [])
            self.assertEqual(session.ws.calls[-1], ("Fetch.continueRequest", {"requestId": "f2"}))

    def test_drop_is_noop_after_release(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/"))
            session.intercept_release("f1")
            calls_before = list(session.ws.calls)
            session.intercept_drop("f1")  # already released: no Fetch.failRequest
            self.assertEqual(session.ws.calls, calls_before)

    def test_drop_records_reason_and_clears_queue(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/x"))
            session.intercept_drop("f1", reason="operator_choice")
            self.assertEqual(session.ws.calls[-1], ("Fetch.failRequest",
                                                    {"requestId": "f1", "errorReason": "BlockedByClient"}))
            self.assertTrue(session.held["f1"]["released"])
            self.assertEqual(session.held["f1"]["drop_reason"], "operator_choice")
            self.assertEqual(session.held_summary(), [])

    def test_drop_unknown_fetch_still_fails_request(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session.intercept_drop("fX", reason="never_held")
            self.assertEqual(session.ws.calls[-1], ("Fetch.failRequest",
                                                    {"requestId": "fX", "errorReason": "BlockedByClient"}))

    def test_modified_url_in_scope_release_forwards_url(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/a"))
            session.intercept_release("f1", url="https://target.local/b")
            method, params = session.ws.calls[-1]
            self.assertEqual(method, "Fetch.continueRequest")
            self.assertEqual(params["url"], "https://target.local/b")
            self.assertEqual(params["headers"], {})  # merged (empty) headers ride with a url modification
            self.assertTrue(session.held["f1"]["released"])
            self.assertEqual(session.held["f1"]["url"], "https://target.local/b")

    def test_modified_url_rejected_then_inscope_release_succeeds(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/a"))
            with self.assertRaises(PermissionError):
                session.intercept_release("f1", url="https://evil.tracker.com/x")
            # recovery: in-scope modification after a rejected one
            session.intercept_release("f1", url="https://target.local/safe")
            self.assertEqual(session.ws.calls[-1], ("Fetch.continueRequest",
                                                    {"requestId": "f1", "url": "https://target.local/safe",
                                                     "headers": {}}))

    def test_release_forwards_method_change(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._session(tmpdir, mode="hold")
            session._on_cdp_event(self._paused("f1", "https://target.local/post", method="POST",
                                               headers={"Content-Type": "text/plain"}))
            session.intercept_release("f1", method="GET")
            method, params = session.ws.calls[-1]
            self.assertEqual(method, "Fetch.continueRequest")
            self.assertEqual(params["method"], "GET")
            # original held headers ride along with a method-only modification
            self.assertEqual(params["headers"], {"Content-Type": "text/plain"})


class TestPhase4Intruder(unittest.TestCase):
    """Phase 4: intruder-lite — payload injection into one param, rate-limited, scope-confined. Offline only."""

    def setUp(self):
        self.scope = ScopePolicy(allowed_origins=["https://target.example", "https://oast.example"])
        self.request = {
            "raw_event": "request", "request_id": "req.1", "method": "GET",
            "url": "https://target.example/run?cmd=whoami", "headers": {"Cookie": "session=secret"}
        }

    @staticmethod
    def _param_value(url):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["cmd"][0]

    # small deterministic fixtures — the live catalogs grow (db + lite merge), behavior tests must not depend on their size
    FIXTURE_DB = {
        "rce": [
            {"id": "rce_printf_semi", "value": ";printf '%s' 'MITR3_{token}';#", "detects": ["marker_reflection"]},
            {"id": "rce_printf_subst", "value": "$(printf '%s' 'MITR3_{token}')", "detects": ["marker_reflection"]},
            {"id": "rce_id_semi", "value": ";id", "detects": ["unix_id_pattern"]},
        ],
        "lfi": [{"id": "lfi_passwd_traverse", "value": "../../../../etc/passwd", "detects": ["unix_passwd_entry"]}],
        "ssrf": [{"id": "ssrf_canary_plain", "value": "{canary}", "detects": ["oob_callback"]}],
    }

    def test_load_intruder_payloads_from_catalog(self):
        db = load_intruder_payloads()
        for kind, minimum in (("rce", 7), ("lfi", 4), ("ssrf", 2)):
            self.assertGreaterEqual(len(db[kind]), minimum)
        self.assertTrue(all("value" in p and "id" in p for items in db.values() for p in items))
        ids = [p["id"] for items in db.values() for p in items]
        self.assertEqual(len(ids), len(set(ids)))  # merge never duplicates a probe id
        self.assertIn("rce_printf_semi", ids)  # db baseline survived the merge

    def test_intruder_rce_all_probes_and_marker_hits(self):
        sent = []
        def transport(url, method, headers):
            sent.append(url)
            value = self._param_value(url)
            body = value.replace("+", " ")
            if "MITR3_" in value:
                body += " " + re.search(r"MITR3_[a-f0-9]{16}", value).group(0)
            body += " uid=0(root) gid=0(root) groups=0(root)"
            return {"status": 200, "content_type": "text/plain", "body_bytes": len(body),
                    "body_sha256": str(len(sent)) * 64, "body": body}

        result = run_intruder(self.request, self.scope, "cmd", "rce", transport=transport,
                              delay=0.1, payload_db=self.FIXTURE_DB)
        self.assertEqual(result["probes_sent"], 3)
        self.assertEqual(len(sent), 3)
        self.assertTrue(all(m == "GET" for _, m, _ in sent))
        self.assertTrue(all("whoami" not in u for u in sent))  # original value never replayed
        marker_hits = [r for r in result["results"] if r["marker_observed"]]
        self.assertEqual(len(marker_hits), 2)  # the two printf canaries echo the marker
        id_hits = [r for r in result["results"] if any(i["type"] == "unix_id_pattern" for i in r["indicators"])]
        self.assertEqual(len(id_hits), 3)  # transport echoes id output to every probe
        self.assertIn("rce_printf_semi", result["hit_probe_ids"])
        # no raw body or credentials leak into the result
        self.assertNotIn("body", json.dumps(result["results"][0]))
        self.assertNotIn("session=secret", json.dumps(result))

    def test_intruder_lfi_payloads_reach_transport_and_detect_passwd(self):
        sent = []
        def transport(url, method, headers):
            sent.append(url)
            body = "root:x:0:0:root:/root:/bin/bash\n" if "passwd" in urllib.parse.unquote(self._param_value(url)) else "ok"
            return {"status": 200, "content_type": "text/html", "body_bytes": len(body),
                    "body_sha256": "b" * 64, "body": body}

        result = run_intruder(self.request, self.scope, "cmd", "lfi", transport=transport,
                              delay=0.1, payload_db=self.FIXTURE_DB)
        self.assertEqual(result["probes_sent"], 1)
        self.assertIn("lfi_passwd_traverse", result["hit_probe_ids"])
        hit = next(r for r in result["results"] if r["probe_id"] == "lfi_passwd_traverse")
        self.assertTrue(any(i["type"] == "unix_passwd_entry" and i["severity"] == "HIGH" for i in hit["indicators"]))

    def test_intruder_ssrf_uses_canary_with_correlation_token(self):
        sent = []
        def transport(url, method, headers):
            sent.append(url)
            return {"status": 200, "content_type": "text/plain", "body_bytes": 0,
                    "body_sha256": "c" * 64, "body": ""}

        result = run_intruder(self.request, self.scope, "cmd", "ssrf",
                              canary_url="https://oast.example/callback", transport=transport,
                              delay=0.1, payload_db=self.FIXTURE_DB)
        self.assertEqual(result["probes_sent"], 1)
        self.assertEqual(result["canary_correlation"], re.search(r"MITR3_([a-f0-9]{16})", sent[0][0]).group(1))
        for url in sent:
            value = urllib.parse.unquote(self._param_value(url))
            self.assertIn("oast.example", value)
            self.assertTrue(value.startswith("https://"))

    def test_intruder_ssrf_requires_canary(self):
        calls = []
        with self.assertRaises(ValueError):
            run_intruder(self.request, self.scope, "cmd", "ssrf", transport=lambda *a: calls.append(a))
        self.assertEqual(calls, [])

    def test_intruder_rejects_out_of_scope_and_post_before_transport(self):
        calls = []
        out = dict(self.request, url="https://evil.example/run?cmd=x")
        with self.assertRaises(PermissionError):
            run_intruder(out, self.scope, "cmd", "rce", transport=lambda *a: calls.append(a))
        post = dict(self.request, method="POST")
        with self.assertRaises(PermissionError):
            run_intruder(post, self.scope, "cmd", "rce", transport=lambda *a: calls.append(a))
        self.assertEqual(calls, [])

    def test_intruder_fuzzes_one_position_others_intact(self):
        sent = []
        def transport(url, method, headers):
            sent.append(url)
            return {"status": 200, "content_type": "text/plain", "body_bytes": 0,
                    "body_sha256": "e" * 64, "body": ""}

        request = dict(self.request, url="https://target.example/run?mode=y&cmd=whoami")
        result = run_intruder(request, self.scope, "cmd", "rce", transport=transport,
                              delay=0.1, payload_db=self.FIXTURE_DB)
        self.assertEqual(result["probes_sent"], 3)
        self.assertTrue(all("mode=y" in u for u in sent))  # other params stay intact
        self.assertTrue(all("whoami" not in u for u in sent))  # fuzzed value replaced

    def test_intruder_param_must_appear_exactly_once(self):
        request = dict(self.request, url="https://target.example/run?cmd=a&cmd=b")
        calls = []
        with self.assertRaises(ValueError):
            run_intruder(request, self.scope, "cmd", "rce", transport=lambda *a: calls.append(a))
        self.assertEqual(calls, [])

    def test_intruder_rate_limited_and_capped(self):
        sent = []
        def transport(url, method, headers):
            sent.append(url)
            return {"status": 200, "content_type": "text/plain", "body_bytes": 0,
                    "body_sha256": "d" * 64, "body": ""}
        with unittest.mock.patch("tools.mitr3_live_browser.time.sleep") as fake_sleep:
            result = run_intruder(self.request, self.scope, "cmd", "rce",
                                  transport=transport, delay=0.5, max_probes=3,
                                  payload_db=self.FIXTURE_DB)
        self.assertEqual(len(sent), 3)
        self.assertEqual(result["probes_sent"], 3)
        self.assertEqual(result["probe_limit"], 3)
        self.assertEqual(fake_sleep.call_count, 2)  # delay before every probe except the first
        fake_sleep.assert_called_with(0.5)
        # bounds clamp: absurd values are clamped, never passthrough
        with unittest.mock.patch("tools.mitr3_live_browser.time.sleep") as fs2:
            run_intruder(self.request, self.scope, "cmd", "rce", transport=transport,
                         delay=999, max_probes=99999, payload_db=self.FIXTURE_DB)
        self.assertEqual(fs2.call_args[0][0], 60.0)

    def test_intruder_result_sealed_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = Path(tmpdir) / "s.raw.jsonl"
            capture.write_text("{}\n", encoding="utf-8")
            os.chmod(tmpdir, 0o700)
            os.chmod(capture, 0o600)
            _preflight_phase2_evidence(str(capture))
            result = {"event": "intruder_result", "kind": "rce", "results": [{"probe_id": "x"}],
                      "hit_probe_ids": ["x"]}
            evidence_path, digest = _write_phase2_evidence(str(capture), result)
            sealed = json.load(open(evidence_path))
            self.assertEqual(sealed["evidence_sha256"], digest)
            mode = stat.S_IMODE(os.stat(evidence_path).st_mode)
            self.assertEqual(mode, 0o600)


class TestPhase4Intruder(unittest.TestCase):
    """Phase 4: run_intruder fixtures — rate-limit, delay, strict redirect rejection. Offline only."""

    def _request(self, url="https://target.local/search?q=x"):
        return {"raw_event": "request", "request_id": "req.i", "method": "GET",
                "url": url, "headers": {}}

    def _scope(self):
        return ScopePolicy(allowed_origins=["https://target.local"])

    def _db(self, kind="rce", n=5):
        return {kind: [{"id": f"p{i}", "value": f"; probe{i}", "detects": []} for i in range(n)]}

    def _transport(self, body="ok", status=200):
        calls = []

        def transport(url, method, headers):
            calls.append({"url": url, "method": method, "headers": headers})
            return {"status": status, "content_type": "text/html",
                    "body_bytes": len(body), "body_sha256": "0" * 64, "body": body}

        transport.calls = calls
        return transport

    def test_rate_limit_caps_probes(self):
        transport = self._transport()
        result = run_intruder(self._request(), self._scope(), "q", "rce",
                              transport=transport, max_probes=2, payload_db=self._db(n=5))
        self.assertEqual(result["probes_sent"], 2)
        self.assertEqual(result["probe_limit"], 2)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(len(transport.calls), 2)
        for c in transport.calls:  # every probe stays on the allowlisted origin
            self.assertTrue(c["url"].startswith("https://target.local/"))

    def test_delay_sleeps_between_probes_only(self):
        transport = self._transport()
        with unittest.mock.patch("time.sleep") as fake_sleep:
            result = run_intruder(self._request(), self._scope(), "q", "rce",
                                  transport=transport, delay=0.5, max_probes=10,
                                  payload_db=self._db(n=4))
        self.assertEqual(fake_sleep.call_count, 3)  # n-1: never sleeps before the first probe
        for call in fake_sleep.call_args_list:
            self.assertEqual(call.args, (0.5,))
        self.assertEqual(result["delay_seconds"], 0.5)

    def test_delay_clamped_to_minimum(self):
        transport = self._transport()
        result = run_intruder(self._request(), self._scope(), "q", "rce",
                              transport=transport, delay=0.01, max_probes=5,
                              payload_db=self._db(n=1))
        self.assertEqual(result["delay_seconds"], 0.1)

    def test_out_of_scope_redirect_never_followed(self):
        # unit: the strict handler refuses every redirect target
        self.assertIsNone(_NoRedirectHandler().redirect_request(
            None, None, 302, "Found", {}, "https://evil.tracker.com/x"))
        # fixture: a 302 response is recorded as-is; no second request to the redirect target
        transport = self._transport(body="", status=302)
        result = run_intruder(self._request(), self._scope(), "q", "rce",
                              transport=transport, max_probes=3, payload_db=self._db(n=1))
        self.assertEqual(result["probes_sent"], 1)
        self.assertEqual(result["results"][0]["status"], 302)
        self.assertTrue(all(c["url"].startswith("https://target.local/") for c in transport.calls))
        self.assertFalse(any("evil.tracker.com" in c["url"] for c in transport.calls))

    def test_marker_reflection_counts_as_hit(self):
        # simulated vulnerable app: decodes the param and echoes it back
        def reflected_transport(url, method, headers):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["q"][0]
            body = urllib.parse.unquote(q)
            return {"status": 200, "content_type": "text/html",
                    "body_bytes": len(body), "body_sha256": "0" * 64, "body": body}

        db = {"rce": [{"id": "rce_marker", "value": "; echo MITR3_{token}", "detects": []}]}
        result = run_intruder(self._request(), self._scope(), "q", "rce",
                              transport=reflected_transport, payload_db=db)
        self.assertTrue(result["results"][0]["marker_observed"])
        self.assertIn("rce_marker", result["hit_probe_ids"])

    def test_parameter_must_appear_exactly_once(self):
        with self.assertRaises(ValueError):
            run_intruder(self._request(url="https://target.local/s?q=1&q=2"),
                         self._scope(), "q", "rce", payload_db=self._db(n=1))
        with self.assertRaises(ValueError):
            run_intruder(self._request(url="https://target.local/s?other=1"),
                         self._scope(), "q", "rce", payload_db=self._db(n=1))

    def test_canary_required_for_any_kind_with_canary_payload(self):
        db = {"rce": [{"id": "rce_oob", "value": "; curl {canary}", "detects": []}]}
        # no canary_url at all: engine must refuse, whatever the kind
        with self.assertRaises(ValueError):
            run_intruder(self._request(), self._scope(), "q", "rce", payload_db=db)
        # approved canary on a separate allowlisted origin: run proceeds
        scope = ScopePolicy(allowed_origins=["https://target.local", "https://canary.example.com"])
        transport = self._transport()
        result = run_intruder(self._request(), scope, "q", "rce", canary_url="https://canary.example.com/hook",
                              transport=transport, payload_db=db)
        self.assertEqual(result["probes_sent"], 1)
        self.assertTrue(result["canary_correlation"])
        # probe stays on the target origin; the canary URL travels inside the parameter value
        self.assertTrue(transport.calls[0]["url"].startswith("https://target.local/"))


class TestAntiFalsePositives(unittest.TestCase):
    """BlackOps: negative anti-FP validation for candidate parameters and benign bodies."""

    NEGATIVE_PARAMS = ["hostname", "executor", "basename", "context", "sort", "email",
                       "count", "color", "description", "reference", "host_name", "reexec"]

    POSITIVE_PARAMS = ["cmd", "file", "url"]

    BENIGN_BODIES = [
        "Your order 4711 was shipped. reference id=4711 (2026-11-11).",
        "Error: file 'settings.py' not found in directory listing",
        "session uid=42 updated profile",
        "user localhost_dev logged in",
        "The template engine compiles templates on demand",
    ]

    def test_benign_params_are_not_candidates(self):
        # 'description' contains 'script', 'executor' contains 'exec' — word boundaries must reject both
        self.assertEqual(IndicatorDetector.check_param_indicators(self.NEGATIVE_PARAMS), [])

    def test_positive_params_still_detected(self):
        out = IndicatorDetector.check_param_indicators(self.POSITIVE_PARAMS)
        self.assertEqual({i["param"] for i in out}, set(self.POSITIVE_PARAMS))

    def test_benign_bodies_have_no_diagnostic_hits(self):
        for body in self.BENIGN_BODIES:
            self.assertEqual(IndicatorDetector.check_response_diagnostics(body), [],
                             f"false positive on: {body[:50]}")


class TestPhase5SelfHostedCanary(unittest.TestCase):
    """M5: self-hosted OOB canary — callbacks observed on our own listener. Loopback only."""

    def setUp(self):
        self.scope = ScopePolicy(allowed_origins=["https://target.example", "https://oast.example"])
        self.request = {
            "raw_event": "request", "request_id": "req.1", "method": "GET",
            "url": "https://target.example/fetch?url=x", "headers": {}
        }

    def test_canary_listener_records_and_matches_hits(self):
        listener = CanaryListener(port=0)
        listener.start()
        try:
            secret = secrets.token_hex(8)
            url = listener.canary_url(secret)
            with urllib.request.urlopen(url + "?probe=1", timeout=5) as resp:
                self.assertEqual(resp.read(), b"mitr3-canary-ok")
            hits = listener.wait_hits(secret, timeout=2)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["source_ip"], "127.0.0.1")
            self.assertEqual(hits[0]["method"], "GET")
            self.assertIn(secret, hits[0]["path"])
            self.assertEqual(listener.wait_hits("no-such-token", timeout=0.2), [])
        finally:
            listener.stop()

    def test_canary_listener_stop_closes_port(self):
        listener = CanaryListener(port=0)
        listener.start()
        port = listener.port
        listener.stop()
        with self.assertRaises(Exception):
            urllib.request.urlopen(f"http://127.0.0.1:{port}/x/", timeout=2)

    def test_self_hosted_canary_accepts_private_http_and_validates_scope(self):
        # private http canary accepted in self-hosted mode when its origin is allowlisted
        scope = ScopePolicy(allowed_origins=["http://10.66.0.9:8993", "https://target.example"])
        parsed = _validate_ssrf_canary("http://10.66.0.9:8993/abc/", scope, "https://target.example/fetch",
                                       self_hosted=True)
        self.assertEqual(parsed.hostname, "10.66.0.9")
        # public mode still rejects the same URL (private IP)
        with self.assertRaises(ValueError):
            _validate_ssrf_canary("http://10.66.0.9:8993/abc/", scope, "https://target.example/fetch")
        # self-hosted still rejects credentials
        with self.assertRaises(ValueError):
            _validate_ssrf_canary("http://user:pw@10.66.0.9:8993/", scope, "https://target.example/fetch",
                                  self_hosted=True)
        # and still rejects the target's own origin (different scheme, same host = out of scope -> PermissionError)
        with self.assertRaises(PermissionError):
            _validate_ssrf_canary("http://target.example/x", scope, "https://target.example/fetch",
                                  self_hosted=True)
        # true same-origin (allowlisted canary, same origin as target) -> separate-origin ValueError
        with self.assertRaises(ValueError):
            _validate_ssrf_canary("https://target.example/canary", scope, "https://target.example/fetch",
                                  self_hosted=True)

    def test_probe_self_hosted_oob_end_to_end(self):
        listener = CanaryListener(port=0)
        listener.start()
        try:
            secret = secrets.token_hex(8)
            canary = listener.canary_url(secret)
            scope = ScopePolicy(allowed_origins=["https://target.example", f"http://127.0.0.1:{listener.port}"])

            def transport(url, method, headers):
                value = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["url"][0]
                if "127.0.0.1" in value:
                    # "vulnerable" target performs the SSRF callback for real, on loopback
                    urllib.request.urlopen(value, timeout=5).read()
                return {"status": 200, "content_type": "text/plain", "body_bytes": 0,
                        "body_sha256": "f" * 64, "body": ""}

            result = run_probe(self.request, scope, "ssrf", "url", canary,
                               transport=transport, self_hosted=True)
            self.assertIsNotNone(result["canary_correlation"])
            hits = listener.wait_hits(secret, timeout=3)
            self.assertEqual(len(hits), 1)
            self.assertIn("mitr3_probe", hits[0]["query"])
        finally:
            listener.stop()

    def test_intruder_self_hosted_mode_flag_reaches_validation(self):
        # private http canary rejected in public mode even with kind=ssrf (flag not set)
        calls = []
        with self.assertRaises(ValueError):
            run_intruder(self.request, self.scope, "url", "ssrf", canary_url="http://127.0.0.1:8993/x/",
                         transport=lambda *a: calls.append(a))
        self.assertEqual(calls, [])


class TestAgentAuthorizedExecution(unittest.TestCase):
    """Standing operator authorization: execution lane runs active ops without an interactive TTY.
    Scope, preflight, evidence and identity gates stay intact."""

    def _capture(self, tmpdir, url):
        human = Path(tmpdir) / "human-only"
        human.mkdir(mode=0o700)
        capture = human / "s.raw.jsonl"
        capture.write_text(json.dumps({
            "raw_event": "request", "request_id": "req.1", "method": "GET",
            "url": url, "headers": {}
        }) + "\n", encoding="utf-8")
        os.chmod(capture, 0o600)
        return str(capture)

    def test_agent_authorized_confirm_works_without_tty(self):
        request = {"raw_event": "request", "request_id": "req.1", "method": "GET",
                   "url": "https://target.example/x", "headers": {}}
        with unittest.mock.patch("sys.stdin") as fake_stdin:
            fake_stdin.isatty.return_value = False
            with self.assertRaises(PermissionError):
                _confirm_phase2("REPLAY", request)  # no TTY, no agent flag -> blocked
            self.assertTrue(_confirm_phase2("REPLAY", request, agent_authorized=True))  # standing auth -> allowed

    def test_agent_authorized_cli_end_to_end_loopback(self):
        listener = CanaryListener(port=0)
        listener.start()
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                capture = self._capture(tmpdir, f"http://127.0.0.1:{listener.port}/page")
                scope_origin = f"http://127.0.0.1:{listener.port}"
                with unittest.mock.patch.dict(os.environ, {"MITR3_AGENT": "opencode-exec"}):
                    rc = phase2_cli("REPLAY", [capture, "--request-id", "req.1",
                                               "--allow-origin", scope_origin, "--agent-authorized"])
                self.assertEqual(rc, 0)
                probes = sorted((Path(tmpdir) / "human-only" / "probes").glob("phase2_*.json"))
                self.assertEqual(len(probes), 1)
                sealed = json.load(open(probes[0]))
                self.assertEqual(sealed["authorization"]["mode"], "agent_standing")
                self.assertEqual(sealed["authorization"]["agent"], "opencode-exec")
                self.assertEqual(sealed["response"]["status"], 200)
        finally:
            listener.stop()

    def test_agent_authorized_requires_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            capture = self._capture(tmpdir, "http://127.0.0.1:9/page")
            env = {k: v for k, v in os.environ.items() if k != "MITR3_AGENT"}
            with unittest.mock.patch.dict(os.environ, env, clear=True):
                rc = phase2_cli("REPLAY", [capture, "--request-id", "req.1",
                                           "--allow-origin", "http://127.0.0.1:9", "--agent-authorized"])
            self.assertEqual(rc, 1)  # identity gate: no MITR3_AGENT, no run


class TestCanaryHardening(unittest.TestCase):
    """PIP's opsec notes: single accepted endpoint (rest 404), rotated JSONL callback log."""

    def test_single_endpoint_404_and_match_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log = str(Path(tmpdir) / "canary_hits.jsonl")
            listener = CanaryListener(port=0, accept_path="SECRET123", log_file=log)
            listener.start()
            try:
                with urllib.request.urlopen(listener.canary_url("SECRET123"), timeout=5) as r:
                    self.assertEqual(r.status, 200)
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(f"http://127.0.0.1:{listener.port}/other-path/", timeout=5)
                self.assertEqual(ctx.exception.code, 404)
                self.assertEqual(len(listener.hits), 2)  # the 404 probe is still evidence
                self.assertEqual([h["matched"] for h in listener.hits], [True, False])
            finally:
                listener.stop()
            lines = [json.loads(l) for l in open(log) if l.strip()]
            self.assertEqual(len(lines), 2)

    def test_log_rotation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log = str(Path(tmpdir) / "canary_hits.jsonl")
            listener = CanaryListener(port=0, accept_path=None, log_file=log, max_log_bytes=1)
            listener.start()
            try:
                urllib.request.urlopen(listener.canary_url("a"), timeout=5).read()
                urllib.request.urlopen(listener.canary_url("b"), timeout=5).read()
            finally:
                listener.stop()
            self.assertTrue(os.path.exists(log + ".1"))  # tiny cap forces rotation
            self.assertTrue(os.path.exists(log))


class TestCanaryLogEvidence(unittest.TestCase):
    """M5 hardening: canary JSONL evidence log — per-hit write and rotation at max_log_bytes. Loopback only."""

    def _listener(self, tmpdir, **kw):
        listener = CanaryListener(host="127.0.0.1", port=0,
                                  log_file=str(Path(tmpdir) / "probes" / "canary_hits.jsonl"), **kw)
        listener.start()
        self.addCleanup(listener.stop)
        return listener

    @staticmethod
    def _get(url):
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    def test_hit_written_as_sealed_jsonl_line(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            listener = self._listener(tmpdir)
            secret = secrets.token_hex(8)
            listener.accept_path = secret
            status, body = self._get(listener.canary_url(secret))
            self.assertEqual(status, 200)
            log_path = Path(tmpdir) / "probes" / "canary_hits.jsonl"
            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            hit = json.loads(lines[0])
            self.assertTrue(hit["matched"])
            self.assertIn(secret, hit["path"])
            self.assertIn("ts", hit)
            self.assertIn("source_ip", hit)

    def test_log_rotates_at_max_bytes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            listener = self._listener(tmpdir, max_log_bytes=1)
            secret = secrets.token_hex(8)
            listener.accept_path = secret  # both requests are logged, only the secret gets 200
            self._get(listener.canary_url(secret))
            self._get(f"http://127.0.0.1:{listener.port}/other-path/")
            log_path = Path(tmpdir) / "probes" / "canary_hits.jsonl"
            rotated = Path(str(log_path) + ".1")
            self.assertEqual(len(rotated.read_text(encoding="utf-8").splitlines()), 1)  # 1st hit
            self.assertEqual(len(log_path.read_text(encoding="utf-8").splitlines()), 1)  # 2nd hit
            self.assertTrue(json.loads(rotated.read_text(encoding="utf-8").splitlines()[0])["matched"])


class TestFullCycleRealFetchSurface(unittest.TestCase):
    """Rehearsal of the authorized cycle (probe → intruder → OOB) against a REAL local HTTP surface.
    The fixture app is vulnerable-by-contract: /fetch?url=<value> performs a server-side fetch of the
    value and reflects the response — the same shape the duo will meet on the next live target.
    Loopback only; stdlib only."""

    @staticmethod
    def _start_app():
        class VulnApp(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                target = (q.get("url") or [""])[0]
                if target:
                    # direct opener: loopback fetch must not be hijacked by ambient proxy env
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    try:
                        with opener.open(target, timeout=1) as resp:
                            out = b"Fetched: " + resp.read(4096)
                    except OSError as exc:
                        out = f"Fetch failed: {exc}".encode()
                else:
                    out = b"no url param"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), VulnApp)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def setUp(self):
        self.app = self._start_app()
        self.addCleanup(self.app.shutdown)
        self.addCleanup(self.app.server_close)
        self.app_port = self.app.server_address[1]

    def _cycle(self, log_file=None):
        listener = CanaryListener(host="127.0.0.1", port=0, log_file=log_file)
        listener.start()
        self.addCleanup(listener.stop)
        secret = secrets.token_hex(8)
        listener.accept_path = secret  # single-endpoint: only this run's secret gets 200
        canary_url = listener.canary_url(secret)
        scope = ScopePolicy(allowed_origins=[f"http://127.0.0.1:{self.app_port}",
                                             f"http://127.0.0.1:{listener.port}"])
        request = {"raw_event": "request", "request_id": "cycle.1", "method": "GET",
                   "url": f"http://127.0.0.1:{self.app_port}/fetch?url=start", "headers": {}}
        return listener, secret, canary_url, scope, request

    def test_probe_then_intruder_oob_lands_on_canary(self):
        listener, secret, canary_url, scope, request = self._cycle()
        probe = run_probe(request, scope, "ssrf", "url", canary_url, self_hosted=True)
        self.assertEqual(probe["probe_type"], "ssrf")
        self.assertGreaterEqual(len(listener.wait_hits(secret, timeout=1.0)), 1)  # probe alone reaches OOB
        result = run_intruder(request, scope, "url", "ssrf", canary_url,
                              delay=0.1, max_probes=30, self_hosted=True)
        self.assertEqual(result["probes_sent"], 11)
        self.assertTrue(result["canary_correlation"])
        hits = listener.wait_hits(secret, timeout=3)
        # 3 canary-bearing payloads in the ssrf family (plain, path, token_query) + 1 probe
        self.assertGreaterEqual(len(hits), 4)
        self.assertTrue(all(h["matched"] for h in hits))

    def test_oob_callbacks_sealed_in_jsonl_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            listener, secret, canary_url, scope, request = self._cycle(
                log_file=str(Path(tmpdir) / "probes" / "canary_hits.jsonl"))
            run_probe(request, scope, "ssrf", "url", canary_url, self_hosted=True)
            run_intruder(request, scope, "url", "ssrf", canary_url,
                         delay=0.1, max_probes=30, self_hosted=True)
            log_path = Path(tmpdir) / "probes" / "canary_hits.jsonl"
            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(len(lines), 4)
            parsed = [json.loads(line) for line in lines]
            self.assertTrue(all(h["matched"] and h["source_ip"] == "127.0.0.1" for h in parsed))

if __name__ == "__main__":
    unittest.main()
