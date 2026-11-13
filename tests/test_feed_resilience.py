"""Feed sync resilience: retry, checksum/structure checks, and cache fallback. No network."""
import base64
import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mitr3_feed_resilience", ROOT / "bin/mitr3-rag-intel.py")
intel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(intel)


def kev_bytes(count=100, declared=None, cve_ok=True):
    vulns = []
    for i in range(1, count + 1):
        vulns.append({
            "cveID": f"CVE-2024-{i:04d}" if cve_ok else "not-a-cve",
            "vendorProject": "Vendor", "product": "Product", "vulnerabilityName": "Name",
            "dateAdded": "2024-01-02", "shortDescription": "Short", "requiredAction": "Patch",
            "dueDate": "2024-02-02", "cwes": ["CWE-79"],
        })
    body = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2024.01.02",
            "dateReleased": "2024-01-02T00:00:00.0000Z", "count": count if declared is None else declared,
            "vulnerabilities": vulns}
    return json.dumps(body).encode()


def asvs_bytes(version="5.0.0"):
    requirements = [{
        "Name": "Chapter",
        "Items": [{"Name": "Section", "Items": [{"Shortcode": f"1.2.{i}", "Description": "Check control"}]}],
    } for i in range(12)]
    return json.dumps({"Name": "ASVS", "Version": version, "Requirements": requirements}).encode()


class Body:
    def __init__(self, url, payload, headers=None):
        self._url = url
        self._payload = payload
        self.headers = headers or {}

    def geturl(self):
        return self._url

    def read(self, n=-1):
        if n is None or n < 0 or n >= len(self._payload):
            data, self._payload = self._payload, b""
            return data
        data, self._payload = self._payload[:n], self._payload[n:]
        return data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def digest_header(payload):
    token = base64.b64encode(hashlib.sha256(payload).digest()).decode()
    return {"Content-Digest": "sha-256=:" + token + ":"}


class FeedResilienceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.cache = base / "cache"
        self.cache.mkdir()
        self.manifest_path = self.cache / "manifest.json"
        self.patch = mock.patch.multiple(intel, CACHE=self.cache, MANIFEST=self.manifest_path)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.sleep = mock.patch.object(intel.time, "sleep").start()
        self.addCleanup(self.sleep.stop)
        self.kev = kev_bytes()
        self.asvs = asvs_bytes()
        self.checked_at = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=5)).isoformat()

    def seed(self, name, payload, checked_at=None):
        path = self.cache / (name + ".json")
        path.write_bytes(payload)
        manifest = {}
        if self.manifest_path.exists():
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        manifest[name] = {"source": name, "url": intel.URLS[name], "bytes": len(payload),
                          "sha256": hashlib.sha256(payload).hexdigest(),
                          "checked_at": checked_at or self.checked_at, "item_count": 1, "fallback": False}
        self.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def route(self, kev_plan, asvs_plan):
        """kev_plan/asvs_plan: list of payloads, headers, or exceptions. Cycles the last item."""
        plans = {intel.URLS["cisa-kev"]: list(kev_plan), intel.URLS["owasp-asvs-5.0.0"]: list(asvs_plan)}
        seen = {url: 0 for url in plans}

        def urlopen(req, timeout=None):
            self.assertEqual(timeout, intel.FETCH_TIMEOUT)
            self.assertEqual(req.get_header("Accept"), "application/json")
            url = req.full_url
            plan = plans[url]
            index = min(seen[url], len(plan) - 1)
            seen[url] += 1
            item = plan[index]
            if isinstance(item, BaseException):
                raise item
            payload, headers = item if isinstance(item, tuple) else (item, None)
            return Body(url, payload, headers)

        return urlopen, seen

    def sync_with(self, kev_plan, asvs_plan):
        urlopen, seen = self.route(kev_plan, asvs_plan)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(intel.urllib.request, "urlopen", side_effect=urlopen):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                intel.sync()
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return manifest, stdout.getvalue(), stderr.getvalue(), seen

    def test_success_writes_cache_without_fallback(self):
        manifest, log, err, seen = self.sync_with([self.kev], [self.asvs])
        self.assertEqual(seen[intel.URLS["cisa-kev"]], 1)
        self.assertEqual(seen[intel.URLS["owasp-asvs-5.0.0"]], 1)
        self.assertFalse(self.sleep.called)
        self.assertFalse(manifest["cisa-kev"]["fallback"])
        self.assertFalse(manifest["owasp-asvs-5.0.0"]["fallback"])
        self.assertEqual(manifest["cisa-kev"]["sha256"], hashlib.sha256(self.kev).hexdigest())
        self.assertEqual((self.cache / "cisa-kev.json").read_bytes(), self.kev)
        self.assertIn("FETCH_OK cisa-kev", log)
        self.assertNotIn("FETCH_CACHE_FALLBACK", log)
        self.assertEqual(err, "")
        for name in intel.URLS:
            intel.check_manifest(name, manifest)

    def test_retry_then_success_uses_exponential_backoff(self):
        plan = [urllib.error.URLError("reset"), TimeoutError("slow"), self.kev]
        manifest, log, err, seen = self.sync_with(plan, [self.asvs])
        self.assertEqual(seen[intel.URLS["cisa-kev"]], 3)
        self.assertEqual([call.args[0] for call in self.sleep.call_args_list],
                         [intel.FETCH_BACKOFF, intel.FETCH_BACKOFF * 2])
        self.assertFalse(manifest["cisa-kev"]["fallback"])
        self.assertEqual((self.cache / "cisa-kev.json").read_bytes(), self.kev)
        self.assertIn("FETCH_RETRY cisa-kev attempt 1", log)
        self.assertIn("FETCH_RETRY cisa-kev attempt 2", log)
        self.assertNotIn("attempt 3", log)
        self.assertEqual(err, "")

    def test_corrupt_payload_falls_back_and_keeps_cache(self):
        self.seed("cisa-kev", self.kev)
        self.seed("owasp-asvs-5.0.0", self.asvs)
        manifest, log, err, seen = self.sync_with([b"{not-json"], [self.asvs])
        self.assertEqual(seen[intel.URLS["cisa-kev"]], intel.FETCH_ATTEMPTS)
        self.assertEqual((self.cache / "cisa-kev.json").read_bytes(), self.kev)
        row = manifest["cisa-kev"]
        self.assertTrue(row["fallback"])
        self.assertEqual(row["checked_at"], self.checked_at)
        self.assertEqual(row["sha256"], hashlib.sha256(self.kev).hexdigest())
        self.assertGreaterEqual(row["cache_age_seconds"], 5 * 3600 - 5)
        self.assertLess(row["cache_age_seconds"], 5 * 3600 + 30)
        self.assertIn("FETCH_CACHE_FALLBACK cisa-kev", log)
        self.assertIn("cache_age_seconds " + str(row["cache_age_seconds"]), log)
        self.assertIn(self.checked_at, log)
        self.assertIn("FETCH_CACHE cisa-kev", log)
        self.assertFalse(manifest["owasp-asvs-5.0.0"]["fallback"])
        self.assertIn("FETCH_OK owasp-asvs-5.0.0", log)
        intel.check_manifest("cisa-kev", manifest)

    def test_count_mismatch_and_bad_checksum_do_not_replace_cache(self):
        self.seed("cisa-kev", self.kev)
        mismatched = kev_bytes(declared=101)
        bad_header = {"Content-Digest": "sha-256=:" + base64.b64encode(b"\x00" * 32).decode() + ":"}
        manifest, log, _, _ = self.sync_with([(mismatched, None), (self.kev, bad_header)], [self.asvs])
        self.assertTrue(manifest["cisa-kev"]["fallback"])
        self.assertEqual((self.cache / "cisa-kev.json").read_bytes(), self.kev)
        self.assertIn("FETCH_CACHE_FALLBACK cisa-kev", log)
        # A declared checksum that matches is accepted and replaces the cache.
        manifest, log, _, seen = self.sync_with([(self.kev, digest_header(self.kev))], [self.asvs])
        self.assertEqual(seen[intel.URLS["cisa-kev"]], 1)
        self.assertFalse(manifest["cisa-kev"]["fallback"])
        self.assertEqual((self.cache / "cisa-kev.json").read_bytes(), self.kev)
        self.assertNotIn("FETCH_CACHE_FALLBACK", log)

    def test_asvs_failure_does_not_drop_a_fresh_kev_sync(self):
        self.seed("owasp-asvs-5.0.0", self.asvs)
        manifest, log, _, _ = self.sync_with([self.kev], [asvs_bytes(version="9.9.9")])
        self.assertFalse(manifest["cisa-kev"]["fallback"])
        self.assertTrue(manifest["owasp-asvs-5.0.0"]["fallback"])
        self.assertEqual(manifest["owasp-asvs-5.0.0"]["checked_at"], self.checked_at)
        self.assertIn("FETCH_OK cisa-kev", log)
        self.assertIn("FETCH_CACHE_FALLBACK owasp-asvs-5.0.0", log)
        self.assertIn("cache_age_seconds", log)
        intel.check_manifest("cisa-kev", manifest)
        intel.check_manifest("owasp-asvs-5.0.0", manifest)

    def test_missing_cache_fails_closed(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(intel.urllib.request, "urlopen", side_effect=urllib.error.URLError("down")):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(urllib.error.URLError):
                    intel.sync()
        self.assertFalse((self.cache / "cisa-kev.json").exists())
        self.assertIn("FETCH_FAILED cisa-kev", stderr.getvalue())
        self.assertIn("no_valid_cache", stderr.getvalue())
        self.assertEqual(self.sleep.call_count, intel.FETCH_ATTEMPTS - 1)

    def test_redirect_off_host_is_not_cached(self):
        self.seed("cisa-kev", self.kev)

        def urlopen(req, timeout=None):
            if req.full_url == intel.URLS["cisa-kev"]:
                return Body("https://evil.example/feed.json", self.kev)
            return Body(req.full_url, self.asvs)

        stdout = io.StringIO()
        with mock.patch.object(intel.urllib.request, "urlopen", side_effect=urlopen):
            with contextlib.redirect_stdout(stdout):
                intel.sync()
        self.assertEqual((self.cache / "cisa-kev.json").read_bytes(), self.kev)
        self.assertIn("FETCH_CACHE_FALLBACK cisa-kev", stdout.getvalue())
        self.assertIn("cache_age_seconds", stdout.getvalue())

    def test_catalog_count_guard(self):
        with self.assertRaisesRegex(ValueError, "count mismatch"):
            intel.check_structure("cisa-kev", json.loads(kev_bytes(declared=50)))
        intel.check_structure("cisa-kev", json.loads(self.kev))

    def test_declared_checksum_headers(self):
        digest = hashlib.sha256(self.kev).hexdigest()
        self.assertEqual(intel.declared_sha256({"x-checksum-sha256": "sha256:" + digest}), digest)
        self.assertIsNone(intel.declared_sha256({}))
        self.assertIsNone(intel.declared_sha256(None))
        with self.assertRaisesRegex(ValueError, "no sha-256"):
            intel.declared_sha256({"Digest": "sha-512=:YQ==:"})
        with self.assertRaisesRegex(ValueError, "Unreadable"):
            intel.declared_sha256({"x-checksum-sha256": "zz"})
        other = base64.b64encode(b"\x11" * 32).decode()
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            intel.declared_sha256({"x-checksum-sha256": digest, "Content-Digest": "sha-256=:" + other + ":"})


class RefreshPipelineTests(unittest.TestCase):
    def test_sync_timeout_covers_retries_and_fallback_log_is_visible(self):
        spec = importlib.util.spec_from_file_location(
            "mitr3_refresh_resilience", ROOT / "bin/mitr3-rag-intel-refresh.py")
        refresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(refresh)
        completed = mock.Mock(returncode=0, stdout="FETCH_CACHE_FALLBACK cisa-kev cache_age_seconds 90\n", stderr="")
        with mock.patch.object(refresh.subprocess, "run", return_value=completed) as run:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                refresh.run("sync")
        self.assertEqual(run.call_args.kwargs["timeout"], 180)
        self.assertIn("FETCH_CACHE_FALLBACK", stdout.getvalue())
        self.assertIn("cache_age_seconds 90", stdout.getvalue())
