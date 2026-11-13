#!/usr/bin/env python3
"""Regras determinísticas de prioridade de alerta CVE: cada faixa, empate e dado ausente."""
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mitr3_cve_priority", ROOT / "bin/mitr3-cve-priority.py")
priority = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = priority
SPEC.loader.exec_module(priority)

REFRESH_SPEC = importlib.util.spec_from_file_location(
    "mitr3_rag_refresh_for_priority", ROOT / "bin/mitr3-rag-intel-refresh.py")
refresh = importlib.util.module_from_spec(REFRESH_SPEC)
sys.modules[REFRESH_SPEC.name] = refresh
REFRESH_SPEC.loader.exec_module(refresh)

CVE = "CVE-2024-1000"


def snapshot_body(vendor="Acme"):
    return {"dateAdded": "2026-11-01", "vendorProject": vendor, "product": "Widget",
            "vulnerabilityName": "Example", "knownRansomwareCampaignUse": "Unknown"}


class RuleTests(unittest.TestCase):
    def test_kev_alone_is_p1_and_cites_cisa_and_nvd(self):
        verdict = priority.prioritize({"cve": CVE, "in_kev": True, "date_added": "2026-11-01"})
        self.assertEqual(verdict.level, "P1")
        self.assertEqual(verdict.deciding_rule, "kev_listed")
        self.assertEqual(verdict.matched_rules, ("kev_listed",))
        self.assertIn("kev_listed", verdict.justification)
        self.assertIn("CISA KEV", verdict.justification)
        text = verdict.to_dict()["text"]
        self.assertTrue(text.startswith("[P1] " + CVE))
        self.assertIn("Prioridade: P1", text)
        self.assertEqual(verdict.sources[0]["id"], "cisa_kev")
        self.assertIn(CVE, verdict.sources[0]["url"])
        self.assertIn("https://nvd.nist.gov/vuln/detail/" + CVE, text)
        self.assertNotIn("first.org", text)

    def test_kev_wins_over_epss_and_cvss(self):
        verdict = priority.prioritize({
            "cve": CVE, "in_kev": True, "epss": 0.9, "cvss": 10, "severity": "CRITICAL"})
        self.assertEqual(verdict.level, "P1")
        self.assertEqual(verdict.deciding_rule, "kev_listed")
        self.assertEqual(verdict.matched_rules, ("kev_listed", "epss_at_least_p2", "cvss_at_least_p2"))

    def test_explicit_not_in_kev_does_not_infer_catalog(self):
        verdict = priority.prioritize({"cve": CVE, "in_kev": False})
        self.assertEqual(verdict.level, "P4")
        self.assertIn("fora do CISA KEV", verdict.justification)
        self.assertNotIn("cisa.gov", verdict.to_dict()["text"])

    def test_unknown_kev_is_not_treated_as_listed(self):
        verdict = priority.prioritize({"cve": CVE})
        self.assertIsNone(verdict.inputs["in_kev"])
        self.assertEqual(verdict.level, "P4")
        self.assertEqual(verdict.deciding_rule, "no_elevating_signal")
        self.assertIn("não há sinal de presença no CISA KEV", verdict.justification)

    def test_illegible_kev_flag_does_not_raise(self):
        verdict = priority.prioritize({"cve": CVE, "in_kev": "yes"})
        self.assertIsNone(verdict.inputs["in_kev"])
        self.assertEqual(verdict.level, "P4")
        self.assertIn("in_kev ilegível", verdict.justification)

    def test_intel_kev_row_is_p1_without_rereading_the_feed(self):
        verdict = priority.prioritize({
            "id": "CVE-2020-1472", "source": "cisa-kev", "kind": "known_exploited_catalog"})
        self.assertEqual(verdict.cve, "CVE-2020-1472")
        self.assertEqual(verdict.level, "P1")
        self.assertEqual(verdict.deciding_rule, "kev_listed")

    def test_other_intel_source_is_not_kev(self):
        verdict = priority.prioritize({"cve": CVE, "source": "public-cases", "kind": "writeup"})
        self.assertIs(verdict.inputs["in_kev"], False)
        self.assertEqual(verdict.level, "P4")

    def test_epss_threshold_is_inclusive_p2(self):
        on_threshold = priority.prioritize({"cve": CVE, "epss": 0.10})
        self.assertEqual(on_threshold.deciding_rule, "epss_at_least_p2")
        self.assertIn("limiar 0.10", on_threshold.justification)
        below = priority.prioritize({"cve": CVE, "epss": 0.099})
        self.assertEqual(below.level, "P3")
        self.assertEqual(below.deciding_rule, "epss_at_least_p3")
        self.assertEqual(priority.prioritize({"cve": CVE, "epss": 0.019}).level, "P4")

    def test_epss_p2_cites_first_and_names_the_rule(self):
        verdict = priority.prioritize({"cve": CVE, "in_kev": False, "epss": "0.97660"})
        self.assertEqual(verdict.level, "P2")
        self.assertEqual(verdict.deciding_rule, "epss_at_least_p2")
        self.assertEqual(verdict.sources[0]["id"], "first_epss")
        self.assertIn("api.first.org", verdict.sources[0]["url"])
        self.assertIn(CVE, verdict.sources[0]["url"])
        self.assertNotIn("cisa.gov", verdict.to_dict()["text"])

    def test_cvss_bands_and_severity_without_score(self):
        self.assertEqual(priority.prioritize({"cve": CVE, "cvss": 7.0}).deciding_rule, "cvss_at_least_p2")
        self.assertEqual(priority.prioritize({"cve": CVE, "cvss": 4.0}).deciding_rule, "cvss_at_least_p3")
        self.assertEqual(priority.prioritize({"cve": CVE, "cvss": 3.9}).level, "P4")
        self.assertEqual(
            priority.prioritize({"cve": CVE, "severity": "critical"}).deciding_rule, "cvss_at_least_p2")
        self.assertEqual(priority.prioritize({"cve": CVE, "baseSeverity": "MEDIUM"}).level, "P3")
        self.assertEqual(priority.prioritize({"cve": CVE, "severity": "low"}).level, "P4")

    def test_numeric_cvss_wins_over_contradictory_severity(self):
        verdict = priority.prioritize({"cve": CVE, "cvss": 3.0, "severity": "CRITICAL"})
        self.assertEqual(verdict.level, "P4")
        self.assertIn("não substitui o score numérico", verdict.justification)
        high = priority.prioritize({"cve": CVE, "cvssScore": 9.8, "severity": "LOW"})
        self.assertEqual(high.deciding_rule, "cvss_at_least_p2")
        self.assertEqual(high.sources[0]["id"], "nvd")

    def test_same_level_tie_prefers_epss_and_records_both_rules(self):
        verdict = priority.prioritize({"cve": CVE, "epss": 0.2, "cvss": 8.8})
        self.assertEqual(verdict.level, "P2")
        self.assertEqual(verdict.deciding_rule, "epss_at_least_p2")
        self.assertEqual(verdict.matched_rules, ("epss_at_least_p2", "cvss_at_least_p2"))
        self.assertIn("Também dispararam: `cvss_at_least_p2`", verdict.justification)
        by_id = {rule.rule_id: rule for rule in verdict.rules}
        self.assertEqual(by_id["epss_at_least_p3"].status, "superseded")
        self.assertEqual(by_id["cvss_at_least_p3"].status, "superseded")
        self.assertNotIn("epss_at_least_p3", verdict.justification)
        self.assertNotIn("cvss_at_least_p3", verdict.justification)

    def test_higher_level_wins_when_signals_disagree(self):
        verdict = priority.prioritize({"cve": CVE, "epss": 0.05, "cvss": 8.0})
        self.assertEqual(verdict.level, "P2")
        self.assertEqual(verdict.deciding_rule, "cvss_at_least_p2")
        self.assertEqual(verdict.matched_rules, ("cvss_at_least_p2", "epss_at_least_p3"))

    def test_missing_scores_stay_p4_and_still_link_nvd(self):
        verdict = priority.prioritize({"cve": CVE})
        self.assertEqual(verdict.matched_rules, ("no_elevating_signal",))
        self.assertIsNone(verdict.inputs["cvss"])
        self.assertIsNone(verdict.inputs["epss"])
        text = verdict.to_dict()["text"]
        self.assertIn("[P4]", text)
        self.assertIn("no_elevating_signal", text)
        self.assertIn("https://nvd.nist.gov/vuln/detail/" + CVE, text)
        self.assertNotIn("first.org", text)
        self.assertNotIn("cisa.gov", text)

    def test_illegible_scores_do_not_break_the_alert(self):
        verdict = priority.prioritize({"cve": CVE, "cvss": "alto", "epss": True, "severity": "IMPORTANT"})
        self.assertEqual(verdict.level, "P4")
        self.assertIsNone(verdict.inputs["cvss"])
        self.assertIsNone(verdict.inputs["epss"])
        self.assertIsNone(verdict.inputs["severity"])
        self.assertGreaterEqual(len(verdict.inputs["notes"]), 3)

    def test_out_of_range_score_is_absent(self):
        verdict = priority.prioritize({"cve": CVE, "cvss": 10.1, "epss": 0})
        self.assertIsNone(verdict.inputs["cvss"])
        self.assertEqual(verdict.inputs["epss"], 0.0)
        self.assertEqual(verdict.level, "P4")
        self.assertIn("cvss fora de faixa", verdict.justification)

    def test_custom_thresholds_change_the_verdict(self):
        policy = priority.PriorityPolicy(epss_p2=0.5, epss_p3=0.2, cvss_p2=9.0, cvss_p3=5.0)
        self.assertEqual(priority.prioritize({"cve": CVE, "epss": 0.2}, policy=policy).level, "P3")
        self.assertEqual(priority.prioritize({"cve": CVE, "epss": 0.5}, policy=policy).deciding_rule, "epss_at_least_p2")
        self.assertEqual(priority.prioritize({"cve": CVE, "cvss": 8.8}, policy=policy).level, "P3")

    def test_invalid_thresholds_are_rejected(self):
        with self.assertRaises(ValueError):
            priority.PriorityPolicy(cvss_p3=9, cvss_p2=7)
        with self.assertRaises(ValueError):
            priority.PriorityPolicy(epss_p2=1.5)
        with self.assertRaises(ValueError):
            priority.PriorityPolicy(epss_p3=0.2, epss_p2=0.2)
        with self.assertRaises(ValueError):
            priority.policy_from_mapping({"MITR3_PRIORITY_CVSS_P2": "nope"})

    def test_library_defaults_ignore_process_environment(self):
        with mock.patch.dict("os.environ", {"MITR3_PRIORITY_EPSS_P2": "0.99"}):
            verdict = priority.prioritize({"cve": CVE, "epss": 0.2})
        self.assertEqual(verdict.level, "P2")
        self.assertEqual(verdict.inputs["thresholds"]["epss_p2"], 0.10)

    def test_policy_mapping_overrides_one_threshold(self):
        policy = priority.policy_from_mapping({"MITR3_PRIORITY_EPSS_P2": "0.5"})
        self.assertEqual(policy.epss_p2, 0.5)
        self.assertEqual(policy.epss_p3, 0.02)

    def test_invalid_cve_is_rejected(self):
        with self.assertRaises(ValueError):
            priority.prioritize({"cve": "not-a-cve"})
        with self.assertRaises(ValueError):
            priority.prioritize({"id": "CASE-example"})

    def test_prioritize_does_not_open_the_network(self):
        with mock.patch.object(priority, "_default_opener", side_effect=AssertionError("network")):
            verdict = priority.prioritize({"cve": CVE, "in_kev": True})
        self.assertEqual(verdict.level, "P1")

    def test_public_text_keeps_the_header_on_one_line(self):
        verdict = priority.prioritize({
            "cve": CVE, "in_kev": True, "vendor": "Acme\nInjected", "product": "Widget\x00X"})
        text = verdict.to_dict()["text"]
        self.assertIn("Acme Injected Widget X", text.splitlines()[0])
        self.assertNotIn("\nInjected", text)


class EpssLookupTests(unittest.TestCase):
    def _response(self, body, status=200):
        payload = body if isinstance(body, bytes) else body.encode()

        class Response:
            def read(self, _limit):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        response = Response()
        response.status = status
        return response

    def test_parses_public_epss_payload(self):
        body = json.dumps({"data": [{
            "cve": "CVE-2024-1000", "epss": "0.42000", "percentile": "0.91000", "date": "2026-11-12"}]})

        def opener(req, timeout):
            self.assertEqual(timeout, 5.0)
            self.assertEqual(req.full_url, priority.epss_url(CVE))
            self.assertEqual(req.get_header("Accept"), "application/json")
            return self._response(body)

        found = priority.lookup_epss(CVE, opener=opener)
        self.assertEqual(found.status, "ok")
        self.assertEqual(found.score, 0.42)
        self.assertEqual(found.percentile, 0.91)
        self.assertEqual(found.score_date, "2026-11-12")

    def test_rejects_cve_mismatch_empty_and_bad_score(self):
        mismatch = priority.parse_epss_payload(
            CVE, {"data": [{"cve": "CVE-1999-0001", "epss": "0.9"}]}, "https://api.first.org/x")
        self.assertEqual(mismatch.error, "cve_mismatch")
        self.assertIsNone(mismatch.score)
        empty = priority.parse_epss_payload(CVE, {"data": []}, "https://api.first.org/x")
        self.assertEqual(empty.error, "no_match")
        bad = priority.parse_epss_payload(CVE, {"data": [{"cve": CVE, "epss": "nope"}]}, "https://api.first.org/x")
        self.assertEqual(bad.error, "invalid_score")
        self.assertEqual(priority.parse_epss_payload(CVE, [], "https://api.first.org/x").error, "invalid_payload")

    def test_http_timeout_malformed_and_oversize_stay_unavailable(self):
        def timeout(_req, _timeout):
            raise TimeoutError("slow")

        def down(_req, _timeout):
            raise urllib.error.URLError("dns")

        def http(_req, _timeout):
            raise urllib.error.HTTPError("https://api.first.org/", 503, "nope", hdrs=None, fp=None)

        self.assertEqual(priority.lookup_epss(CVE, opener=timeout).error, "timeout")
        self.assertEqual(priority.lookup_epss(CVE, opener=down).error, "network_error")
        self.assertEqual(priority.lookup_epss(CVE, opener=http).error, "http_status")
        status = priority.lookup_epss(CVE, opener=lambda _req, _timeout: self._response(b"{}", status=503))
        self.assertEqual(status.error, "http_status")
        broken = priority.lookup_epss(CVE, opener=lambda _req, _timeout: self._response(b"not-json"))
        self.assertEqual(broken.error, "invalid_json")
        huge = priority.lookup_epss(
            CVE, max_bytes=8, opener=lambda _req, _timeout: self._response(b'{"data":[{"cve":"CVE-2024-1000"}]}'))
        self.assertEqual(huge.error, "oversize")

    def test_invalid_cve_never_calls_the_opener(self):
        def opener(_req, _timeout):
            raise AssertionError("network")

        found = priority.lookup_epss("../etc/passwd", opener=opener)
        self.assertEqual(found.error, "invalid_cve")
        self.assertIsNone(found.source_url)

    def test_redirect_stays_on_first_https(self):
        handler = priority._PinHost()
        req = urllib.request.Request(priority.epss_url(CVE))
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/steal")
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(req, None, 302, "Found", {}, "http://api.first.org/data/v1/epss")
        allowed = handler.redirect_request(req, None, 302, "Found", {}, priority.epss_url(CVE))
        self.assertEqual(allowed.get_full_url(), priority.epss_url(CVE))

    def test_failed_lookup_still_produces_an_alert(self):
        def opener(_req, _timeout):
            raise TimeoutError("slow")

        found = priority.lookup_epss(CVE, opener=opener)
        verdict = priority.prioritize({"cve": CVE, "epss_error": found.error})
        self.assertEqual(verdict.level, "P4")
        self.assertIsNone(verdict.inputs["epss"])
        self.assertIn("EPSS indisponível (timeout)", verdict.justification)


class DeltaTests(unittest.TestCase):
    def test_compare_addition_becomes_p1_without_touching_ingestion(self):
        current = {"CVE-2024-1000": snapshot_body(), "CVE-2024-2000": snapshot_body(vendor="Beta")}
        delta = refresh.compare({"CVE-2024-1000": snapshot_body()}, current)
        alerts = priority.prioritize_kev_additions(delta, current)
        self.assertEqual([item["cve"] for item in alerts], ["CVE-2024-2000"])
        self.assertEqual(alerts[0]["level"], "P1")
        self.assertEqual(alerts[0]["deciding_rule"], "kev_listed")
        self.assertEqual(alerts[0]["vendor"], "Beta")
        self.assertIn("dateAdded 2026-11-01", alerts[0]["justification"])

    def test_initial_baseline_does_not_alert_the_whole_catalog(self):
        delta = refresh.compare(None, {"CVE-2024-1000": snapshot_body()})
        self.assertIsNone(delta["added"])
        self.assertEqual(priority.prioritize_kev_additions(delta, {}), [])

    def test_thin_delta_item_still_alerts_when_snapshot_body_is_missing(self):
        delta = {"added": [
            {"cve": "CVE-2024-2000", "dateAdded": "2026-11-02", "vendor": "Beta", "product": "Widget"},
            {"cve": "CVE-2024-1000", "dateAdded": "2026-11-01", "vendor": "Acme", "product": "Widget"},
        ]}
        alerts = priority.prioritize_kev_additions(delta, {})
        self.assertEqual([item["cve"] for item in alerts], ["CVE-2024-2000", "CVE-2024-1000"])
        self.assertTrue(all(item["level"] == "P1" for item in alerts))
        self.assertEqual(alerts[0]["vendor"], "Beta")

    def test_ransomware_note_stays_inside_the_kev_rule(self):
        body = snapshot_body()
        body["knownRansomwareCampaignUse"] = "Known"
        alerts = priority.prioritize_kev_additions(
            {"added": [{"cve": CVE, "dateAdded": "2026-11-01", "vendor": "Acme", "product": "Widget"}]},
            {CVE: body})
        self.assertEqual(alerts[0]["level"], "P1")
        self.assertEqual(alerts[0]["deciding_rule"], "kev_listed")
        self.assertIn("ransomware como Known", alerts[0]["justification"])

    def test_lookup_failure_does_not_drop_the_rest_of_the_batch(self):
        def flaky(cve):
            if cve.endswith("1000"):
                raise OSError("down")
            return priority.EpssLookup(cve, 0.5, 0.8, "2026-11-12", "ok", None, priority.epss_url(cve))

        delta = {"added": [
            {"cve": CVE, "vendor": "Acme", "product": "Widget", "dateAdded": "2026-11-01"},
            {"cve": "CVE-2024-2000", "vendor": "Beta", "product": "Widget", "dateAdded": "2026-11-02"},
        ]}
        alerts = priority.prioritize_kev_additions(delta, {}, epss_lookup=flaky)
        self.assertEqual(alerts[0]["level"], "P1")
        self.assertEqual(alerts[0]["inputs"]["epss_error"], "lookup_failed")
        self.assertNotIn("epss_at_least_p2", alerts[0]["matched_rules"])
        self.assertEqual(alerts[1]["deciding_rule"], "kev_listed")
        self.assertIn("epss_at_least_p2", alerts[1]["matched_rules"])
        self.assertEqual(alerts[1]["inputs"]["epss"], 0.5)

    def test_bad_delta_item_is_isolated(self):
        alerts = priority.prioritize_kev_additions(
            {"added": ["nope", {"cve": CVE, "vendor": "Acme", "product": "Widget", "dateAdded": "2026-11-01"}]},
            {})
        self.assertFalse(alerts[0]["ok"])
        self.assertEqual(alerts[1]["level"], "P1")

    def test_malformed_delta_is_a_contract_error(self):
        with self.assertRaises(ValueError):
            priority.prioritize_kev_additions({"added": "x"}, {})
        with self.assertRaises(ValueError):
            priority.prioritize_kev_additions([], {})


class CliTests(unittest.TestCase):
    def test_text_alert_names_the_cvss_rule(self):
        stdout = io.StringIO()
        code = priority.main(
            ["--cve", CVE, "--not-in-kev", "--cvss", "8.8", "--format", "text"], stdout=stdout)
        self.assertEqual(code, 0)
        self.assertIn("[P2] " + CVE, stdout.getvalue())
        self.assertIn("cvss_at_least_p2", stdout.getvalue())
        self.assertIn("https://nvd.nist.gov/vuln/detail/" + CVE, stdout.getvalue())

    def test_json_record_from_kev_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "record.json"
            path.write_text(json.dumps({"cve": CVE, **snapshot_body(), "vendor": "Acme\nInjected"}), encoding="utf-8")
            stdout = io.StringIO()
            code = priority.main(
                ["--record", str(path), "--from-kev-snapshot", "--format", "json"], stdout=stdout)
        self.assertEqual(code, 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["level"], "P1")
        self.assertTrue(data["inputs"]["in_kev"])
        self.assertEqual(data["vendor"], "Acme Injected")
        self.assertIn("`kev_listed`", data["justification"])

    def test_env_threshold_and_cli_override(self):
        stdout = io.StringIO()
        code = priority.main(
            ["--cve", CVE, "--epss", "0.2", "--format", "json"],
            stdout=stdout, environ={"MITR3_PRIORITY_EPSS_P2": "0.5"})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["level"], "P3")
        stdout = io.StringIO()
        code = priority.main(
            ["--cve", CVE, "--epss", "0.2", "--epss-p2", "0.15", "--format", "json"],
            stdout=stdout, environ={"MITR3_PRIORITY_EPSS_P2": "0.5"})
        self.assertEqual(json.loads(stdout.getvalue())["deciding_rule"], "epss_at_least_p2")

    def test_fetch_failure_still_exits_zero(self):
        def boom(_cve):
            raise OSError("down")

        stdout, stderr = io.StringIO(), io.StringIO()
        code = priority.main(
            ["--cve", CVE, "--fetch-epss", "--format", "json"],
            stdout=stdout, stderr=stderr, epss_lookup=boom)
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["level"], "P4")
        self.assertEqual(data["inputs"]["epss_error"], "lookup_failed")
        self.assertIn("EPSS indisponível", data["justification"])

    def test_explicit_epss_skips_fetch(self):
        def boom(_cve):
            raise AssertionError("fetched")

        stdout = io.StringIO()
        code = priority.main(
            ["--cve", CVE, "--epss", "0.5", "--fetch-epss", "--format", "json"],
            stdout=stdout, epss_lookup=boom)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["deciding_rule"], "epss_at_least_p2")

    def test_usage_errors(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        self.assertEqual(priority.main([], stdout=stdout, stderr=stderr), 2)
        self.assertIn("informe --cve ou --record", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")
        stderr = io.StringIO()
        self.assertEqual(priority.main(["--cve", "nope"], stdout=io.StringIO(), stderr=stderr), 2)
        self.assertIn("invalid CVE identifier", stderr.getvalue())
        stderr = io.StringIO()
        self.assertEqual(priority.main(
            ["--cve", CVE, "--not-in-kev", "--from-kev-snapshot"],
            stdout=io.StringIO(), stderr=stderr), 2)


if __name__ == "__main__":
    unittest.main()
