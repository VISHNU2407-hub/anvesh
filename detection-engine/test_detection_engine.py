"""Unit tests for detection_engine.analyze_url.

Run from the detection-engine/ folder:

    python -m unittest discover -p "test_*.py" -v

or simply:

    python test_detection_engine.py
"""

import inspect
import unittest

import detection_engine
from detection_engine import (
    DISCLAIMER,
    INDETERMINATE_CATEGORY,
    MAX_INPUT_LENGTH,
    MAX_RISK_SCORE,
    RISK_BANDS,
    SEVERITY_SCORES,
    analyze_url,
    categorize_risk,
    score_findings,
)

REQUIRED_KEYS = {
    "input_url",
    "is_valid",
    "parse_error",
    "scheme",
    "hostname",
    "port",
    "path",
    "query",
    "fragment",
    "risk_score",
    "risk_category",
    "findings",
    "findings_count",
    "disclaimer",
}

FINDING_KEYS = {"rule_id", "title", "severity", "score", "description", "evidence"}

ORDERED_CATEGORIES = [name for name, _floor in RISK_BANDS]


def rule_ids(result):
    return {finding["rule_id"] for finding in result["findings"]}


class StructureAssertions(unittest.TestCase):
    """Shared helpers that assert the output contract."""

    def assert_valid_structure(self, result):
        self.assertIsInstance(result, dict)
        self.assertTrue(REQUIRED_KEYS.issubset(result.keys()),
                        "missing keys: %s" % (REQUIRED_KEYS - set(result)))
        self.assertIsInstance(result["is_valid"], bool)
        self.assertIsInstance(result["findings"], list)
        self.assertIsInstance(result["findings_count"], int)
        self.assertEqual(result["findings_count"], len(result["findings"]))
        self.assertIsInstance(result["disclaimer"], str)

        self.assertIn(result["risk_category"],
                      ORDERED_CATEGORIES + [INDETERMINATE_CATEGORY])

        if result["is_valid"]:
            self.assertIsInstance(result["risk_score"], int)
            self.assertGreaterEqual(result["risk_score"], 0)
            self.assertLessEqual(result["risk_score"], MAX_RISK_SCORE)
            self.assertIsNone(result["parse_error"])
        else:
            self.assertIsNone(result["risk_score"])
            self.assertEqual(result["risk_category"], INDETERMINATE_CATEGORY)
            self.assertIsInstance(result["parse_error"], str)

        for finding in result["findings"]:
            self.assertIsInstance(finding, dict)
            self.assertTrue(FINDING_KEYS.issubset(finding.keys()),
                            "finding missing keys: %s"
                            % (FINDING_KEYS - set(finding)))
            self.assertIn(finding["severity"], SEVERITY_SCORES)
            self.assertEqual(finding["score"], SEVERITY_SCORES[finding["severity"]])

    def assert_never_raises(self, value):
        try:
            result = analyze_url(value)
        except Exception as exc:  # pragma: no cover - failure path
            self.fail("analyze_url(%r) raised %r" % (value, exc))
        self.assert_valid_structure(result)
        return result


class ValidUrlTests(StructureAssertions):
    def test_benign_https_url_is_valid(self):
        result = analyze_url("https://example.com")
        self.assert_valid_structure(result)
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["findings"], [])
        # No findings must NOT be reported as a safety guarantee.
        self.assertEqual(result["risk_category"], "low_observed_risk")
        self.assertIn("does not mean the URL is safe", result["disclaimer"])

    def test_path_query_and_fragment_are_captured(self):
        result = analyze_url("https://example.com/path/page?a=1&b=2#section")
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["path"], "/path/page")
        self.assertEqual(result["query"], "a=1&b=2")
        self.assertEqual(result["fragment"], "section")
        self.assertEqual(result["hostname"], "example.com")

    def test_hostname_and_scheme_are_normalized(self):
        result = analyze_url("  HTTPS://EXAMPLE.COM/  ")
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["hostname"], "example.com")

    def test_trailing_dot_fqdn_is_normalized(self):
        result = analyze_url("https://example.com./path")
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["hostname"], "example.com")

    def test_standard_port_is_accepted_without_port_finding(self):
        result = analyze_url("https://example.com:443/")
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["port"], 443)
        self.assertNotIn("non_standard_port", rule_ids(result))
        self.assertEqual(result["risk_score"], 0)


class InvalidUrlTests(StructureAssertions):
    def assert_invalid(self, value, expected_rule=None):
        result = self.assert_never_raises(value)
        self.assertFalse(result["is_valid"])
        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["risk_category"], INDETERMINATE_CATEGORY)
        self.assertIsNone(result["hostname"])
        self.assertIsInstance(result["parse_error"], str)
        self.assertTrue(result["findings"], "invalid input must still yield a finding")
        if expected_rule is not None:
            self.assertIn(expected_rule, rule_ids(result))
        return result

    def test_empty_string(self):
        self.assert_invalid("", "malformed_input")

    def test_whitespace_only_string(self):
        self.assert_invalid("    ", "malformed_input")

    def test_string_without_scheme(self):
        self.assert_invalid("example.com/path", "malformed_input")

    def test_string_without_host(self):
        self.assert_invalid("https://", "malformed_input")

    def test_garbage_string(self):
        self.assert_invalid("ht!tp:://???not a url", "malformed_input")

    def test_raw_whitespace_inside_url(self):
        self.assert_invalid("http://exa mple.com/", "malformed_input")

    def test_control_characters(self):
        self.assert_invalid("http://example.com/\x00", "malformed_input")

    def test_malformed_port(self):
        self.assert_invalid("http://example.com:abc/", "malformed_input")

    def test_unbalanced_ipv6_bracket(self):
        self.assert_invalid("http://[::1/", "malformed_input")

    def test_none_input(self):
        self.assert_invalid(None, "malformed_input")

    def test_non_string_inputs(self):
        for value in (123, 1.5, True, b"https://example.com", ["x"], {"u": 1}, object()):
            with self.subTest(value=value):
                self.assert_invalid(value, "malformed_input")

    def test_dangerous_scheme_is_flagged(self):
        for value in ("javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=",
                      "file:///etc/passwd"):
            with self.subTest(value=value):
                result = self.assert_invalid(value, "dangerous_scheme")
                self.assertNotEqual(result["risk_category"], "low_observed_risk")

    def test_input_over_length_limit(self):
        self.assert_invalid("https://example.com/" + "a" * MAX_INPUT_LENGTH,
                            "malformed_input")


class SuspiciousPatternTests(StructureAssertions):
    def test_ip_host_with_login_path(self):
        result = self.assert_never_raises("http://192.168.10.5/login")
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["hostname"], "192.168.10.5")
        ids = rule_ids(result)
        self.assertIn("ip_address_host", ids)
        self.assertIn("plain_http_scheme", ids)
        self.assertIn("suspicious_keywords", ids)
        self.assertEqual(result["risk_score"], 40)
        self.assertEqual(result["risk_category"], "elevated_observed_risk")

    def test_userinfo_trick(self):
        result = self.assert_never_raises("https://paypal.com@evil.example/")
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["hostname"], "evil.example")
        ids = rule_ids(result)
        self.assertIn("userinfo_trick", ids)
        self.assertIn("suspicious_keywords", ids)
        keyword_finding = next(f for f in result["findings"]
                               if f["rule_id"] == "suspicious_keywords")
        self.assertIn("paypal", keyword_finding["evidence"])
        self.assertGreater(result["risk_score"], 0)

    def test_suspicious_tld_and_lure_wording(self):
        result = self.assert_never_raises("http://free-prize.xyz/claim")
        ids = rule_ids(result)
        self.assertIn("suspicious_tld", ids)
        self.assertIn("suspicious_keywords", ids)
        self.assertIn("plain_http_scheme", ids)
        self.assertGreaterEqual(result["risk_score"], 30)

    def test_punycode_hostname(self):
        result = self.assert_never_raises("https://xn--pypal-4ve.com/login")
        self.assertIn("punycode_hostname", rule_ids(result))
        self.assertIn("suspicious_keywords", rule_ids(result))
        self.assertGreaterEqual(result["risk_score"], 30)

    def test_url_shortener(self):
        result = self.assert_never_raises("https://bit.ly/3kXyZ9")
        self.assertIn("url_shortener", rule_ids(result))

    def test_open_redirect_parameter(self):
        result = self.assert_never_raises(
            "https://example.com/out?redirect=https%3A%2F%2Fevil.test")
        self.assertIn("redirect_parameter", rule_ids(result))
        self.assertGreaterEqual(result["risk_score"], 10)

    def test_excessive_subdomains(self):
        result = self.assert_never_raises("https://a.b.c.d.example.com/")
        self.assertIn("excessive_subdomains", rule_ids(result))

    def test_deep_path(self):
        result = self.assert_never_raises("https://example.com/a/b/c/d/e/f")
        self.assertIn("deep_path", rule_ids(result))

    def test_double_slash_path(self):
        result = self.assert_never_raises("https://example.com//evil")
        self.assertIn("double_slash_path", rule_ids(result))

    def test_excessive_url_encoding(self):
        url = "https://example.com/%2f%2e%2e%2f%61%62%63%64%65%66%67%68"
        result = self.assert_never_raises(url)
        self.assertIn("excessive_url_encoding", rule_ids(result))

    def test_excessive_length(self):
        result = self.assert_never_raises("https://example.com/" + "a" * 300)
        self.assertTrue(result["is_valid"])
        self.assertIn("excessive_length", rule_ids(result))

    def test_non_standard_port(self):
        result = self.assert_never_raises("https://example.com:8443/")
        self.assertIn("non_standard_port", rule_ids(result))

    def test_unsupported_scheme_with_host(self):
        result = self.assert_never_raises("ftp://files.example.com/pub")
        self.assertTrue(result["is_valid"])
        self.assertIn("unsupported_scheme", rule_ids(result))
        self.assertGreaterEqual(result["risk_score"], 30)

    def test_risky_url_scores_higher_than_benign_url(self):
        benign = analyze_url("https://example.com")
        risky = analyze_url("http://192.168.10.5/login/verify?redirect=http://x")
        self.assertLess(benign["risk_score"], risky["risk_score"])
        self.assertLess(
            ORDERED_CATEGORIES.index(benign["risk_category"]),
            ORDERED_CATEGORIES.index(risky["risk_category"]),
        )

    def test_findings_are_sorted_by_score(self):
        result = self.assert_never_raises("http://192.168.10.5/login")
        scores = [f["score"] for f in result["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


class RiskCategoryTests(unittest.TestCase):
    def test_band_boundaries(self):
        cases = {
            0: "low_observed_risk",
            19: "low_observed_risk",
            20: "moderate_observed_risk",
            39: "moderate_observed_risk",
            40: "elevated_observed_risk",
            69: "elevated_observed_risk",
            70: "high_observed_risk",
            100: "high_observed_risk",
        }
        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(categorize_risk(score), expected)

    def test_none_score_is_indeterminate(self):
        self.assertEqual(categorize_risk(None), INDETERMINATE_CATEGORY)

    def test_categories_are_monotonic(self):
        previous = -1
        for _name, floor in RISK_BANDS:
            self.assertGreater(floor, previous)
            previous = floor

    def test_score_is_capped_at_100(self):
        findings = [{"score": 70}, {"score": 70}]
        self.assertEqual(score_findings(findings), MAX_RISK_SCORE)

    def test_score_of_no_findings_is_zero(self):
        self.assertEqual(score_findings([]), 0)


class EdgeCaseTests(StructureAssertions):
    def test_non_ascii_hostname(self):
        result = self.assert_never_raises("https://ex\u00e4mple.com/")
        self.assertTrue(result["is_valid"])
        self.assertIn("non_ascii_hostname", rule_ids(result))

    def test_localhost_with_custom_port(self):
        result = self.assert_never_raises("http://localhost:8000/")
        self.assertTrue(result["is_valid"])
        ids = rule_ids(result)
        self.assertIn("unqualified_hostname", ids)
        self.assertIn("non_standard_port", ids)
        self.assertIn("plain_http_scheme", ids)
        self.assertEqual(result["risk_category"], "moderate_observed_risk")

    def test_long_but_valid_url(self):
        result = self.assert_never_raises("https://example.com/" + "a" * 9000)
        self.assertTrue(result["is_valid"])
        self.assertLessEqual(result["risk_score"], MAX_RISK_SCORE)

    def test_fuzz_inputs_never_crash(self):
        nasty = [
            None, "", " ", "\n", "\t", 0, 1.5, True, False, b"http://x",
            [], {}, object(), "://", "%%%", "%", "http://", "https://",
            "http://[]", "http://a..b", "http://-x.com", "http://@/",
            "http://user@:80", "http://:", "?query=1", "#fragment",
            "http://example.com/" + "../" * 100, "\u200bhttps://example.com",
            "http://example.com/?a=" + "=" * 500,
            "H" * (MAX_INPUT_LENGTH + 100),
            "http://255.255.255.255:65536/",
            "https://example.com/\x7f",
        ]
        for value in nasty:
            with self.subTest(value=repr(value)[:60]):
                self.assert_never_raises(value)

    def test_repeated_calls_are_deterministic(self):
        url = "http://192.168.10.5/login?redirect=http://evil.test"
        self.assertEqual(analyze_url(url), analyze_url(url))

    def test_module_never_makes_network_requests(self):
        source = inspect.getsource(detection_engine)
        self.assertNotIn("urlopen", source)
        self.assertNotIn("import requests", source)
        self.assertNotIn("http.client", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("urllib.request", source)


class OutputContractTests(StructureAssertions):
    def test_valid_result_shape(self):
        result = self.assert_never_raises("https://example.com/login")
        self.assertEqual(set(result), REQUIRED_KEYS)

    def test_invalid_result_shape(self):
        result = self.assert_never_raises("not a url")
        self.assertEqual(set(result), REQUIRED_KEYS)

    def test_findings_explain_themselves(self):
        result = self.assert_never_raises("http://192.168.10.5/login")
        self.assertTrue(result["findings"])
        for finding in result["findings"]:
            self.assertTrue(finding["rule_id"])
            self.assertTrue(finding["description"])
            self.assertTrue(finding["evidence"])

    def test_disclaimer_states_limits(self):
        self.assertIn("not a probability", DISCLAIMER)
        self.assertIn("does not mean the URL is safe", DISCLAIMER)
        self.assertIn("no network requests were made", DISCLAIMER)

    def test_no_safety_claim_for_empty_findings(self):
        result = analyze_url("https://example.com")
        self.assertEqual(result["findings"], [])
        self.assertNotEqual(result["risk_category"], "safe")
        self.assertIn("does not mean the URL is safe", result["disclaimer"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
