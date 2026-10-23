"""Offline advisory parsing/matching; fixtures require no network or native pkg.

The projected GHSA-22w9-gpgv-pcgc record below retains the public API's actual
package/range fields observed 2026-10-15. Unused author/description metadata is
deliberately omitted. Multi-branch fixture comes from GHSA-f99w-3pm7-v4cv.
"""

from copy import deepcopy
import importlib
import json
import unittest
from unittest.mock import Mock, patch

from installer import security_assessment as security


NOW = "2026-10-15T12:00:00+00:00"
IDENTITY = "GHSA-22w9-gpgv-pcgc"
MULTI_ID = "GHSA-f99w-3pm7-v4cv"


def advisory(identity=IDENTITY, value=">= 34.0.0", fixed="34.0.1"):
    return {"ghsa_id": identity, "html_url": security.ADVISORY_URL + identity,
            "state": "published", "withdrawn_at": None,
            "vulnerabilities": [
                {"package": {"ecosystem": "nextcloud", "name": "files_lock"},
                 "vulnerable_version_range": ">= 32.0.0, >= 33.0.0",
                 "patched_versions": " 32.0.6, 33.0.6", "vulnerable_functions": []},
                {"package": {"ecosystem": "nextcloud", "name": "Server"},
                 "vulnerable_version_range": value, "patched_versions": fixed,
                 "vulnerable_functions": []},
                {"package": {"ecosystem": "nextcloud entreprise", "name": "Server"},
                 "vulnerable_version_range": ">= 32.0.0, >= 33.0.0, >= 34.0.0",
                 "patched_versions": "32.0.6, 33.0.6, 34.0.1", "vulnerable_functions": []}]}


def raw(items):
    return json.dumps(items).encode()


def feed(items=None, **kwargs):
    return security.normalize_nextcloud([raw([advisory()] if items is None else items)],
                                       fetched_at=kwargs.pop("fetched_at", NOW),
                                       complete=kwargs.pop("complete", True), **kwargs)


class SecurityAssessmentTests(unittest.TestCase):
    def check(self, version="34.0.0", evidence=None):
        return security.assess_nextcloud(version, feed() if evidence is None else evidence, now=NOW)

    def test_real_projected_record_and_numeric_boundaries(self):
        evidence = feed()
        self.assertEqual(evidence["unsupported_ids"], [])
        for version, status in (("33.0.99", "no-known-advisories"), ("34.0.0", "affected"),
                                ("34.0.0.2", "affected"), ("34.0.1", "no-known-advisories")):
            with self.subTest(version=version):
                result = self.check(version, evidence)
                self.assertEqual(result["status"], status)
                self.assertEqual(result["coverage"], "complete")
                self.assertEqual(result["eol"]["status"], "unknown")
                self.assertFalse(result["execution_authorized"])
        self.assertEqual(self.check()["findings"], [{"id": IDENTITY,
                         "url": security.ADVISORY_URL + IDENTITY, "affected_version": "34.0.0"}])
        numeric = feed([advisory(value=">= 34.0.9, < 34.0.11", fixed="34.0.11")])
        self.assertEqual(self.check("34.0.10", numeric)["status"], "affected")
        self.assertEqual(self.check("34.0.2", numeric)["status"], "no-known-advisories")

    def test_introduced_unbounded_fixed_last_affected_and_exact(self):
        cases = [("< 34.0.1", None, "33.9.9", True),
                 ("<= 34.0.1", "34.0.2", "34.0.1", True),
                 ("<= 34.0.1", "34.0.2", "34.0.1.1", False),
                 (">= 34.0.1", None, "35.0.0", True),
                 ("34.0.1", "34.0.2", "34.0.1.0", True),
                 ("= 34.0.1", None, "34.0.0", False)]
        for value, fixed, version, affected in cases:
            with self.subTest(value=value):
                result = self.check(version, feed([advisory(value=value, fixed=fixed)]))
                self.assertEqual(result["status"], "affected" if affected else "no-known-advisories")

    def test_ambiguous_live_multibranch_is_unknown_not_clean(self):
        item = advisory(MULTI_ID, ">= 32.0.0, >= 33.0.0, >= 34.0.0", "32.0.12, 33.0.6, 34.0.1")
        result = self.check("35.0.0", feed([item]))
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["unsupported_ids"], [MULTI_ID])
        mixed = self.check(evidence=feed([item, advisory()]))
        self.assertEqual(mixed["status"], "affected")
        self.assertEqual(mixed["coverage"], "unknown")

    def test_unsupported_and_inconsistent_ranges_cannot_silently_clean(self):
        cases = [("*", None), ("> 34.0.0", None), ("^34.0.0", None),
                 (">= 34.0.0 || < 33.0.1", None), ("34.0.0-beta1", None),
                 (">= 34.0.1, < 34.0.0", None), (">= 34.0.0, < 34.0.1", "34.0.2"),
                 (">= 34.0.0", "35.0.1"), (">= 34.0.0", "34.0.1, 35.0.1"),
                 (">= 34.0.0, <= 34.0.1, < 34.0.2", None),
                 ("<= 34.0.1", "34.0.0"), (None, None), ("", "34.0.1")]
        for value, fixed in cases:
            with self.subTest(value=value, fixed=fixed):
                result = self.check("35.0.0", feed([advisory(value=value, fixed=fixed)]))
                self.assertEqual(result["status"], "unknown")
                self.assertIn("unsupported-ranges", result["reasons"])

    def test_bad_installed_versions_are_never_package_compared_or_echoed(self):
        for version in ("34.0.0_1", "34.0.0,1", "34.0.0rc1", "v34.0.0", "34.0", "034.0.0",
                        "34.0.0\x1b[31m", None, 34, "9" * 10000):
            with self.subTest(version=str(version)[:30]):
                result = self.check(version)
                self.assertEqual(result["status"], "unknown")
                self.assertIsNone(result["installed_version"])

    def test_missing_stale_partial_future_and_invalid_feeds(self):
        self.assertEqual(security.assess_nextcloud("34.0.1", now=NOW)["status"], "unknown")
        for evidence in (feed(complete=False), feed(fetched_at="2026-10-13T00:00:00Z"),
                         feed(fetched_at="2026-10-16T00:00:00Z"), {}, [], {"status": "secure"}):
            self.assertEqual(self.check("34.0.1", evidence)["status"], "unknown")
        stale = self.check(evidence=feed(fetched_at="2026-10-13T00:00:00Z"))
        self.assertEqual((stale["status"], stale["freshness"], stale["coverage"]),
                         ("affected", "stale", "unknown"))
        self.assertEqual(self.check(evidence=feed(fetched_at="2026-10-14T12:00:00Z"))["freshness"], "fresh")

    def test_withdrawal_and_other_packages_do_not_create_core_findings(self):
        withdrawn = advisory()
        withdrawn["withdrawn_at"] = "2026-10-14T00:00:00Z"
        other = advisory(MULTI_ID)
        other["vulnerabilities"] = [other["vulnerabilities"][0], other["vulnerabilities"][2]]
        result = self.check(evidence=feed([withdrawn, other]))
        self.assertEqual(result["status"], "no-known-advisories")
        withdrawn["withdrawn_at"] = None
        withdrawn["state"] = "withdrawn"
        self.assertEqual(self.check(evidence=feed([withdrawn]))["status"], "no-known-advisories")

    def test_feed_schema_corruption_rejected(self):
        mutations = [("state", "draft"), ("withdrawn_at", "not-a-date"),
                     ("ghsa_id", "GHSA-evil\n"), ("html_url", "https://evil.invalid/"),
                     ("vulnerabilities", []), ("vulnerabilities", [{}])]
        for key, value in mutations:
            item = advisory()
            item[key] = value
            with self.subTest(key=key), self.assertRaises(security.AssessmentError):
                feed([item])
        item = advisory()
        del item["withdrawn_at"]
        with self.assertRaises(security.AssessmentError):
            feed([item])
        with self.assertRaises(security.AssessmentError):
            feed([advisory(), advisory()])

    def test_normalized_evidence_is_revalidated_and_output_is_bounded(self):
        original = feed()
        for key, value in (("schema_version", True), ("provider", security.PKG_PROVIDER),
                           ("source_url", "https://evil.invalid"), ("complete", "yes"),
                           ("fetched_at", "2026-10-15\x1b12:00:00+00:00"),
                           ("content_sha256", "a"), ("unsupported_ids", ["\x1b[31m"]),
                           ("records", [{"id": IDENTITY}])):
            evidence = deepcopy(original)
            evidence[key] = value
            self.assertEqual(self.check(evidence=evidence)["status"], "unknown")
        item = advisory()
        item.update(description="\x1b[31mSECRET", summary="\nSECRET")
        result = self.check(evidence=feed([item]))
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("description", json.dumps(result))

    def test_json_limits_duplicate_keys_and_nonfinite_constants(self):
        payloads = [b'[{"ghsa_id":"a","ghsa_id":"b"}]', b'[NaN]', b'[Infinity]',
                    b'{}', b'\xff', b'[' * 30 + b']' * 30, b'[] trailing']
        for payload in payloads:
            with self.subTest(payload=payload[:40]), self.assertRaises(security.AssessmentError):
                security.normalize_nextcloud([payload], fetched_at=NOW, complete=True)
        with patch.object(security, "MAX_BYTES", 1), self.assertRaises(security.AssessmentError):
            feed()
        with patch.object(security, "MAX_NODES", 3), self.assertRaises(security.AssessmentError):
            feed()
        with patch.object(security, "MAX_RECORDS", 1), self.assertRaises(security.AssessmentError):
            feed([advisory(), advisory(MULTI_ID)])

    def test_import_and_providers_do_not_execute_or_connect(self):
        with patch("subprocess.run", side_effect=AssertionError("native execution")), \
                patch("socket.socket", side_effect=AssertionError("network")), \
                patch("builtins.open", side_effect=AssertionError("file access")):
            importlib.reload(security)
            self.check()
            packages = security.assess_freebsd_packages()
        self.assertEqual(packages["provider"], security.PKG_PROVIDER)
        self.assertEqual(packages["status"], "unknown")
        self.assertEqual(packages["reasons"], ["native-audit-not-implemented"])


class RefreshTests(unittest.TestCase):
    def response(self, url=security.REFRESH_URL, items=None, link=None, **changes):
        return dict({"status": 200, "url": url, "body": raw([advisory()] if items is None else items),
                     "link": link}, **changes)

    def test_explicit_bounded_refresh_pagination_and_provenance(self):
        next_url = "https://api.github.com/repositories/63675426/security-advisories?per_page=100&state=published&after=YWJj%3D%3D"
        fetcher = Mock(side_effect=[self.response(link=f'<{next_url}>; rel="next"'),
                                    self.response(next_url, [advisory(MULTI_ID)])])
        evidence = security.refresh_nextcloud(fetcher, fetched_at=NOW)
        self.assertTrue(evidence["complete"])
        self.assertEqual(len(evidence["records"]), 2)
        self.assertEqual(fetcher.call_count, 2)
        first, second = fetcher.call_args_list
        self.assertEqual(first.args, (security.REFRESH_URL,))
        self.assertEqual(first.kwargs["max_bytes"], security.MAX_BYTES)
        self.assertLess(second.kwargs["max_bytes"], first.kwargs["max_bytes"])
        result = security.assess_nextcloud("34.0.0", evidence, now=NOW)
        self.assertEqual(result["provenance"]["authentication"], "https-source-not-signed-feed")

    def test_http_errors_redirects_and_missing_pagination_metadata_fail(self):
        for changes in ({"status": 403}, {"status": 429}, {"status": 304},
                        {"url": "https://evil.invalid"}, {"body": b'{"message":"rate limited"}'},
                        {"link": "truncated"}, {"body": "[]"}):
            response = self.response()
            response.update(changes)
            with self.subTest(changes=changes), self.assertRaises(security.AssessmentError):
                security.refresh_nextcloud(Mock(return_value=response), fetched_at=NOW)
        response = self.response()
        del response["link"]
        with self.assertRaises(security.AssessmentError):
            security.refresh_nextcloud(Mock(return_value=response), fetched_at=NOW)

    def test_unapproved_links_fail_before_second_fetch(self):
        for url in ("http://api.github.com/", "https://evil.invalid/", "https://api.github.com@evil.invalid/",
                    security.REFRESH_URL + "&token=secret", security.REFRESH_URL + "&state=draft",
                    security.REFRESH_URL.replace("security-advisories/security-advisories", "server/security-advisories"),
                    security.REFRESH_URL + "#fragment"):
            fetcher = Mock(return_value=self.response(link=f'<{url}>; rel="next"'))
            with self.subTest(url=url), self.assertRaises(security.AssessmentError):
                security.refresh_nextcloud(fetcher, fetched_at=NOW)
            self.assertEqual(fetcher.call_count, 1)

    def test_repeated_cursor_page_budget_and_transport_exception_redaction(self):
        fetcher = Mock(return_value=self.response(link=f'<{security.REFRESH_URL}>; rel="next"'))
        with self.assertRaises(security.AssessmentError):
            security.refresh_nextcloud(fetcher, fetched_at=NOW)
        self.assertEqual(fetcher.call_count, 1)
        with patch.object(security, "MAX_PAGES", 0), self.assertRaises(security.AssessmentError):
            security.refresh_nextcloud(Mock(), fetched_at=NOW)
        with self.assertRaises(security.AssessmentError) as failure:
            security.refresh_nextcloud(Mock(side_effect=RuntimeError("SECRET\x1b[31m")), fetched_at=NOW)
        self.assertEqual(str(failure.exception), "Advisory refresh failed")


if __name__ == "__main__":
    unittest.main()
