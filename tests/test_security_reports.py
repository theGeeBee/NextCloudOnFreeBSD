"""Private security-report caching/CLI/HTTPS boundaries; never query a host."""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from email.message import Message
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch

from installer import main, security_assessment as assessment, security_reports as reports, updates
from installer import package_security
from installer.state import Registry, atomic_json, atomic_write, config_digest
from test_security_assessment import advisory, raw
from test_state import configuration
from version_fixtures import resolved_plan
from test_package_security import FakePkg


class SecurityReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="security-reports-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.registry = Registry(self.directory / "registry")
        self.registry.initialize()
        self.config = configuration(accept_microsoft_fonts=True)
        self.register(self.config)
        self.enterContext(patch("installer.deploy.source_digest", return_value="a" * 64 + "\n"))
        self.fetcher = Mock(side_effect=lambda url, **kwargs: {
            "status": 200, "url": url, "body": raw([advisory(value=">= 35.0.0", fixed="35.0.1")]), "link": None})
        native_refresh = package_security.refresh
        def native_adapter(packages, *, runner=None):
            if runner is None:
                raise package_security.NativeAuditUnavailable("Offline test: no native adapter")
            return native_refresh(packages, runner=runner, directory=self.directory)
        self.enterContext(patch.object(package_security, "refresh", side_effect=native_adapter))

    def register(self, config):
        path = self.registry.save_new(config, {"admin_password": "NEVER-READ-SECURITY-SECRET"})
        self.registry.set_status(config.instance, "ready")
        atomic_json(path / "versions.json", resolved_plan(config))
        atomic_write(path / "source.sha256", "a" * 64 + "\n")
        atomic_json(path / "deployment.json", {"schema_version": 2, "config_sha256": config_digest(config),
                                              "steps": {"installation": {"state": "complete"}}})
        return path

    @property
    def state(self):
        return self.registry.instance_path(self.config.instance)

    @property
    def cache(self):
        return self.registry.root / "security-reports" / (self.config.instance + ".json")

    def check(self, **kwargs):
        return reports.check_security(self.registry, [self.config.instance], **kwargs)

    def refresh(self, **kwargs):
        return self.check(refresh=True, fetcher=self.fetcher, **kwargs)

    def tree(self):
        return {str(path.relative_to(self.registry.root)): path.read_bytes()
                for path in self.registry.root.rglob("*") if path.is_file()}

    def test_default_cache_miss_reads_no_secrets_and_has_no_effects(self):
        before = self.tree()
        read = updates._read
        def guarded(path):
            self.assertNotEqual(path.name, "secrets.json")
            return read(path)
        with patch.object(self.registry, "locked", side_effect=AssertionError("lock")), \
                patch.object(self.registry, "initialize", side_effect=AssertionError("initialization")), \
                patch.object(reports, "_transport", side_effect=AssertionError("transport")), \
                patch.object(updates, "check_updates", side_effect=AssertionError("updates")), \
                patch("subprocess.run", side_effect=AssertionError("native")), \
                patch("socket.socket", side_effect=AssertionError("network")), \
                patch.object(updates, "_read", side_effect=guarded):
            result = self.check()
        row = result["instances"][0]
        self.assertEqual((row["status"], row["freshness"], row["source"]),
                         ("unknown", "missing", "retained-intended-version"))
        self.assertEqual(row["installed_version"], "35.0.0")
        self.assertFalse(result["inspection_failed"])
        self.assertEqual(before, self.tree())
        self.assertNotIn("NEVER-READ", json.dumps(result))

    def test_target_and_save_validation_precede_any_reads(self):
        for names in (None, [], "cloud", ["cloud", "cloud"], ["../cloud"], ["UPPER"], [2]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                reports.check_security(self.registry, names)
        with self.assertRaisesRegex(ValueError, "requires explicit refresh"):
            self.check(save_report=True)

    def test_absent_registry_never_initialized_even_when_save_requested(self):
        registry = Registry(self.directory / "absent")
        with patch.object(registry, "locked", side_effect=AssertionError("lock")):
            result = reports.check_security(registry, ["cloud"], refresh=True, save_report=True, fetcher=self.fetcher)
        self.assertTrue(result["inspection_failed"])
        self.assertFalse(registry.root.exists())
        self.fetcher.assert_not_called()

    def test_refresh_only_is_read_only_and_keeps_providers_independent(self):
        before = self.tree()
        with patch.object(self.registry, "locked", side_effect=AssertionError("lock")):
            result = self.refresh()
        row = result["instances"][0]
        self.assertFalse(result["inspection_failed"], result)
        self.assertEqual(row["providers"]["nextcloud"]["status"], "affected")
        self.assertEqual(row["providers"]["freebsd_pkg"]["status"], "unknown")
        self.assertEqual(row["providers"]["nextcloud"]["eol"]["status"], "unknown")
        self.assertFalse(row["migration_supported"])
        self.assertEqual(before, self.tree())

    def test_no_known_core_advisories_does_not_make_aggregate_secure(self):
        self.fetcher.side_effect = lambda url, **kwargs: {"status": 200, "url": url,
            "body": raw([advisory(value=">= 34.0.0", fixed="34.0.1")]), "link": None}
        row = self.refresh()["instances"][0]
        self.assertEqual(row["providers"]["nextcloud"]["status"], "no-known-advisories")
        self.assertEqual(row["status"], "unknown")

    def test_explicit_save_preserves_feed_hashes_and_private_modes(self):
        before = {path.name: path.read_bytes() for path in self.state.iterdir()}
        result = self.refresh(save_report=True)
        self.assertFalse(result["inspection_failed"], result)
        self.assertTrue(result["instances"][0]["saved"])
        value = json.loads(self.cache.read_bytes())
        self.assertFalse(value["report"]["saved"])
        self.assertEqual(value["report"]["provenance"]["feed_sha256"], reports._hash(value["feed"]))
        self.assertEqual(value["report"]["providers"]["nextcloud"]["provenance"]["content_sha256"],
                         value["feed"]["content_sha256"])
        self.assertEqual(self.cache.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.cache.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.state.iterdir()})
        with patch.object(self.registry, "locked", side_effect=AssertionError("lock")), \
                patch.object(reports, "_transport", side_effect=AssertionError("network")):
            cached = self.check()["instances"][0]
        self.assertEqual(cached["providers"], result["instances"][0]["providers"])
        self.assertFalse(cached["saved"])

    def test_feed_or_status_tampering_is_not_trusted_or_echoed(self):
        self.refresh(save_report=True)
        original = json.loads(self.cache.read_bytes())
        for mutation in (lambda value: value["feed"]["records"].clear(),
                         lambda value: value["report"].update(status="secure\x1b[31mSECRET"),
                         lambda value: value["report"].update(errors=["SECRET"]),
                         lambda value: value["report"]["provenance"].update(feed_sha256="0" * 64),
                         lambda value: value.update(generated_at="9999-01-01T00:00:00Z")):
            value = deepcopy(original)
            mutation(value)
            atomic_json(self.cache, value)
            result = self.check()
            self.assertTrue(result["inspection_failed"])
            self.assertEqual(result["instances"][0]["providers"]["nextcloud"]["status"], "unknown")
            self.assertNotIn("SECRET", json.dumps(result))

    def test_stale_bindings_and_time_cannot_keep_success_status(self):
        self.refresh(save_report=True)
        atomic_write(self.state / "source.sha256", "b" * 64 + "\n")
        row = self.check()["instances"][0]
        self.assertEqual(row["freshness"], "stale")
        self.assertIn("source_sha256", row["stale_reasons"])
        self.assertEqual(row["providers"]["nextcloud"]["status"], "unknown")
        atomic_write(self.state / "source.sha256", "a" * 64 + "\n")
        value = json.loads(self.cache.read_bytes())
        older = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        value["feed"]["fetched_at"] = older
        row = reports._base("cloud", "35.0.0", value["report"]["bindings"],
                            value["report"]["provenance"]["installed_policy_sha256"], value["packages"])
        reports._assess(row, value["feed"], older, value["packages"], value["package_evidence"])
        value.update(report=row, generated_at=older)
        atomic_json(self.cache, value)
        row = self.check()["instances"][0]
        self.assertEqual(row["freshness"], "stale")
        self.assertIn("older-than-24-hours", row["stale_reasons"])
        self.assertEqual(row["status"], "unknown")

    def test_refresh_failure_is_sanitized_and_cached_without_success_fallback(self):
        self.refresh(save_report=True)
        self.fetcher.side_effect = RuntimeError("TOKEN-SECRET\x1b[31m")
        failed = self.refresh(save_report=True)
        self.assertTrue(failed["inspection_failed"])
        self.assertTrue(failed["instances"][0]["saved"])
        cached = self.check()
        self.assertEqual(cached["instances"][0]["errors"], ["refresh-failed"])
        self.assertEqual(cached["instances"][0]["status"], "unknown")
        self.assertNotIn("SECRET", json.dumps(cached))
        self.assertIsNone(json.loads(self.cache.read_bytes())["feed"])

    def test_unsafe_cache_and_instance_files_fail_closed(self):
        self.refresh(save_report=True)
        self.cache.chmod(0o644)
        self.assertTrue(self.check()["inspection_failed"])
        self.cache.chmod(0o600)
        original = self.cache.read_bytes()
        self.cache.unlink()
        other = self.directory / "other"
        other.write_bytes(original)
        self.cache.symlink_to(other)
        self.assertTrue(self.check()["inspection_failed"])
        self.cache.unlink()
        self.cache.parent.rmdir()
        self.cache.parent.symlink_to(self.directory / "missing", target_is_directory=True)
        self.assertTrue(self.check()["inspection_failed"])
        self.cache.parent.unlink()
        (self.state / "versions.json").chmod(0o644)
        self.assertTrue(self.check()["inspection_failed"])

    def test_one_public_fetch_per_selection_and_invalid_instances_are_isolated(self):
        self.register(configuration(instance="other", accept_microsoft_fonts=True))
        result = reports.check_security(self.registry, ["cloud", "other", "absent"],
                                        refresh=True, fetcher=self.fetcher)
        self.assertEqual(self.fetcher.call_count, 1)
        self.assertEqual([row["status"] for row in result["instances"]], ["affected", "affected", "unknown"])
        self.assertTrue(result["inspection_failed"])

    def test_nonready_instance_does_not_refresh_and_cannot_save(self):
        self.registry.set_status("cloud", "failed")
        result = self.refresh(save_report=True)
        self.fetcher.assert_not_called()
        self.assertIn("instance-not-ready", result["instances"][0]["errors"])
        self.assertFalse(self.cache.exists())

    def test_refresh_race_and_short_lock_revalidation_prevent_save(self):
        original = self.fetcher.side_effect
        def changed(url, **kwargs):
            atomic_write(self.state / "source.sha256", "b" * 64 + "\n")
            return original(url, **kwargs)
        self.fetcher.side_effect = changed
        result = self.refresh(save_report=True)
        self.assertIn("inspection-failed", result["instances"][0]["errors"])
        self.assertFalse(self.cache.exists())
        atomic_write(self.state / "source.sha256", "a" * 64 + "\n")
        self.fetcher.side_effect = original
        locked = self.registry.locked
        @contextmanager
        def race():
            with locked():
                atomic_write(self.state / "source.sha256", "c" * 64 + "\n")
                yield
        with patch.object(self.registry, "locked", side_effect=race):
            result = self.refresh(save_report=True)
        self.assertIn("save-failed", result["instances"][0]["errors"])
        self.assertFalse(self.cache.exists())

    def test_network_or_restore_conflict_prevents_cache_save(self):
        with patch("installer.firewall.pending_transactions", return_value=[self.registry.root / "transactions/pending"]):
            self.assertTrue(self.refresh(save_report=True)["inspection_failed"])
        self.assertFalse(self.cache.exists())
        atomic_json(self.state / "restore.json", {"state": "pending"})
        self.assertTrue(self.refresh(save_report=True)["inspection_failed"])
        self.assertFalse(self.cache.exists())

    def test_lifecycle_generation_bindings_and_safe_entry_guard(self):
        import test_maintenance
        from installer.maintenance import entry_guard
        fixture = test_maintenance.EnrollmentTransitionTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.enroll()
        with patch("subprocess.run", side_effect=AssertionError("native")):
            entry_guard("check-security", registry=fixture.registry)
            result = reports.check_security(fixture.registry, ["cloud"], refresh=True,
                                            save_report=True, fetcher=self.fetcher)
        self.assertFalse(result["inspection_failed"], result)
        self.assertIsNotNone(result["instances"][0]["bindings"]["lifecycle_sha256"])
        self.assertEqual(result["instances"][0]["source"], "retained-intended-version")

    def native_refresh(self, runner, **kwargs):
        return self.refresh(runner=runner, **kwargs)

    def test_native_provider_schema2_cache_exact_closure_and_no_cached_execution(self):
        result = self.native_refresh(FakePkg(vulnerable=False), save_report=True)
        self.assertFalse(result["inspection_failed"], result)
        row = result["instances"][0]
        self.assertEqual(row["providers"]["freebsd_pkg"]["status"], "no-known-advisories")
        value = json.loads(self.cache.read_bytes())
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["packages"], package_security.retained_packages(resolved_plan(self.config)))
        self.assertEqual(value["report"]["provenance"]["package_evidence_sha256"], reports._hash(value["package_evidence"]))
        with patch.object(package_security, "refresh", side_effect=AssertionError("native refresh")), \
                patch.object(self.registry, "locked", side_effect=AssertionError("lock")):
            cached = self.check()
        self.assertFalse(cached["inspection_failed"], cached)
        self.assertEqual(cached["instances"][0]["providers"], row["providers"])
        self.assertNotIn("audit_output", json.dumps(cached))

    def test_native_failure_preserves_upstream_and_upstream_failure_preserves_native(self):
        runner = Mock()
        runner.run.side_effect = RuntimeError("SECRET\x1b[31m")
        result = self.native_refresh(runner, save_report=True)
        self.assertEqual(result["instances"][0]["providers"]["nextcloud"]["status"], "affected")
        self.assertEqual(result["instances"][0]["providers"]["freebsd_pkg"]["status"], "unknown")
        self.assertIn("package-refresh-failed", result["instances"][0]["errors"])
        self.assertTrue(result["instances"][0]["saved"], result)
        cached = self.check()
        self.assertEqual(cached["instances"][0]["providers"]["nextcloud"]["status"], "affected")
        self.assertNotIn("SECRET", json.dumps(cached))
        self.fetcher.side_effect = RuntimeError("SECRET")
        result = self.native_refresh(FakePkg(), save_report=True)
        self.assertEqual(result["instances"][0]["providers"]["nextcloud"]["status"], "unknown")
        self.assertEqual(result["instances"][0]["providers"]["freebsd_pkg"]["status"], "affected")
        self.assertTrue(result["instances"][0]["saved"], result)
        self.assertEqual(self.check()["instances"][0]["providers"]["freebsd_pkg"]["status"], "affected")

    def test_native_evidence_tampering_cannot_keep_cached_coverage(self):
        self.native_refresh(FakePkg(vulnerable=False), save_report=True)
        original = json.loads(self.cache.read_bytes())
        for mutate in (lambda value: value["package_evidence"].update(audit_sha256="0" * 64),
                       lambda value: value["package_evidence"]["packages"].pop(next(iter(value["packages"]))),
                       lambda value: value["report"]["providers"]["freebsd_pkg"].update(status="secure"),
                       lambda value: value["report"]["provenance"].update(package_evidence_sha256="0" * 64)):
            value = deepcopy(original)
            mutate(value)
            atomic_json(self.cache, value)
            result = self.check()
            self.assertTrue(result["inspection_failed"])
            self.assertEqual(result["instances"][0]["providers"]["freebsd_pkg"]["status"], "unknown")

    def test_schema1_cache_preserves_original_unknown_native_coverage(self):
        self.refresh(save_report=True)
        value = json.loads(self.cache.read_bytes())
        row = reports._base("cloud", "35.0.0", value["report"]["bindings"],
                            value["report"]["provenance"]["installed_policy_sha256"])
        reports._assess(row, value["feed"], value["report"]["checked_at"])
        legacy = {"schema_version": 1, "generated_at": value["generated_at"], "report": row, "feed": value["feed"]}
        atomic_json(self.cache, legacy)
        before = self.cache.read_bytes()
        with patch.object(package_security, "refresh", side_effect=AssertionError("native")):
            result = self.check()
        self.assertFalse(result["inspection_failed"], result)
        self.assertEqual(result["instances"][0]["providers"]["freebsd_pkg"], assessment.assess_freebsd_packages())
        self.assertEqual(self.cache.read_bytes(), before)
        refreshed = self.native_refresh(FakePkg(vulnerable=False), save_report=True)
        self.assertFalse(refreshed["inspection_failed"], refreshed)
        self.assertEqual(json.loads(self.cache.read_bytes())["schema_version"], 2)


class SecurityTransportTests(unittest.TestCase):
    def setUp(self):
        self.connection = Mock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.headers = {"Content-Type": "application/json", "Content-Length": "2"}
        self.response.getheader.side_effect = lambda name, default=None: self.headers.get(name, default)
        self.response.headers = Message()
        self.response.read1.side_effect = [b"[]", b""]
        self.factory = self.enterContext(patch.object(reports.http.client, "HTTPSConnection", return_value=self.connection))

    def fetch(self, **kwargs):
        return reports._https_fetch(assessment.REFRESH_URL, max_bytes=kwargs.pop("max_bytes", 1024),
                                    headers={"Authorization": "DO-NOT-SEND"},
                                    deadline=reports.time.monotonic() + 30, **kwargs)

    def test_verified_https_without_credentials_proxy_redirects_or_unbounded_reads(self):
        result = self.fetch()
        self.assertEqual(result["body"], b"[]")
        self.assertEqual(self.factory.call_args.args, ("api.github.com",))
        context = self.factory.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        sent = self.connection.request.call_args.kwargs["headers"]
        self.assertNotIn("Authorization", sent)
        self.assertNotIn("Cookie", sent)
        self.assertTrue(all(call.args[0] <= 1025 for call in self.response.read1.call_args_list))
        self.connection.close.assert_called_once()

    def test_redirect_error_compression_and_oversized_headers_refused(self):
        self.response.status = 302
        with self.assertRaises(assessment.AssessmentError):
            self.fetch()
        self.response.read1.assert_not_called()
        self.response.status = 200
        for values in ({"Content-Encoding": "gzip"}, {"Content-Length": "9999999999"},
                       {"Content-Length": "garbage"}, {"Content-Type": "text/html"}):
            saved = dict(self.headers)
            self.headers.update(values)
            with self.assertRaises(assessment.AssessmentError):
                self.fetch()
            self.headers = saved

    def test_unknown_length_overflow_truncation_and_timeout(self):
        self.headers.pop("Content-Length")
        self.response.read1.side_effect = [b"oversized"]
        with self.assertRaises(assessment.AssessmentError):
            self.fetch(max_bytes=2)
        self.headers["Content-Length"] = "3"
        self.response.read1.side_effect = [b"[]", b""]
        with self.assertRaises(assessment.AssessmentError):
            self.fetch()
        with patch.object(reports.time, "monotonic", return_value=10):
            with self.assertRaises(assessment.AssessmentError):
                reports._https_fetch(assessment.REFRESH_URL, max_bytes=1, headers={}, deadline=9)


class SecurityCLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="security-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.registry = Registry(Path(self.temporary.name) / "absent")
        self.enterContext(patch.object(main, "Registry", return_value=self.registry))
        self.host = self.enterContext(patch.object(main, "require_host"))
        self.enterContext(patch.object(main, "Runner"))
        self.ui = Mock()
        self.enterContext(patch.object(main, "TerminalUI", return_value=self.ui))
        self.enterContext(patch.object(main, "Deployment", side_effect=AssertionError("deployment")))
        self.stdout = io.StringIO()
        self.enterContext(patch.object(main.sys, "stdout", self.stdout))
        self.enterContext(patch.object(main.sys, "stdin", io.StringIO()))

    def test_noninteractive_json_cache_miss_does_not_lock_or_bootstrap(self):
        with patch.object(self.registry, "locked", side_effect=AssertionError("lock")), \
                patch.object(self.registry, "initialize", side_effect=AssertionError("initialize")), \
                patch.object(reports, "_transport", side_effect=AssertionError("network")):
            self.assertEqual(main.main(["check-security", "cloud", "--json"]), 1)
        result = json.loads(self.stdout.getvalue())
        self.assertEqual(result["instances"][0]["source"], "retained-intended-version")
        self.assertFalse(self.registry.root.exists())
        self.host.assert_called_once()

    def test_empty_all_is_read_only_and_noninteractive_implicit_scope_refused(self):
        self.assertEqual(main.main(["check-security", "--all", "--json"]), 0)
        self.assertEqual(json.loads(self.stdout.getvalue())["instances"], [])
        self.assertFalse(self.registry.root.exists())
        with self.assertRaisesRegex(ValueError, "Select an instance or --all"):
            main.main(["check-security"])

    def test_invalid_selection_and_save_flags_rejected_before_host_guard(self):
        for args in (["cloud", "--all"], ["../cloud"], ["cloud", "--save-report"]):
            with patch.object(main.sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
                main.main(["check-security", *args])
        self.host.assert_not_called()

    def test_explicit_flags_dispatch_and_menu_discoverability(self):
        with patch.object(reports, "check_security", return_value={"instances": [], "inspection_failed": False}) as check:
            self.assertEqual(main.main(["check-security", "cloud", "--refresh", "--save-report", "--json"]), 0)
        check.assert_called_once_with(self.registry, ["cloud"], refresh=True, save_report=True)
        self.ui.menu.side_effect = ["check-security", "cached"]
        view = {"instances": [{"instance": "cloud", "state": "ready", "error": None, "pending": []}],
                "errors": [], "pending_network": []}
        args = main.menu(self.ui, self.registry, view=view)
        self.assertEqual(args.command, "check-security")
        self.assertFalse(args.refresh)
        self.assertFalse(args.save_report)


if __name__ == "__main__":
    unittest.main()
