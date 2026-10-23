"""pkg 2.8.4 source-shaped fixtures; all native execution is injected/mocked."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import package_security as security
from test_state import configuration
from version_fixtures import resolved_plan


ID = "01234567-89ab-cdef-0123-456789abcdef"
XML = (f'<?xml version="1.0"?><!DOCTYPE vuxml PUBLIC "-//vuxml.org//DTD VuXML 1.0//EN" '
       f'"http://www.vuxml.org/dtd/vuxml-1"><vuxml xmlns="{security.NAMESPACE}">'
       f'<vuln vid="{ID}"><topic>Public advisory</topic><affects><package><name>redis</name>'
       '<range><lt>8.10.3</lt></range></package></affects></vuln></vuxml>').encode()
PACKAGES = {"redis": "8.10.2_1,2", "python311": "3.11.14"}


def affected(packages=PACKAGES):
    name = sorted(packages)[-1]
    return {"pkg_count": 1, "packages": {name: {
        "version": packages[name], "issue_count": 1,
        "issues": [{"Affected versions": ["< 8.10.3_2,2"], "description": "Public topic\ntext",
                    "cve": ["CVE-2026-12345"], "url": f"https://vuxml.FreeBSD.org/freebsd/{ID}.html"}],
        "reverse dependencies": []}}}


class FakePkg:
    """Materialize only the private files a mocked native invocation would emit."""
    def __init__(self, *, vulnerable=True, version="2.8.4", xml=XML):
        self.vulnerable, self.version, self.xml = vulnerable, version, xml
        self.calls, self.roots = [], []
        self.run = Mock(side_effect=self.execute)

    def execute(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        marker = args.index("pkg-security")
        output = Path(args[marker + 2])
        command = args[marker + 3:]
        root = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("PKG_DBDIR="))).parent
        self.roots.append(root)
        assert root.stat().st_mode & 0o777 == 0o700
        for name in ("repos", "db", "cache", "tmp", "home"):
            assert (root / name).stat().st_mode & 0o777 == 0o700
        assert list((root / "repos").iterdir()) == []
        if command[-1] == "-v":
            output.write_text(self.version + "\n")
            output.chmod(0o600)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        audit = command[command.index("audit"):]
        db = Path(audit[audit.index("-f") + 1])
        explicit = audit[audit.index("--") + 1:]
        assert explicit
        packages = dict(argument.rsplit("-", 1) for argument in explicit)
        if "-F" in audit:
            assert not db.exists()
            db.write_bytes(self.xml)
            db.chmod(0o444)  # Actual pkg_audit_fetch publication mode.
            return SimpleNamespace(returncode=int(self.vulnerable), stdout="download progress", stderr="")
        assert "--raw=json" in audit
        value = affected(packages) if self.vulnerable else {"pkg_count": 0}
        output.write_text(json.dumps(value))
        output.chmod(0o600)
        return SimpleNamespace(returncode=int(self.vulnerable), stdout="", stderr="")


class PackageParsingTests(unittest.TestCase):
    def parse(self, value, code=1, packages=PACKAGES):
        return security.parse_audit(json.dumps(value), code, packages)

    def test_source_shaped_affected_exit_one_and_zero_omitted_packages(self):
        result = self.parse(affected())
        self.assertEqual(result[0]["package"], "redis")
        self.assertEqual(result[0]["version"], "8.10.2_1,2")
        self.assertEqual(result[0]["advisories"][0]["cve"], ["CVE-2026-12345"])
        self.assertNotIn("description", json.dumps(result))
        self.assertEqual(self.parse({"pkg_count": 0}, code=0), [])

    def test_missing_null_empty_nonzero_exit_and_duplicate_json_fail_closed(self):
        cases = [("", 0), ("{}", 0), ('{"pkg_count":0,"packages":null}', 0),
                 ('{"pkg_count":0,"packages":{}}', 0), ('{"pkg_count":0}', 1),
                 ('{"pkg_count":0,"pkg_count":0}', 0), ('{"pkg_count":NaN}', 0),
                 ('{"pkg_count":true}', 0), ('{"pkg_count":0} progress', 0),
                 (json.dumps(affected()), 0), (json.dumps(affected()), 70)]
        for output, code in cases:
            with self.subTest(output=output), self.assertRaises(ValueError):
                security.parse_audit(output, code, PACKAGES)

    def test_whole_json_counts_schema_and_exact_argument_bindings(self):
        value = affected()
        changes = [lambda x: x.update(pkg_count=2), lambda x: x.update(extra="unsupported"),
                   lambda x: x["packages"]["redis"].update(version="8.10.2_2,2"),
                   lambda x: x["packages"]["redis"].update(issue_count=2),
                   lambda x: x["packages"]["redis"].update(issue_count=True),
                   lambda x: x["packages"]["redis"].update(**{"reverse dependencies": ["python311"]}),
                   lambda x: x["packages"]["redis"]["issues"][0].update(cve=["SECRET\x1b"]),
                   lambda x: x["packages"]["redis"]["issues"][0].update(url="https://evil.invalid/"),
                   lambda x: x["packages"]["redis"]["issues"][0].update(**{"Affected versions": []}),
                   lambda x: x["packages"]["redis"]["issues"][0].update(description="SECRET\x1b[31m")]
        for change in changes:
            modified = deepcopy(value)
            change(modified)
            with self.assertRaises(ValueError):
                self.parse(modified)
        with self.assertRaises(ValueError):
            self.parse(value, packages={"python311": "3.11.14"})

    def test_no_empty_arguments_wildcards_option_injection_or_dash_version_reinterpretation(self):
        for packages in ({}, {"-a": "1"}, {"pkg*": "1"}, {"pkg": "1\nSECRET"}, {"pkg": "1.0-rc1"}):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                security.parse_audit('{"pkg_count":0}', 0, packages)
        self.assertEqual(security._arguments({"with-dash": "1.2_3,4"}), ("with-dash-1.2_3,4",))
        with patch.object(security, "MAX_OUTPUT", 2), self.assertRaises(ValueError):
            self.parse({"pkg_count": 0}, 0)

    def test_complete_retained_closure_includes_all_groups_and_exact_dedup(self):
        plan = resolved_plan(configuration(accept_microsoft_fonts=True))
        packages = security.retained_packages(plan)
        self.assertEqual(set(packages), set().union(*(set(group) for group in plan["packages"].values())))
        self.assertIn(plan["roles"]["manager"], packages)
        self.assertIn(plan["roles"]["php"], packages)
        self.assertIn(plan["roles"]["onlyoffice"], packages)
        self.assertNotIn("nextcloud", packages)  # Upstream archive has its own provider.
        plan["packages"]["host"][plan["roles"]["php"]] = deepcopy(plan["packages"]["nextcloud"][plan["roles"]["php"]])
        plan["packages"]["host"][plan["roles"]["php"]]["version"] = "0.1"
        with self.assertRaises(ValueError):
            security.retained_packages(plan)

    def test_xml_shape_empty_feed_entities_and_truncation_rejected(self):
        security._validate_xml(XML)
        for xml in (b"", b"<html/>", f'<vuxml xmlns="{security.NAMESPACE}"/>'.encode(), XML[:-3],
                    f'<vuxml xmlns="{security.NAMESPACE}"><vuln vid="{ID}"/></vuxml>'.encode(),
                    XML.replace(b"<lt>8.10.3</lt>", b"<lt/>"),
                    b'<!DOCTYPE vuxml [<!ENTITY injected "text">]><vuxml/>'):
            with self.subTest(xml=xml[:30]), self.assertRaises(ValueError):
                security._validate_xml(xml)


class PackageRefreshTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pkg-security-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def refresh(self, runner):
        return security.refresh(PACKAGES, runner=runner, directory=self.directory)

    def test_explicit_fetch_then_json_audit_is_private_isolated_and_bound(self):
        runner = FakePkg()
        with patch.dict(os.environ, {"VULNXML_SITE": "https://evil.invalid", "HTTP_AUTH": "SECRET", "SSL_NO_VERIFY_PEER": "1"}):
            evidence = self.refresh(runner)
        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(evidence["vuxml_sha256"], security._hash(XML))
        self.assertEqual(evidence["packages"], PACKAGES)
        for args, options in runner.calls:
            self.assertEqual(args[:2], ("/usr/bin/env", "-i"))
            self.assertIn("LC_ALL=C", args)
            self.assertIn("VULNXML_SITE=" + security.SOURCE_URL, args)
            self.assertIn("PKG_ENABLE_PLUGINS=false", args)
            self.assertIn("NETRC=/dev/null", args)
            self.assertNotIn("SECRET", " ".join(args))
            self.assertTrue(options["hide_output"])
            self.assertEqual(options["input"], "")
            self.assertLessEqual(options["timeout"], 90)
            self.assertFalse(options["check"])
        self.assertIn("-F", runner.calls[1][0])
        self.assertNotIn("--raw=json", runner.calls[1][0])
        self.assertNotIn("-F", runner.calls[2][0])
        self.assertIn("--raw=json", runner.calls[2][0])
        self.assertTrue(all(not root.exists() for root in runner.roots))
        report = security.assess(PACKAGES, evidence)
        self.assertEqual(report["status"], "affected")
        self.assertEqual(report["source"], "retained-intended-version")
        self.assertEqual(report["eol"]["status"], "unknown")

    def test_missing_or_unreviewed_pkg_cannot_fetch_and_linux_default_never_executes(self):
        runner = FakePkg(version="2.8.5")
        with self.assertRaisesRegex(ValueError, "not reviewed"):
            self.refresh(runner)
        self.assertEqual(len(runner.calls), 1)
        with patch.object(security.sys, "platform", "linux"), \
                patch("installer.host.Runner", side_effect=AssertionError("native")), \
                patch.object(security.tempfile, "TemporaryDirectory", side_effect=AssertionError("write")):
            with self.assertRaises(security.NativeAuditUnavailable):
                security.refresh(PACKAGES)

    def test_timeouts_empty_output_fetch_failure_and_no_stale_fallback(self):
        runner = FakePkg()
        execute = runner.execute
        def empty(*args, **kwargs):
            result = execute(*args, **kwargs)
            if "--raw=json" in args:
                Path(args[args.index("pkg-security") + 2]).write_bytes(b"")
            return result
        runner.run.side_effect = empty
        with self.assertRaises(ValueError):
            self.refresh(runner)
        timeout = Mock()
        timeout.run.side_effect = subprocess.TimeoutExpired("SECRET", 1, output="SECRET")
        with self.assertRaises(ValueError) as failure:
            self.refresh(timeout)
        self.assertNotIn("SECRET", str(failure.exception))
        self.assertEqual(list(self.directory.iterdir()), [])
        runner = FakePkg(xml=b"")
        with self.assertRaises(ValueError):
            self.refresh(runner)
        self.assertEqual(len(runner.calls), 2)

    def test_changed_vuxml_cannot_authorize_clean_result(self):
        runner = FakePkg(vulnerable=False)
        execute = runner.execute
        def changed(*args, **kwargs):
            result = execute(*args, **kwargs)
            if "--raw=json" in args:
                database = Path(args[args.index("-f") + 1])
                database.write_bytes(XML + b"\n")
            return result
        runner.run.side_effect = changed
        with self.assertRaisesRegex(ValueError, "changed"):
            self.refresh(runner)

    def test_unsafe_native_files_and_size_limits_are_rejected(self):
        runner = FakePkg()
        execute = runner.execute
        def linked(*args, **kwargs):
            result = execute(*args, **kwargs)
            if "--raw=json" in args:
                path = Path(args[args.index("pkg-security") + 2])
                path.unlink()
                path.symlink_to("vuln.xml")
            return result
        runner.run.side_effect = linked
        with self.assertRaises(ValueError):
            self.refresh(runner)
        with patch.object(security, "MAX_VUXML", 1), self.assertRaises(ValueError):
            self.refresh(FakePkg())

    def test_evidence_digest_args_freshness_and_failure_are_revalidated(self):
        evidence = self.refresh(FakePkg(vulnerable=False))
        self.assertEqual(security.assess(PACKAGES, evidence)["status"], "no-known-advisories")
        for field, value in (("audit_sha256", "0" * 64), ("packages_sha256", "0" * 64),
                             ("pkg_version", "2.9.0"), ("exit_status", 1),
                             ("source_url", "https://evil.invalid"), ("vuxml_bytes", 0)):
            changed = dict(evidence, **{field: value})
            self.assertEqual(security.assess(PACKAGES, changed)["status"], "unknown")
        changed = dict(evidence, fetched_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())
        self.assertEqual(security.assess(PACKAGES, changed)["freshness"], "stale")
        self.assertEqual(security.assess(PACKAGES, changed)["status"], "unknown")
        self.assertEqual(security.assess({"different": "1"}, evidence)["status"], "unknown")
        self.assertEqual(security.assess(PACKAGES)["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
