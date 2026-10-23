"""Offline admission faults: authentic original seals, never native provisioning."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_admission as admission, enrollment
from installer.generations import Store, _encode, descriptor
from installer.maintenance_state import NativeState
from installer.paths import RESOURCES
from installer.state import Registry, atomic_json, atomic_write, config_digest
import test_generations as fixtures


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="admission-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.registry = Registry(self.root)
        self.native = NativeState(self.registry, {"fixture": "executor"})
        self.harness = admission.SourceAdmission(self.native)
        self.config = SimpleNamespace(instance="cloud", nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo",
                                      bastille_root=str(self.root / "bastille"))
        self.d = SimpleNamespace(config=self.config, state=self.root / "instances/cloud",
            jail_root=lambda jail: Path(self.config.bastille_root) / "jails" / jail / "root", jail=Mock())
        self.d.state.mkdir(parents=True)
        atomic_json(self.d.state / "inventory.json", {})
        self.expected = {"trees": {}}
        for jail, app in (("cloudnc", "nextcloud"), ("cloudoo", "onlyoffice/documentserver")):
            root = self.d.jail_root(jail)
            names = (*admission.STATIC_ROOTS, "usr/local/www/" + app)
            for name in names:
                (root / name).mkdir(parents=True, exist_ok=True)
            # Parent/static child trees intentionally overlap, as on FreeBSD.
            roots = tuple(root / name for name in names)
            self.expected["trees"][jail] = {name: enrollment._tree_identity(root / name,
                jail_root=root, observed_roots=roots) for name in names}
        self.store = self.native.store
        self.store._mkdir("fixture")
        resources = self.store._put("fixture/resources.json", {"package_inventory_sha256": {}})
        baseline = self.store._put("fixture/first-readiness.json", self.expected)
        self.original = ({"graph": "bound"}, {"generation": "initial"}, resources, baseline, self.expected)
        self.check = self.patch(admission.SourceAdmission, "_original", return_value=self.original)
        self.packages = self.patch(enrollment, "_packages", return_value={})
        self.patch(enrollment, "_plugins")
        self.observe = self.patch(enrollment, "_observe_non_tree", return_value={})
        self.startup = self.patch(admission.fence, "startup_inventory", return_value={"etc/rc.conf": "a" * 64})
        self.cron = self.patch(admission, "_scheduled_writers")
        self.integration = self.patch(admission, "_integrations", return_value={"config_sha256": "b" * 64,
                                                                               "apps_sha256": "c" * 64})

    def patch(self, target, name, **kwargs):
        manager = patch.object(target, name, **kwargs)
        value = manager.start()
        self.addCleanup(manager.stop)
        return value

    def test_seals_private_original_readiness_reference_before_any_intent(self):
        result = self.harness.admit_source(self.d)
        self.assertEqual(set(result), {"startup", "evidence"})
        record = json.loads(self.store._bound(result["evidence"]))
        self.assertEqual(record["first_readiness"], self.original[3])
        self.assertEqual(record["generation"], self.original[1])
        self.assertEqual(record["native_acceptance"], "not-run")
        self.assertFalse(record["execution_authorized"])
        self.assertIsNone(self.store.pending())
        path = self.store.root / result["evidence"]["path"]
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(ValueError):
            self.store._write_once(result["evidence"]["path"], b"replacement", recover=False)

    def test_admission_uses_the_exact_enrollment_static_tree_projection(self):
        self.assertIs(admission.STATIC_ROOTS, enrollment.STATIC_ROOTS)
        self.assertIn("usr/include", admission.STATIC_ROOTS)
        self.assertIn("usr/local/llvm19", admission.STATIC_ROOTS)

    def test_two_real_tree_scans_bracket_all_admission_observations(self):
        events = []
        real = admission._trees
        def trees(*args):
            events.append("trees")
            return real(*args)
        self.packages.side_effect = lambda *args: events.append("packages") or {}
        self.observe.side_effect = lambda *args: events.append("non-tree") or {}
        self.integration.side_effect = lambda *args: events.append("integrations") or {}
        with patch.object(admission, "_trees", side_effect=trees) as scans, \
                patch.object(enrollment, "_observe", side_effect=AssertionError("No duplicate tree inventory")):
            self.harness.admit_source(self.d)
        self.assertEqual(scans.call_count, 2)
        self.assertEqual(events, ["trees", "packages", "non-tree", "integrations", "trees"])

    def test_drift_during_non_tree_observation_and_next_call_never_reuses_admission(self):
        def changed(*args):
            (self.d.jail_root("cloudnc") / "bin/changed").write_text("moving tree")
            return {}
        self.observe.side_effect = changed
        with self.assertRaises(ValueError):
            self.harness.admit_source(self.d)
        self.assertFalse(self.store._present("maintenance/admissions"))
        self.observe.reset_mock()
        with self.assertRaises(ValueError):
            self.harness.admit_source(self.d)
        self.observe.assert_not_called()

    def test_changed_code_config_base_or_office_fails_before_any_occ(self):
        for jail, name in (("cloudnc", "usr/local/www/nextcloud"), ("cloudnc", "usr/local/lib"),
                           ("cloudnc", "etc"), ("cloudoo", "usr/local/www/onlyoffice/documentserver")):
            with self.subTest(jail=jail, name=name):
                changed = self.d.jail_root(jail) / name / "injected.php"
                changed.write_text("SECRET")
                with self.assertRaisesRegex(ValueError, "^" + admission.DENIED + "$"):
                    self.harness.admit_source(self.d)
                changed.unlink()
        self.observe.assert_not_called()
        self.integration.assert_not_called()
        self.packages.assert_not_called()
        self.assertFalse(self.store._present("maintenance/admissions"))

    def test_unknown_baseline_path_cannot_expand_symlink_authority(self):
        self.expected["trees"]["cloudnc"]["var/unreviewed"] = "a" * 64
        with self.assertRaises(ValueError):
            self.harness.admit_source(self.d)
        self.observe.assert_not_called()

    def test_replaced_root_and_missing_tree_refuse(self):
        self.d.jail_root = lambda jail: self.root / jail
        with self.assertRaises(ValueError):
            self.harness.admit_source(self.d)
        self.observe.assert_not_called()

    def test_full_observation_and_late_tree_drift_are_not_adopted(self):
        self.observe.return_value = {"config:list": "changed"}
        with self.assertRaises(ValueError):
            self.harness.admit_source(self.d)
        self.integration.assert_not_called()
        self.observe.return_value = {}
        def change(_):
            (self.d.jail_root("cloudnc") / "bin/changed").write_text("late writer")
            return {"config_sha256": "b" * 64, "apps_sha256": "c" * 64}
        self.integration.side_effect = change
        with self.assertRaises(ValueError):
            self.harness.admit_source(self.d)
        self.assertFalse(self.store._present("maintenance/admissions"))

    def test_private_exception_values_are_suppressed(self):
        self.observe.side_effect = ValueError("SECRET LDAP password")
        with self.assertRaisesRegex(ValueError, "^" + admission.DENIED + "$"):
            self.harness.admit_source(self.d)

    def test_startup_override_refusal_precedes_application_observations(self):
        self.startup.side_effect = ValueError("unreviewed rc.local")
        with self.assertRaises(ValueError):
            self.harness.admit_source(self.d)
        self.observe.assert_not_called()
        self.integration.assert_not_called()

    def test_descriptor_is_shared_with_updater_and_has_no_authority(self):
        from installer.maintenance_preflight import recipe
        self.assertEqual(self.harness.descriptor(), recipe())
        self.assertFalse(self.harness.descriptor()["execution_authorized"])
        with self.assertRaises(ValueError):
            admission.SourceAdmission({"eligible": True})


class OriginalSealTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.GenerationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root, self.store = fixture.root, fixture.store
        self.state = fixture.instance()
        from test_state import configuration
        self.config = replace(configuration(), tls_mode="provided", certificate_file="/cert", private_key_file="/key")
        atomic_write(self.state / "config.json", self.config.to_json())
        self.bindings = dict(schema=1, adapter=enrollment.ADAPTER, origin="first-install-readiness")
        atomic_json(self.state / enrollment.BASELINE, {**self.bindings, "observation": {"trees": {}}})
        for name in ("inputs.sha256", "complete", "allow-start"):
            atomic_write(self.state / name, "original\n")
        atomic_json(self.state / "inventory.json", {})
        names = ("config.json", "status.json", "deployment.json", "versions.json", "inventory.json",
                 "source.sha256", "inputs.sha256", "complete", "allow-start", enrollment.BASELINE)
        resources = dict(schema=1, adapter=enrollment.ADAPTER, instance="cloud", eligible=True, blockers=[],
            coverage="first-readiness-static-identity-comparison", source_sha256=fixtures.SOURCE,
            config_sha256=config_digest(self.config), package_inventory_sha256={},
            artifacts={name: hashlib.sha256((self.state / name).read_bytes()).hexdigest() for name in names})
        self.store.begin("enroll-one", "enroll", ["cloud"], fixtures.EXECUTOR)
        archive = self.store.archive_legacy("cloud", "enroll-one")
        self.generation = self.store.seal_generation("cloud", "initial", "enroll-one", archive=archive,
            evidence={"policy.json": (RESOURCES / "versions.json").read_bytes(), "resources.json": _encode(resources)})
        atomic_json(self.state / "config.json", descriptor("cloud", self.generation))
        fixture.publish({"cloud": dict(kind="managed", generation=self.generation, status={"state": "ready"})})
        self.executor = dict(source_sha256=fixtures.SOURCE)
        self.store._put("lifecycle/executor.json", self.executor)
        self.registry = Registry(self.root)
        self.native = NativeState(self.registry, self.executor)
        self.harness = admission.SourceAdmission(self.native)
        self.d = SimpleNamespace(registry=self.registry, state=self.state, config=self.config,
                                 versions={"fixture": "original lock"}, validate_resume=Mock())
        from installer import maintenance, maintenance_generations, resolution, enrollment_start
        for target, name, kwargs in (
                (admission.fence, "_root_required", {}), (enrollment_start, "_held", {}),
                (maintenance, "executor_record", {"return_value": self.executor}),
                (maintenance, "require_instance_adapter", {}),
                (resolution, "validate_plan", {"side_effect": lambda c, p: p}),
                (maintenance_generations, "target_plan", {}),
                (enrollment, "_baseline_bindings", {"return_value": self.bindings}),
                (enrollment, "_inputs", {}), (enrollment, "validate_guard", {})):
            manager = patch.object(target, name, **kwargs)
            manager.start()
            self.addCleanup(manager.stop)
        steps = {name: {"state": "complete"} for name in ("instance ZFS storage", "private networking and PF",
            "FreeBSD jail roots", "persistent mounts", "Nextcloud publication", "readiness checks", "boot activation")}
        manager = patch.object(admission, "Journal", return_value=SimpleNamespace(data={"steps": steps}))
        manager.start()
        self.addCleanup(manager.stop)

    def original(self):
        with self.registry.locked():
            return self.harness._original(self.d)

    def test_managed_descriptor_uses_original_config_and_sealed_baseline(self):
        result = self.original()
        self.assertEqual(result[1], self.generation)
        self.assertIn("legacy/files/enrollment-baseline.json", result[3]["path"])

    def test_changed_first_readiness_or_private_original_is_not_new_baseline(self):
        for name in (enrollment.BASELINE, "inputs.sha256", "inventory.json", "secrets.json"):
            with self.subTest(name=name):
                path = self.state / name
                original = path.read_bytes()
                atomic_json(path, {"replacement": True})
                with self.assertRaises(ValueError):
                    self.original()
                path.write_bytes(original)

    def test_external_acme_pending_or_unlocked_sources_refuse(self):
        for mode in ("external", "acme"):
            self.d.config = replace(self.config, tls_mode=mode)
            with self.assertRaises(ValueError):
                self.original()
        self.d.config = self.config
        with self.assertRaises(ValueError):
            self.harness._original(self.d)
        with patch.object(self.native.store, "pending", return_value={"action": "maintenance"}):
            with self.assertRaises(ValueError):
                self.original()

    def test_successor_is_not_admitted_as_first_edge(self):
        manifest = self.store._generation("cloud", self.generation)
        with patch.object(self.native.store, "_generation", return_value={**manifest,
                "kind": "maintenance-generation", "predecessor": self.generation}):
            with self.assertRaises(ValueError):
                self.original()


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="admission-apps-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        app = self.root / "usr/local/www/nextcloud"
        for name in ("apps/files", "apps/user_ldap", "custom_apps/onlyoffice"):
            (app / name).mkdir(parents=True)
        self.apps = {"enabled": {"files": "1.0.0", "onlyoffice": "10.2.1"}, "disabled": {"user_ldap": "1.0.0"}}
        self.config = {"system": {"datadirectory": "/var/nc-data", "dbtype": "mysql", "dbhost": "localhost"},
                       "apps": {"onlyoffice": {}, "user_ldap": {"installed_version": "1.0.0"}}}
        self.d = SimpleNamespace(config=SimpleNamespace(nextcloud_jail="cloudnc"), jail_root=lambda _: self.root)
        backend = Mock()
        backend.occ.side_effect = lambda command, *args: json.dumps(self.apps if command == "app:list" else self.config)
        manager = patch.object(admission, "NativeBackend", return_value=backend)
        manager.start()
        self.addCleanup(manager.stop)

    def test_config_records_only_hashes_and_rejects_ldap_smtp_storage(self):
        self.assertEqual(set(admission._integrations(self.d)), {"apps_sha256", "config_sha256"})
        for key in ("mail_smtphost", "objectstore", "user_backends"):
            self.config["system"][key] = "SECRET"
            with self.assertRaises(ValueError):
                admission._integrations(self.d)
            del self.config["system"][key]
        self.config["apps"]["user_ldap"]["ldapHost"] = "SECRET"
        with self.assertRaises(ValueError):
            admission._integrations(self.d)

    def test_installer_database_and_disabled_mail_spellings_are_exact(self):
        self.config["system"].update(dbhost="127.0.0.1", mail_smtpmode="null")
        self.assertEqual(set(admission._integrations(self.d)), {"apps_sha256", "config_sha256"})
        for value in ("smtp", "sendmail", "Null", 0):
            with self.subTest(value=value):
                self.config["system"]["mail_smtpmode"] = value
                with self.assertRaises(ValueError):
                    admission._integrations(self.d)
        self.config["system"]["mail_smtpmode"] = "null"
        self.config["system"]["dbhost"] = "database.example.test"
        with self.assertRaises(ValueError):
            admission._integrations(self.d)

    def test_only_reviewed_background_job_runtime_config_is_admitted(self):
        self.config["apps"]["backgroundjob"] = {"lastjob": "1771250000"}
        self.assertEqual(set(admission._integrations(self.d)), {"apps_sha256", "config_sha256"})
        self.config["apps"]["backgroundjob"]["unreviewed"] = "SECRET"
        with self.assertRaises(ValueError):
            admission._integrations(self.d)
        del self.config["apps"]["backgroundjob"]
        self.config["apps"]["not_an_app"] = {}
        with self.assertRaises(ValueError):
            admission._integrations(self.d)


    def test_unknown_disabled_code_is_not_approved(self):
        (self.root / "usr/local/www/nextcloud/custom_apps/extra").mkdir()
        self.apps["disabled"]["extra"] = "1.0.0"
        with self.assertRaises(ValueError):
            admission._integrations(self.d)


class ScheduledWriterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="admission-cron-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.d = SimpleNamespace(config=SimpleNamespace(nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo"),
                                 jail_root=lambda jail: self.root / jail, jail=Mock())
        self.native_owners = {}
        self.real_stat, self.real_fstat = os.stat, os.fstat
        for jail in ("cloudnc", "cloudoo"):
            (self.root / jail / "var/cron/tabs").mkdir(parents=True, mode=0o700)
            for name in ("jobs", "spool"):
                path = self.root / jail / "var/at" / name
                path.mkdir(parents=True, mode=0o755)
                path.chmod(0o755)
                self.owner(path, 1, 0)
        # Non-root offline test: real filesystem/dirfds, only native uid/gid
        # observations are modeled. Do not chown or relax production constants.
        for name, implementation in (("stat", lambda *a, **kw: self.metadata(self.real_stat(*a, **kw))),
                                     ("fstat", lambda fd: self.metadata(self.real_fstat(fd)))):
            manager = patch.object(admission.os, name, side_effect=implementation)
            manager.start()
            self.addCleanup(manager.stop)
        self.template = (RESOURCES / "templates/nextcloud/www-crontab").read_text()
        atomic_write(self.root / "cloudnc/var/cron/tabs/www", "# native spool header\n" + self.template)
        self.d.jail.return_value = SimpleNamespace(returncode=0, stdout=self.template)

    def owner(self, path, uid, gid):
        info = self.real_stat(path, follow_symlinks=False)
        self.native_owners[info.st_dev, info.st_ino] = (uid, gid)

    def metadata(self, info):
        owner = self.native_owners.get((info.st_dev, info.st_ino))
        if owner is None:
            return info
        values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        return SimpleNamespace(**{**values, "st_uid": owner[0], "st_gid": owner[1]})

    def marker(self):
        path = self.root / "cloudnc/var/at/jobs/.lockfile"
        atomic_write(path, "")
        self.owner(path, 0, 0)
        return path

    def test_only_template_cron_and_no_extra_spool_jobs(self):
        admission._scheduled_writers(self.d)
        self.d.jail.assert_called_once_with("cloudnc", "crontab", "-u", "www", "-l", hide_output=True)
        for relative in ("cloudnc/var/cron/tabs/root", "cloudoo/var/cron/tabs/www", "cloudnc/var/at/jobs/task"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(path, "unexpected writer")
            with self.assertRaises(ValueError):
                admission._scheduled_writers(self.d)
            path.unlink()

    def test_modified_template_or_symlink_spool_refuses(self):
        self.d.jail.return_value.stdout += "* * * * * php /tmp/custom.php\n"
        with self.assertRaises(ValueError):
            admission._scheduled_writers(self.d)
        self.d.jail.return_value.stdout = self.template
        path = self.root / "cloudnc/var/cron/tabs/www"
        path.unlink()
        path.symlink_to(RESOURCES / "templates/nextcloud/www-crontab")
        with self.assertRaises((ValueError, OSError)):
            admission._scheduled_writers(self.d)

    def test_native_daemon_directories_and_lazy_empty_root_lock_are_admitted(self):
        admission._at_inventory(self.root / "cloudnc")
        self.marker()
        admission._at_inventory(self.root / "cloudnc")
        self.d.jail.assert_not_called()

    def test_at_directory_owner_group_mode_and_ancestry_are_pinned(self):
        for name in ("jobs", "spool"):
            path = self.root / "cloudnc/var/at" / name
            for uid, gid in ((0, 0), (1, 1), (123, 0)):
                self.owner(path, uid, gid)
                with self.subTest(name=name, uid=uid, gid=gid), self.assertRaises(ValueError):
                    admission._at_inventory(self.root / "cloudnc")
            self.owner(path, 1, 0)
            path.chmod(0o775)
            with self.assertRaises(ValueError):
                admission._at_inventory(self.root / "cloudnc")
            path.chmod(0o755)
        parent = self.root / "cloudnc/var/at"
        self.owner(parent, 1, 0)
        with self.assertRaises(ValueError):
            admission._at_inventory(self.root / "cloudnc")

    def test_only_exact_empty_private_single_link_lock_is_allowed(self):
        path = self.marker()
        for uid, gid in ((1, 0), (0, 1)):
            self.owner(path, uid, gid)
            with self.assertRaises(ValueError):
                admission._at_inventory(self.root / "cloudnc")
        self.owner(path, 0, 0)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            admission._at_inventory(self.root / "cloudnc")
        path.chmod(0o600)
        path.write_bytes(b"not an empty marker")
        with self.assertRaises(ValueError):
            admission._at_inventory(self.root / "cloudnc")
        path.write_bytes(b"")
        os.link(path, self.root / "linked-marker")
        with self.assertRaises(ValueError):
            admission._at_inventory(self.root / "cloudnc")
        path.unlink()
        path.symlink_to(self.root / "linked-marker")
        with self.assertRaises((ValueError, OSError)):
            admission._at_inventory(self.root / "cloudnc")

    def test_sequence_jobs_outputs_and_symlink_containers_are_refused(self):
        for name in ("jobs/.SEQ", "jobs/c0000100000001", "spool/.lockfile", "spool/output"):
            path = self.root / "cloudnc/var/at" / name
            path.write_bytes(b"")
            with self.subTest(name=name), self.assertRaises(ValueError):
                admission._at_inventory(self.root / "cloudnc")
            path.unlink()
        path = self.root / "cloudnc/var/at/jobs"
        path.rename(path.with_name("moved"))
        path.symlink_to("moved", target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            admission._at_inventory(self.root / "cloudnc")

    def test_transient_directory_and_lock_content_races_refuse(self):
        path = self.marker()
        real_read = os.read
        for change in ("directory", "lock"):
            def raced(fd, count):
                target = path.parent / "transient" if change == "directory" else path
                target.write_bytes(b"changed")
                if change == "directory":
                    target.unlink()
                else:
                    target.write_bytes(b"")
                return real_read(fd, count)
            with self.subTest(change=change), patch.object(admission.os, "read", side_effect=raced):
                with self.assertRaises(ValueError):
                    admission._at_inventory(self.root / "cloudnc")

if __name__ == "__main__":
    unittest.main()
