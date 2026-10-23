"""Fixed commands, real private files and fault injection; no native execution."""

from copy import deepcopy
from dataclasses import asdict
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_validation as validation, maintenance_generations as generations
from installer import maintenance_journal as journal, maintenance_update as updater, nextcloud_update as update
from installer.generations import Store, _encode, _hash, _json
from installer.maintenance_native import NativeContext
from installer.maintenance_publication import CLOSED_CHECKS, OPEN_CHECKS, PublicationBlocked
from installer.paths import RESOURCES
from installer.runtime_inventory import HELPER
from test_maintenance_preflight import inputs as runtime_fixture
import test_maintenance_native as native_fixtures
from version_fixtures import historical_maintenance_policy


class Fixture(unittest.TestCase):
    def setUp(self):
        self.enterContext(historical_maintenance_policy())
        temporary = tempfile.TemporaryDirectory(prefix="fixed-validation-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.enterContext(patch.object(validation, "ROOT_GID", os.getegid()))
        self.enterContext(patch("installer.runtime_inventory.ROOT_UID", os.geteuid()))
        self.n = n = object.__new__(NativeContext)
        n.operation, n.directory = "execution-validation", "maintenance/operations/execution-validation"
        n.store = Store(self.home / "state")
        n.store.root.mkdir(mode=0o700)
        n.store._mkdir(n.directory)
        n.c, self.plan, self.observed, _, _ = runtime_fixture()
        intent = n.record("intent", {"operation": n.operation})
        self.ref = n.record("fixture-observation", {"offline": True})
        n.journal = native_fixtures.MemoryJournal(n.store, n.directory, intent)
        n.journal.reference = intent
        # Exercise real native failure/phase schemas, but no boot permission.
        n.journal.fail = lambda code, **kwargs: self.fail_journal(code, **kwargs)
        for phase in ("quiesced", "recovery-ready", "migrating", "validating"):
            n.journal.advance(phase, {key: self.ref for key in journal.NATIVE_REQUIRED[phase]})
        self.inputs = dict(recipe=validation.policy.recipe(), executor={"executor_sha256": "e" * 64},
            entries={n.c.instance: {"generation": self.ref}}, originals={n.c.instance: {"files": {
                "config.json": {"retained": n.record("original-config", _json(n.c.to_json()))},
                "versions.json": {"retained": n.record("original-versions", self.plan)}}}})
        n.check = Mock(side_effect=lambda **kwargs: ({}, self.inputs, n.journal.read()))
        n.native = SimpleNamespace(read=lambda operation: ({}, self.inputs))
        n.profile = lambda: self.ref
        self.roots = {jail: self.home / jail for _, jail in validation._roles(n)}
        for root in self.roots.values():
            (root / "root/cloud-installer").mkdir(parents=True, mode=0o700)
        self.commands = []
        self.maintenance = True
        self.version = "35.0.1.1"
        self.master = 71
        self.failure = None
        n.backend = Mock()
        n.backend.running.side_effect = lambda jail, service: [(self.master, 1, "php-fpm")] if service == "php_fpm" else []
        n.backend.jailed.side_effect = self.command
        n.backend.occ.side_effect = self.occ
        n.backend.output.side_effect = self.output
        n.d = SimpleNamespace(config=n.c, jail_root=lambda jail: self.roots[jail],
                              require_running_jail=lambda jail: 41 if jail == n.c.nextcloud_jail else 42,
                              jail=self.command)
        n.admission = {"evidence": self.ref}
        n._recovery_context = Mock()

    def fail_journal(self, code, **kwargs):
        self.n.journal.value = journal.native_failure(self.n.journal.value, code, **kwargs)
        self.n.journal.save()

    def write(self, path, data, mode=0o600):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def package_rows(self, group):
        return "\n".join(" ".join(item[key] for key in ("name", "version", "origin"))
                         for item in self.observed["packages"][group])

    def output(self, *args):
        if args == ("pkg", "query", "%n %v %o"):
            return self.package_rows("host")
        if args == ("sysctl", "-n", "kern.boottime"):
            return "boot-one"
        raise AssertionError(args)

    def status(self):
        return dict(installed=True, maintenance=self.maintenance, needsDbUpgrade=False, version=self.version)

    def occ(self, *args):
        self.commands.append((self.n.c.nextcloud_jail, "occ", *args))
        if args == self.failure:
            raise RuntimeError("PRIVATE COMMAND DIAGNOSTIC")
        if args[0] == "maintenance:mode":
            marker = _json(self.n.store._read(self.n.directory + "/validation-canary.json"))
            self.assertEqual(marker["state"], "opening-canary")
            self.assertFalse(self.n.journal.read()["publication_may_have_begun"])
            self.assertFalse(self.n.journal.read()["recovery_publication_may_have_begun"])
            self.maintenance = args[1] == "--on"
            return ""
        if args[0] == "status":
            return json.dumps(self.status())
        if args[0] == "app:list":
            return json.dumps({"enabled": {"onlyoffice": "10.2.1"}, "disabled": {}})
        if args == ("onlyoffice:documentserver", "--check"):
            self.assertFalse(self.maintenance)
            return "Connection successful"
        raise AssertionError(args)

    def command(self, jail, *args, **kwargs):
        self.commands.append((jail, *args))
        if args == self.failure:
            raise RuntimeError("PRIVATE COMMAND DIAGNOSTIC")
        text = ""
        if args[:2] == ("pkg", "query"):
            text = self.package_rows("nextcloud" if jail == self.n.c.nextcloud_jail else "onlyoffice")
        elif args == ("cat", "/var/run/php-fpm.pid"):
            text = str(self.master)
        elif args[:1] == ("id",):
            text = "33"
        elif args[0] == "/usr/bin/env":
            self.assertIn(HELPER, args)
            key = {"cli": "cli", "main": "main_fpm", "callback": "callback_fpm"}[args[-1]]
            text = json.dumps(self.observed["php"][key])
        elif args[0] in ("mariadb", "/usr/local/bin/mariadb"):
            text = "134217728" if args[-1] == "SELECT @@innodb_log_file_size" else "12.3.3-MariaDB"
        elif args[0] == "mdo" and "config:app:get" in args:
            text = {"DocumentServerUrl": self.n.c.public_url + "onlyoffice/",
                    "DocumentServerInternalUrl": f"http://{self.n.c.onlyoffice_ip}:8081/",
                    "StorageUrl": self.n.c.storage_url}[args[-1]]
        elif args[0] == "mdo" and "/usr/local/bin/redis-cli" in args:
            self.assertEqual(args[1:3], ("-u", "www"))
            self.assertEqual(args[-3:], ("-s", "/var/run/redis/private/nextcloud.sock", "PING"))
            text = "PONG"
        elif args[0] == "supervisorctl":
            text = "ds:docservice RUNNING pid 11\nds:metrics RUNNING pid 12\n"
        elif args[0] == "curl":
            self.assertNotIn("--insecure", args)
            self.assertNotIn("-k", args)
            self.assertIn("--resolve", args)
            if args[-1].endswith("status.php"):
                text = json.dumps(self.status())
            elif args[-1].endswith("healthcheck"):
                text = "true"
            else:
                self.assertIn("--write-out", args)
                text = "403"
        elif args[0] == "python3":
            self.assertIn("socket.socket()" if jail == self.n.c.nextcloud_jail else "healthcheck", " ".join(args))
        elif args[0] not in ("php-fpm", "apachectl", "nginx"):
            raise AssertionError(args)
        return SimpleNamespace(returncode=0, stdout=text, stderr="")


class RuntimeStagingTests(Fixture):
    def source_payload(self):
        _, payloads = validation._payloads(self.n, self.inputs, False)
        for group, jail in validation._roles(self.n):
            for name, data in payloads[group].items():
                self.write(self.roots[jail] / "root/cloud-installer" / name, data)

    def test_only_five_public_files_per_jail_change_and_complete_receipt_is_exact(self):
        self.source_payload()
        sentinel = self.roots[self.n.c.nextcloud_jail] / "root/cloud-installer/tls/privkey.pem"
        self.write(sentinel, b"unchanged private fixture")
        ref = validation.stage_target_runtime(self.n)
        target, files = validation._payloads(self.n, self.inputs, True)
        self.assertEqual(sentinel.read_bytes(), b"unchanged private fixture")
        for group, jail in validation._roles(self.n):
            for name, data in files[group].items():
                path = self.roots[jail] / "root/cloud-installer" / name
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(_json(self.n.store._bound(ref))["target_files"], {k: _hash(v) for k, v in target.items()})
        self.assertEqual(validation.stage_target_runtime(self.n), ref)
        self.assertFalse(self.commands)

    def test_partial_runtime_writes_retry_original_or_target_but_never_adopt_drift(self):
        self.source_payload()
        replace = validation.fence._replace
        count = 0

        def crash(root, item, data):
            nonlocal count
            count += 1
            replace(root, item, data)
            if count == 1:
                raise OSError("crash after atomic rename")

        with patch.object(validation.fence, "_replace", side_effect=crash):
            with self.assertRaises(PublicationBlocked):
                validation.stage_target_runtime(self.n)
        # Both jails' runtime files differ; the first rename survived the crash.
        progress = _json(self.n.store._read(self.n.directory + "/target-runtime-progress.json"))
        self.assertEqual(progress["state"], "writing")
        validation.stage_target_runtime(self.n)
        path = self.roots[self.n.c.onlyoffice_jail] / "root/cloud-installer/runtime.json"
        path.write_bytes(b'{"db_password":"not permitted"}\n')
        with patch.object(validation.fence, "_replace") as mutate:
            with self.assertRaises(PublicationBlocked):
                validation.stage_target_runtime(self.n)
            mutate.assert_not_called()

    def test_unjournaled_target_or_missing_original_refuses_before_plan(self):
        self.source_payload()
        _, target = validation._payloads(self.n, self.inputs, True)
        path = self.roots[self.n.c.nextcloud_jail] / "root/cloud-installer/runtime.json"
        path.write_bytes(target["nextcloud"]["runtime.json"])
        with self.assertRaises(PublicationBlocked):
            validation.stage_target_runtime(self.n)
        self.assertFalse(self.n.store._present(self.n.directory + "/target-runtime-plan.json"))

    def test_effective_receipt_hashes_actual_helpers_and_matches_successor_schema(self):
        self.source_payload()
        validation.stage_target_runtime(self.n)
        source = {"installer/fixed.py": _hash(b"reviewed helper"),
                  "resources/jails/runtime-inventory.php": _hash(b"runtime helper")}
        for _, jail in validation._roles(self.n):
            self.write(self.roots[jail] / "root/cloud-installer/installer/fixed.py", b"reviewed helper")
            self.write(self.roots[jail] / "root/cloud-installer/resources/jails/runtime-inventory.php", b"runtime helper")
        helper = self.roots[self.n.c.nextcloud_jail] / HELPER.lstrip("/")
        self.write(helper, b"runtime helper", 0o640)
        with patch.object(generations, "source_hashes", return_value=source):
            ref = validation.effective_runtime_receipt(self.n, "target-generation")
            observed = _json(self.n.store._bound(ref))
            self.assertEqual(observed["kind"], "effective-public-worker-receipt")
            self.assertEqual(observed["generation"], "target-generation")
            self.assertEqual(set(observed["target_files"]), generations.TARGET_FILES)
            self.assertEqual(set(observed["jails"]), {"nextcloud", "onlyoffice"})
            helper.write_bytes(b"changed helper")
            with self.assertRaises(PublicationBlocked):
                validation.effective_runtime_receipt(self.n, "target-generation")
            self.assertEqual(helper.read_bytes(), b"changed helper")


class ConcreteValidationTests(Fixture):
    def validator(self):
        validator = validation.FixedValidator()
        self.enterContext(patch.object(validator, "_binding", return_value=({}, False)))
        self.enterContext(patch.object(validator, "_observe", return_value=(self.plan,
            {name: self.ref for name in CLOSED_CHECKS - {"cache", "connector"}})))
        return validator

    def test_closed_real_integration_canary_recloses_and_never_marks_publication(self):
        validator = self.validator()
        before = self.n.store.reference(self.n.journal.path)
        result = validator.closed(self.n, self.ref)
        self.assertEqual(set(result), CLOSED_CHECKS)
        self.assertTrue(self.maintenance)
        self.assertEqual(self.n.store.reference(self.n.journal.path), before)
        self.assertEqual(_json(self.n.store._read(self.n.directory + "/validation-canary.json"))["state"], "closed")
        self.assertEqual([call[-1] for call in self.commands if "maintenance:mode" in call], ["--off", "--on"])
        self.assertGreaterEqual(self.n.backend.deny_probe.call_count, 3)
        http_jails = {call[0] for call in self.commands if call[1] == "curl"}
        self.assertEqual(http_jails, set(self.roots))
        self.assertFalse(any("service" in call or "stage_payloads" in call or "sysrc" in call for call in self.commands))

    def test_failed_connector_restores_maintenance_and_fails_journal_without_diagnostics(self):
        validator = self.validator()
        self.failure = ("onlyoffice:documentserver", "--check")
        with self.assertRaises(PublicationBlocked) as caught:
            validator.closed(self.n, self.ref)
        self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertTrue(self.maintenance)
        record = self.n.journal.read()
        self.assertEqual(record["phase"], "recovery-required")
        self.assertEqual(record["error"], "validation-failed")
        self.assertFalse(record["publication_may_have_begun"])

    def test_post_open_reuses_only_queries_without_maintenance_changes_or_general_check(self):
        validator = self.validator()
        self.maintenance = False
        self.n.check.side_effect = AssertionError("general native check forbids publication")
        before = self.n.store.reference(self.n.journal.path)
        result = validator.post_open(self.n, self.ref)
        self.assertEqual(set(result), OPEN_CHECKS)
        self.assertEqual(self.n.store.reference(self.n.journal.path), before)
        self.assertFalse(any("maintenance:mode" in call or "service" in call or "sysrc" in call for call in self.commands))

    def test_failed_maintenance_restore_is_durable_and_never_claims_readiness(self):
        validator = self.validator()
        self.failure = ("maintenance:mode", "--on")
        with self.assertRaises(PublicationBlocked):
            validator.closed(self.n, self.ref)
        self.assertFalse(self.maintenance)
        self.assertEqual(_json(self.n.store._read(self.n.directory + "/validation-canary.json"))["state"], "opening-canary")
        self.assertEqual(self.n.journal.read()["phase"], "recovery-required")

    def test_deny_failure_before_canary_never_turns_maintenance_off(self):
        validator = self.validator()
        self.n.backend.deny_probe.side_effect = ValueError("not 503")
        with self.assertRaises(PublicationBlocked):
            validator.closed(self.n, self.ref)
        self.assertTrue(self.maintenance)
        self.assertFalse(any("maintenance:mode" in call for call in self.commands))

    def test_deny_loss_during_canary_disallows_destructive_recovery(self):
        validator = self.validator()
        self.n.backend.deny_probe.side_effect = [None, ValueError("not 503"), None]
        with self.assertRaises(PublicationBlocked):
            validator.closed(self.n, self.ref)
        self.assertTrue(self.maintenance)
        self.assertTrue(self.n.journal.read()["publication_may_have_begun"])
        self.assertEqual(self.n.journal.read()["error"], "closure-lost")

    def runtime_observation(self):
        self.write(self.roots[self.n.c.nextcloud_jail] / HELPER.lstrip("/"),
                   (RESOURCES / "jails/runtime-inventory.php").read_bytes(), 0o640)
        start = self.n.record("closed-start", dict(profile=self.ref, phase="recovery-validating", prior_state="stopped"))
        self.n.record("validation-started", dict(attempt=start))
        prepared = {"observations": {"full_packages": {
            group: sorted(rows, key=lambda row: (row["name"], row["version"], row["origin"]))
            for group, rows in self.observed["packages"].items()}, "database": "12.3.3-MariaDB",
            "php": deepcopy(self.observed["php"]), "apps": {"enabled": {"onlyoffice": "10.2.1"}, "disabled": {}}}}
        self.enterContext(patch.object(validation, "_code", return_value=(prepared, None,
            update.Inventory((), ()), self.ref, self.ref)))
        self.enterContext(patch.object(validation, "effective_runtime_receipt", return_value=self.ref))
        manifest = {"versions": self.inputs["originals"][self.n.c.instance]["files"]["versions.json"]["retained"],
                    "generation_id": "source-generation"}
        return validation.FixedValidator(), manifest

    def test_actual_cli_and_both_fpm_pools_and_current_master_are_observed(self):
        validator, manifest = self.runtime_observation()
        _, checks = validator._observe(self.n, manifest, False)
        self.assertEqual({call[-1] for call in self.commands if call[1] == "/usr/bin/env"}, {"cli", "main", "callback"})
        self.assertEqual(_json(self.n.store._bound(checks["fpm_restart"]))["pid"], 71)
        self.observed["php"]["callback_fpm"]["loaded_modules"].remove("openssl")
        with self.assertRaises(ValueError):
            validator._observe(self.n, manifest, False)

    def test_extra_live_package_refuses_before_runtime_php(self):
        validator, manifest = self.runtime_observation()
        self.observed["packages"]["nextcloud"].append(dict(name="unexpected", version="1.0", origin="misc/unexpected"))
        with self.assertRaises(ValueError):
            validator._observe(self.n, manifest, False)
        self.assertFalse(any(call[1] == "/usr/bin/env" for call in self.commands))

    def test_replaced_fpm_master_invalidates_runtime_observation(self):
        validator, manifest = self.runtime_observation()
        def replaced(view):
            self.master += 1
            return self.observed["php"]
        with patch.object(validation, "collect_php", side_effect=replaced):
            with self.assertRaisesRegex(PublicationBlocked, "fpm-master-changed-during-validation"):
                validator._observe(self.n, manifest, False)

    def test_missing_authenticated_preparation_has_fixed_actionable_blocker(self):
        validator = validation.FixedValidator()
        with patch.object(validator, "_binding", return_value=({}, False)):
            with self.assertRaisesRegex(PublicationBlocked, "authenticated-update-preparation-required"):
                validator.closed(self.n, self.ref)
        self.assertFalse(any(call[1] == "occ" for call in self.commands))


class CopyVerifierTests(Fixture):
    def references(self):
        self.n.store._mkdir(self.n.directory + "/recovery")
        manifest = self.n.store._put(self.n.directory + "/recovery/manifest.json", dict(datasets={str(i): {} for i in range(14)},
            snapshots={str(i): {} for i in range(14)}, evidence={"private": {}}))
        self.n.journal.value["evidence"]["recovery_set"] = manifest
        self.n.journal.save()
        receipt = self.n.record("copy-receipt", dict(root="backup/owned", path="/backup/export.json", sha256="a" * 64, size=100))
        value = dict(manifest=manifest, receipt=_json(self.n.store._bound(receipt)), datasets=14, snapshots=14, evidence_files=1)
        proof = self.n.record("copy-validation", value)
        self.enterContext(patch.object(validation.recovery, "validate_manifest", side_effect=lambda c, v: v))
        return manifest, receipt, proof, value

    @staticmethod
    def native_observation(receipt):
        from installer import recovery_export
        return dict(evidencecopyverified=True, restorestream_rehearsal=False, fullapplicationrestorerehearsal=False,
                    physical_independence_unassessed=True, threat_scope=recovery_export.SCOPE, receipt=receipt)

    def test_concrete_adapter_calls_live_verifier_and_matches_exact_references_counts(self):
        manifest, receipt, proof, observed = self.references()
        native = self.native_observation(observed["receipt"])
        actual = Mock(return_value=native)
        verifier = validation.RecoveryCopyVerifier(actual)
        ref = verifier.recheck(self.n, manifest, receipt, proof)
        actual.assert_called_once_with(self.n, observed["receipt"])
        self.assertEqual(_json(self.n.store._bound(ref)), dict(manifest=manifest, receipt=receipt, validation=proof,
                                                           datasets=14, snapshots=14, evidence_files=1))
        for invalid in (True, {**native, "evidencecopyverified": False}, {**native, "receipt": {}}):
            actual.return_value = invalid
            with self.assertRaises(PublicationBlocked):
                verifier.recheck(self.n, manifest, receipt, proof)
        actual.return_value = native
        retained = verifier.validate(self.n, manifest, receipt)
        self.assertEqual(_json(self.n.store._bound(retained)), observed)
        for wrong in (dict(observed, snapshots=13), dict(observed, datasets=True)):
            invalid = self.n.record("wrong-copy-validation-" + _hash(_encode(wrong)), wrong)
            with self.assertRaisesRegex(PublicationBlocked, "retained-copy-validation-binding-drift"):
                verifier.recheck(self.n, manifest, receipt, invalid)

    def test_copy_backend_failure_never_falls_back_to_cold_verifier_or_boolean(self):
        manifest, receipt, proof, _ = self.references()
        verifier = validation.RecoveryCopyVerifier(Mock(side_effect=ValueError("PRIVATE OUTPUT")))
        with self.assertRaises(PublicationBlocked) as caught:
            verifier.recheck(self.n, manifest, receipt, proof)
        self.assertNotIn("PRIVATE", str(caught.exception))
        from installer import recovery_export
        with patch.object(recovery_export, "verify_retained", None, create=True), patch.object(recovery_export, "verify") as cold:
            with self.assertRaisesRegex(PublicationBlocked, "live-closed-retained-copy-verifier-unavailable"):
                validation.RecoveryCopyVerifier().recheck(self.n, manifest, receipt, proof)
            cold.assert_not_called()

    def test_default_adapter_uses_new_live_closed_export_verifier(self):
        manifest, receipt, proof, observed = self.references()
        from installer import recovery_export
        with patch.object(recovery_export, "verify_retained", return_value=self.native_observation(observed["receipt"])) as live, \
                patch.object(recovery_export, "verify") as cold:
            validation.RecoveryCopyVerifier().recheck(self.n, manifest, receipt, proof)
            live.assert_called_once_with(self.n, observed["receipt"])
            cold.assert_not_called()


class AuthenticatedCodeTests(Fixture):
    def test_inventory_requires_explicit_boolean_executable(self):
        value = dict(files=[dict(path="occ", size=1, sha256="a" * 64, executable=True)], directories=[""])
        self.assertTrue(validation._inventory(value).files[0].executable)
        for flag in (None, 0, 1, "true"):
            with self.assertRaises(ValueError):
                validation._inventory(dict(value, files=[dict(value["files"][0], executable=flag)]))
        del value["files"][0]["executable"]
        with self.assertRaises(ValueError):
            validation._inventory(value)

    def effect(self, event, binding):
        n = self.n
        value = dict(schema_version=1, kind="nextcloud-update-effect", operation=n.operation,
            intent=n.journal.reference, journal=n.store.reference(n.journal.path), event=event,
            state="before", binding=binding, before=None)
        before = None
        if event != "target-code-verified":
            before = n.record("update-" + event + "-before", value)
        return n.record("update-" + event + "-after", dict(value, state="after", before=before))

    def prepared_code(self, *, target):
        n = self.n
        self.enterContext(patch.object(update, "_ROOT_UID", os.geteuid()))
        # File ownership is native-only; this model uses its real unprivileged
        # test identity for both source owners, retaining all mode/hash checks.
        self.enterContext(patch.object(n.backend, "jailed", side_effect=lambda jail, *args:
            SimpleNamespace(stdout=str(os.getegid() if args == ("id", "-g", "www") else os.geteuid()))))
        self.source = {"occ": b"signed occ", "version.php": b"signed source version",
                       "lib/core.php": b"signed source core", "updater/updater.phar": b"signed updater"}
        self.target = dict(self.source, **{"version.php": b"signed target version", "lib/core.php": b"signed target core"})
        def inventory(files):
            return update.Inventory(tuple(update.FileHash(name, len(data), _hash(data)) for name, data in sorted(files.items())),
                                    ("", "lib", "updater"))
        root = self.roots[n.c.nextcloud_jail]
        self.app = root / update.APP.lstrip("/")
        for name, data in (self.target if target else self.source).items():
            self.write(self.app / name, data, 0o640)
        for path in (self.app, self.app / "lib", self.app / "updater"):
            path.chmod(0o750)
        self.write(self.app / "config/config.php", b"private config", 0o600)
        self.write(self.app / "custom_apps/onlyoffice/lib.php", b"retained connector", 0o640)
        context = SimpleNamespace(host=lambda path: root / path.lstrip("/"), www_uid=os.geteuid(), www_gid=os.getegid())
        source_inventory, target_inventory = inventory(self.source), inventory(self.target)
        # Explicit pre-alias legacy shape, independent of the new serializers.
        def legacy_inventory(value):
            return dict(files=[asdict(item) for item in value.files], directories=list(value.directories))
        bundle = dict(operation=n.operation, source=dict(archive_sha256="a" * 64, proof_sha256="b" * 64),
            artifacts=[dict(path="nextcloud-35.0.2.zip", sha256="c" * 64, size=100, executable=False)],
            source_inventory=legacy_inventory(source_inventory), target_inventory=legacy_inventory(target_inventory), signature="c2ln")
        receipt = dict(source=bundle["source"], source_version=list(update.SOURCE), target_version=list(update.TARGET),
            operation=n.operation, key=update.RELEASE_KEY, artifacts=bundle["artifacts"],
            source_files=bundle["source_inventory"]["files"], source_directories=bundle["source_inventory"]["directories"],
            target_files=bundle["target_inventory"]["files"], target_directories=bundle["target_inventory"]["directories"])
        raw = _encode(receipt)
        self.receipt_path = root / update.STAGING.lstrip("/") / n.operation / "receipt.json"
        self.write(self.receipt_path, raw)
        bundle["receipt_sha256"] = _hash(raw)
        prepared = dict(schema_version=1, kind="prepared-nextcloud-patch", operation=n.operation,
            intent=n.journal.reference, preparation=n.record("prepared-parent", dict(plan=self.ref)), plan=self.ref, admission=n.admission["evidence"],
            recipe=updater.descriptor(), memory_mib=1024, bundle=bundle, observations={},
            custom=updater._custom(context), config_metadata=updater._config_metadata(context))
        self.inputs["preparation"] = prepared["preparation"]
        prepared_ref = n.record("update-prepared", prepared)
        self.effect("stage-artifacts", bundle["receipt_sha256"])
        if target:
            n.journal = native_fixtures.MemoryJournal(n.store, n.directory, n.store.reference(n.directory + "/intent.json"))
            n.journal.reference = n.store.reference(n.directory + "/intent.json")
            for phase in ("quiesced", "recovery-ready", "migrating"):
                n.journal.advance(phase, {key: self.ref for key in journal.NATIVE_REQUIRED[phase]})
            n.journal.step_start("reviewed-migration", replay="never", precondition=self.ref)
            for event in ("target-integrity", "target-code-verified", "final-runtime"):
                self.effect(event, bundle["receipt_sha256"])
            self.effect("code-hardened", updater._hash(bundle["target_inventory"]))
            self.effect("adapter", prepared_ref["sha256"])
            result = n.record("update-result", dict(schema_version=1, kind="nextcloud-patch-result", operation=n.operation,
                prepared=prepared_ref, receipt_sha256=bundle["receipt_sha256"], target=list(update.TARGET), runtime={},
                hardened_sha256=updater._hash(updater._code(context, target_inventory)), custom_sha256=updater._hash(prepared["custom"]),
                appstore={"exists": False, "value": False}, maintenance=True, native_acceptance="not-run", publication_authorized=False))
            n.journal.step_complete("reviewed-migration", result)
            n.journal.advance("validating", {key: self.ref for key in journal.NATIVE_REQUIRED["validating"]})

    def test_legacy_prepared_and_hardening_effect_records_keep_original_hashes(self):
        self.prepared_code(target=True)
        path = self.n.directory + "/update-prepared.json"
        before = self.n.store._read(path)
        prepared = _json(before)
        self.assertNotIn("links", prepared["bundle"]["source_inventory"])
        self.assertNotIn("links", prepared["bundle"]["target_inventory"])
        old_hash = updater._hash(prepared["bundle"]["target_inventory"])
        validation._effect(self.n, "code-hardened", old_hash)
        validation._code(self.n, True)
        self.assertEqual(self.n.store._read(path), before)

    def test_full_target_inventory_result_integrity_and_final_fpm_stop_are_required(self):
        self.prepared_code(target=True)
        _, _, _, code, integrity = validation._code(self.n, True)
        self.assertTrue(self.n.store._bound(code))
        self.assertIn("target-code-verified-after", integrity["path"])
        path = self.app / "lib/core.php"
        path.write_bytes(b"unreviewed code")
        with self.assertRaises(ValueError):
            validation._code(self.n, True)
        path.write_bytes(self.target["lib/core.php"])
        (self.n.store.root / self.n.directory / "update-final-runtime-after.json").unlink()
        with self.assertRaises((ValueError, OSError)):
            validation._code(self.n, True)
        self.assertFalse(any(call[1] == "occ" for call in self.commands))

    def test_restored_source_inventory_is_authenticated_and_rejects_extra_files(self):
        self.prepared_code(target=False)
        validation._code(self.n, False)
        self.write(self.app / "lib/unreviewed.php", b"not in source inventory", 0o640)
        with self.assertRaises(ValueError):
            validation._code(self.n, False)
        (self.app / "lib/unreviewed.php").unlink()
        self.receipt_path.write_bytes(b"changed signed-source binding")
        with self.assertRaisesRegex(PublicationBlocked, "authenticated-inventory-receipt-drift"):
            validation._code(self.n, False)


if __name__ == "__main__":
    unittest.main()
