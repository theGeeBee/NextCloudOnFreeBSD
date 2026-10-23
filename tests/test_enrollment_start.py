"""Live-lock enrollment start authorization; all native commands are mocked."""

from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import enrollment, enrollment_start as starts
from installer.config import Config
from installer.deploy import Deployment, OWNER
from installer.generations import Store
from installer.maintenance import _EnrollmentView, executor_record
from installer.state import Registry, atomic_json, atomic_write, config_digest


def _crash_with_permission(root, intent, plan, connection):
    registry = Registry(root)
    with registry.locked(recovery=True), starts.start_permission(registry, intent, plan):
        connection.send("held")
        connection.recv()
        os._exit(0)


class EnrollmentStartTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="enrollment-start-")
        self.addCleanup(temporary.cleanup)
        self.registry = Registry(Path(temporary.name) / "state")
        self.registry.initialize()
        self.config = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                             acme_email="admin@example.test", external_interface="igb0",
                             ingress_address="192.0.2.10", dns_server="192.0.2.53",
                             management_network="198.51.100.0/24", accept_microsoft_fonts=True)
        self.secrets = {"admin_password": "private", "db_password": "a" * 64, "jwt_secret": "b" * 64}
        self.state = self.registry.save_new(self.config, self.secrets)
        self.registry.set_status(self.config.instance, "ready")
        self.store = Store(self.registry.root)
        self.directory = "maintenance/operations/enroll-test"
        self.store._mkdir(self.directory)
        self.executor = executor_record()
        name = self.config.instance
        original = {
            "config": self.store._write(self.directory + "/" + name + "-config.json", (self.state / "config.json").read_bytes()),
            "status": self.store._write(self.directory + "/" + name + "-status.json", (self.state / "status.json").read_bytes())}
        self.plan = {"schema_version": 1, "operation": "enroll-test", "instance": name,
                     "executor": self.executor, "generation": "initial-test", "graph": "graph-test",
                     "originals": {name: original}, "entries": {}, "evidence": {},
                     "assessment": {"schema": 1, "adapter": enrollment.ADAPTER, "eligible": True,
                                    "instance": name, "source_sha256": self.executor["source_sha256"],
                                    "config_sha256": config_digest(self.config),
                                    "artifacts": {"config.json": original["config"]["sha256"]}}}
        reference = self.store._put(self.directory + "/enrollment.json", self.plan)
        self.store._put(self.directory + "/enrollment-inputs.json", {"schema_version": 1, "plan": reference})
        self.intent = self.store.begin("enroll-test", "enroll", [name], self.executor["executor_sha256"])
        self.permission = self.registry.root / self.directory / "start-permission.json"
        self.lock = self.permission.with_name("start-permission.lock")
        self.view = _EnrollmentView(self.registry, self.store, self.plan)
        self.runner = Mock(spec=["run", "output"])
        self.deployment = Deployment(self.config, self.secrets, self.runner, registry=self.view)
        self.pair = (self.config.nextcloud_jail, self.config.onlyoffice_jail)
        self.live = {}
        self.dying = set()
        self.native = []
        self.runner.run.side_effect = self.run_command
        self.runner.output.side_effect = self.output_command

    def boot(self, **changes):
        args = dict(registry=Registry(self.registry.root), intent=self.intent, instance=self.config.instance,
                    jail=self.config.nextcloud_jail, executor=self.executor["executor_sha256"])
        args.update(changes)
        return starts.boot_permission(**args)

    def run_command(self, *args, **kwargs):
        self.native.append(args)
        if args[:2] == ("jls", "-d"):
            rows = []
            for name, jid in self.live.items():
                host = self.config.nextcloud_host if name == self.pair[0] else self.config.onlyoffice_host
                dying = "true" if name in self.dying else "false"
                rows.append(f"{jid} {name} {self.deployment.jail_root(name)} {dying} {host}")
            return SimpleNamespace(returncode=0, stdout="\n".join(rows))
        if args[:2] == ("jls", "-j"):
            name = args[2]
            return SimpleNamespace(returncode=0 if name in self.live else 1,
                                   stdout=f"{self.live[name]} {name} {self.deployment.jail_root(name)}"
                                   if name in self.live else "")
        if args[:2] == ("bastille", "start"):
            self.assertEqual(self.boot(jail=args[2]), self.config)
            self.live[args[2]] = 10 + self.pair.index(args[2])
            return SimpleNamespace(returncode=0, stdout="")
        if args[:2] == ("bastille", "stop"):
            del self.live[args[2]]
            return SimpleNamespace(returncode=0, stdout="")
        if args[:2] == ("/bin/sh", "-s"):
            self.assertIn("pfctl", kwargs["input"])
            self.assertNotIn("boot_check", kwargs["input"])
            return SimpleNamespace(returncode=0, stdout="")
        self.fail(f"Unexpected mocked native command: {args}")

    def output_command(self, *args, **kwargs):
        if args[:2] == ("bastille", "config"):
            name = args[2]
            if args[-1] == "path":
                return str(self.deployment.jail_root(name))
            if args[-1] == "host.hostname":
                return self.config.nextcloud_host if name == self.pair[0] else self.config.onlyoffice_host
        if args[:3] == ("zfs", "get", "-H") and args[-2] == OWNER:
            return self.config.instance
        self.fail(f"Unexpected mocked native query: {args}")

    @contextmanager
    def checked_starts(self):
        def checked(deployment, names=None, **kwargs):
            return [(name, "owned") for name in (names if names is not None else self.pair)]
        with patch.object(starts, "_preflight", side_effect=lambda *args: starts._live_pair(self.deployment)), \
                patch("installer.lifecycle._checked_jails", side_effect=checked):
            yield

    def test_live_exact_permission_and_ordinary_exit_revocation(self):
        with self.registry.locked(recovery=True):
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                self.boot()
            with starts.start_permission(self.registry, self.intent, self.plan):
                self.assertEqual(self.boot(), self.config)
                self.assertEqual(self.boot(jail=self.pair[1]), self.config)
                for changes in ({"instance": "other"}, {"jail": "othernc"}, {"executor": "f" * 64},
                                {"intent": {**self.intent, "operation": "enroll-other"}}):
                    with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, starts.DENIED):
                        self.boot(**changes)
            self.assertTrue(self.permission.exists())
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                self.boot()
            # Same-intent explicit recovery may reuse the inert binding.
            with starts.start_permission(self.registry, self.intent, self.plan):
                self.assertEqual(self.boot(), self.config)

    def test_real_registry_and_actual_global_exclusive_lock_required(self):
        for registry in (self.registry, self.view):
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                with starts.start_permission(registry, self.intent, self.plan):
                    self.fail("unlocked registry authorized")
        atomic_write(self.registry.root / "operation.lock", "")
        self.registry._locked = True
        with self.assertRaisesRegex(ValueError, starts.DENIED):
            with starts.start_permission(self.registry, self.intent, self.plan):
                self.fail("flag without flock authorized")

    def test_exception_releases_permission_and_nested_holder_is_refused(self):
        with self.registry.locked(recovery=True):
            with self.assertRaisesRegex(RuntimeError, "validation failed"):
                with starts.start_permission(self.registry, self.intent, self.plan):
                    with self.assertRaisesRegex(ValueError, starts.DENIED):
                        with starts.start_permission(self.registry, self.intent, self.plan):
                            self.fail("second holder authorized")
                    self.assertEqual(self.boot(), self.config)
                    raise RuntimeError("validation failed")
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                self.boot()

    def test_only_one_held_lock_or_shared_locks_never_authorize(self):
        with self.registry.locked(recovery=True), starts.start_permission(self.registry, self.intent, self.plan):
            pass
        # Per-operation holder without global lock, then shared rather than
        # exclusive global holder, both fail despite the exact JSON record.
        with self.lock.open("rb") as permission, (self.registry.root / "operation.lock").open("rb") as global_lock:
            fcntl.flock(permission, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                self.boot()
            fcntl.flock(global_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                self.boot()
            fcntl.flock(global_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(permission, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                self.boot()

    def test_process_crash_revokes_even_with_durable_json(self):
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe()
        process = context.Process(target=_crash_with_permission,
                                  args=(self.registry.root, self.intent, self.plan, child))
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(20), "permission holder failed to start")
            self.assertEqual(parent.recv(), "held")
            self.assertEqual(self.boot(), self.config)
            parent.send("crash")
            process.join(20)
            self.assertEqual(process.exitcode, 0)
            self.assertTrue(self.permission.exists())
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                self.boot()
        finally:
            if process.is_alive():
                process.kill()
                process.join()
            parent.close()

    def test_changed_source_plan_config_or_permission_is_refused(self):
        with self.registry.locked(recovery=True), starts.start_permission(self.registry, self.intent, self.plan):
            for path in (self.permission, self.registry.root / self.directory / "enrollment.json",
                         self.registry.root / self.plan["originals"][self.config.instance]["config"]["path"]):
                saved = path.read_bytes()
                value = json.loads(saved)
                value["unknown"] = "DO-NOT-PRINT"
                atomic_json(path, value)
                with self.assertRaisesRegex(ValueError, "^" + starts.DENIED + "$"):
                    self.boot()
                atomic_write(path, saved.decode())
            with patch("installer.maintenance.executor_identity", return_value="f" * 64):
                with self.assertRaisesRegex(ValueError, starts.DENIED):
                    self.boot()
            value = json.loads(self.permission.read_bytes())
            value["schema_version"] = True
            atomic_json(self.permission, value)
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                self.boot()

    def test_changed_cached_plan_and_wrong_enrollment_target_are_refused(self):
        with self.registry.locked(recovery=True):
            altered = copy.deepcopy(self.plan)
            altered["instance"] = "other"
            with self.assertRaisesRegex(ValueError, starts.DENIED):
                with starts.start_permission(self.registry, self.intent, altered):
                    self.fail("altered cached plan authorized")
        self.assertFalse(self.permission.exists())

    def test_unsafe_lock_or_permission_objects_fail_closed(self):
        with self.registry.locked(recovery=True), starts.start_permission(self.registry, self.intent, self.plan):
            pass
        for path in (self.lock, self.permission):
            saved = path.read_bytes()
            for kind in ("symlink", "hardlink", "mode", "fifo"):
                with self.subTest(path=path.name, kind=kind):
                    target = path.with_name(path.name + ".saved")
                    path.rename(target)
                    if kind == "symlink":
                        path.symlink_to(target)
                    elif kind == "hardlink":
                        os.link(target, path)
                    elif kind == "fifo":
                        os.mkfifo(path, 0o600)
                    else:
                        path.write_bytes(saved)
                        path.chmod(0o644)
                    try:
                        with self.registry.locked(recovery=True):
                            with self.assertRaisesRegex(ValueError, starts.DENIED):
                                with starts.start_permission(self.registry, self.intent, self.plan):
                                    self.fail("unsafe permission object authorized")
                    finally:
                        path.unlink()
                        target.rename(path)

    def test_stopped_pair_starts_and_success_leaves_it_running(self):
        with self.registry.locked(recovery=True), self.checked_starts():
            with starts.validation_starts(self.registry, self.deployment, self.intent, self.plan):
                self.assertEqual(set(self.live), set(self.pair))
                self.assertEqual(self.boot(), self.config)
        self.assertEqual([args for args in self.native if args[:2] == ("bastille", "start")],
                         [("bastille", "start", name) for name in self.pair])
        self.assertEqual(set(self.live), set(self.pair))
        with self.assertRaisesRegex(ValueError, starts.DENIED):
            self.boot()

    def test_failed_recheck_stops_only_newly_started_jails(self):
        self.live[self.pair[0]] = 55
        with self.registry.locked(recovery=True), self.checked_starts():
            with self.assertRaisesRegex(ValueError, "recheck failed"):
                with starts.validation_starts(self.registry, self.deployment, self.intent, self.plan):
                    raise ValueError("recheck failed")
        self.assertEqual(self.live, {self.pair[0]: 55})
        self.assertEqual([args for args in self.native if args[:2] == ("bastille", "stop")],
                         [("bastille", "stop", self.pair[1])])
        self.assertEqual(self.store.pending(), self.intent)

    def test_replaced_jid_is_never_stopped_after_validation_failure(self):
        with self.registry.locked(recovery=True), self.checked_starts():
            with self.assertRaises(ValueError):
                with starts.validation_starts(self.registry, self.deployment, self.intent, self.plan):
                    self.live[self.pair[0]] = 99
                    raise ValueError("failure")
        self.assertEqual(self.live, {self.pair[0]: 99})
        self.assertNotIn(("bastille", "stop", self.pair[0]), self.native)

    def test_start_failure_after_jail_creation_cleans_up_exact_pair(self):
        def failing(*args, **kwargs):
            result = self.run_command(*args, **kwargs)
            if args == ("bastille", "start", self.pair[1]):
                raise RuntimeError("start failed after creation")
            return result
        self.runner.run.side_effect = failing
        with self.registry.locked(recovery=True), self.checked_starts():
            with self.assertRaisesRegex(RuntimeError, "start failed"):
                with starts.validation_starts(self.registry, self.deployment, self.intent, self.plan):
                    self.fail("failed native start reached recheck")
        self.assertFalse(self.live)

    def test_live_dying_or_ambiguous_inventory_is_not_treated_as_stopped(self):
        self.live[self.pair[0]] = 42
        self.dying.add(self.pair[0])
        with self.registry.locked(recovery=True), self.checked_starts():
            with self.assertRaises(ValueError):
                with starts.validation_starts(self.registry, self.deployment, self.intent, self.plan):
                    self.fail("dying pair started")
        self.assertFalse(any(args[0] == "bastille" for args in self.native))
        for result in (SimpleNamespace(returncode=1, stdout=""),
                       SimpleNamespace(returncode=0, stdout="ambiguous")):
            with patch.object(self.runner, "run", return_value=result), self.assertRaises(ValueError):
                starts._live_pair(self.deployment)

    def prepare_preflight(self):
        atomic_json(self.state / "deployment.json", {
            "schema_version": 2, "config_sha256": config_digest(self.config),
            "steps": {name: {"state": "complete"} for name in (
                "instance ZFS storage", "private networking and PF", "FreeBSD jail roots",
                "persistent mounts", "Nextcloud publication", "readiness checks", "boot activation")}})
        atomic_write(self.state / "source.sha256", self.executor["source_sha256"] + "\n")
        atomic_write(self.state / "inputs.sha256", hashlib.sha256(json.dumps(self.secrets, sort_keys=True).encode()).hexdigest() + "\n")

    def test_preflight_checks_original_source_inputs_ownership_and_pf_before_start(self):
        self.prepare_preflight()
        with self.registry.locked(recovery=True), starts.start_permission(self.registry, self.intent, self.plan), \
                patch("installer.host.verify_managed_network") as network, \
                patch("installer.lifecycle._checked_jails", return_value=[(name, "owned") for name in self.pair]) as owned:
            self.assertEqual(starts._preflight(self.deployment, self.registry, self.intent, self.plan), {})
            network.assert_called_once_with(self.view, self.runner)
            owned.assert_called_once_with(self.deployment)
            self.assertEqual(len([args for args in self.native if args[0] == "/bin/sh"]), 2)
            self.assertIn(("bastille", "config", self.pair[0], "get", "host.hostname"),
                          [call.args for call in self.runner.output.call_args_list])
        self.assertFalse(any(args[:2] == ("bastille", "start") for args in self.native))

    def test_bad_source_or_inputs_fail_before_native_probes(self):
        self.prepare_preflight()
        for filename in ("source.sha256", "inputs.sha256"):
            with self.subTest(filename=filename):
                path = self.state / filename
                saved = path.read_text()
                atomic_write(path, "f" * 64 + "\n")
                try:
                    with self.registry.locked(recovery=True):
                        with self.assertRaises(ValueError):
                            with starts.validation_starts(self.registry, self.deployment, self.intent, self.plan):
                                self.fail("drift reached native starts")
                    self.runner.run.assert_not_called()
                    self.runner.output.assert_not_called()
                finally:
                    atomic_write(path, saved)

    def test_missing_completed_ownership_checkpoint_is_not_skipped(self):
        self.prepare_preflight()
        journal = json.loads((self.state / "deployment.json").read_bytes())
        del journal["steps"]["FreeBSD jail roots"]
        atomic_json(self.state / "deployment.json", journal)
        with self.registry.locked(recovery=True):
            with self.assertRaises(ValueError):
                with starts.validation_starts(self.registry, self.deployment, self.intent, self.plan):
                    self.fail("missing checkpoint authorized")
        self.runner.run.assert_not_called()
        self.runner.output.assert_not_called()

    def test_ownership_hostname_pf_or_exact_inventory_failure_prevents_all_starts(self):
        self.prepare_preflight()
        def changed_owner(*args, **kwargs):
            if args[:3] == ("zfs", "get", "-H"):
                return "foreign"
            return self.output_command(*args, **kwargs)
        def changed_hostname(*args, **kwargs):
            if args[-1] == "host.hostname":
                return "foreign.example.test"
            return self.output_command(*args, **kwargs)
        for failure in ("owner", "hostname", "pf", "inventory"):
            with self.subTest(failure=failure), self.registry.locked(recovery=True), \
                    patch("installer.host.verify_managed_network") as network, \
                    patch("installer.lifecycle._checked_jails", return_value=[]) as owned:
                self.runner.output.side_effect = {"owner": changed_owner, "hostname": changed_hostname}.get(
                    failure, self.output_command)
                if failure == "pf":
                    network.side_effect = ValueError("PF drift")
                with self.assertRaises(ValueError):
                    with starts.validation_starts(self.registry, self.deployment, self.intent, self.plan):
                        self.fail("unsafe resources reached starts")
                if failure != "inventory":
                    owned.assert_not_called()
                self.assertFalse(any(args[:2] == ("bastille", "start") for args in self.native))


if __name__ == "__main__":
    unittest.main()
