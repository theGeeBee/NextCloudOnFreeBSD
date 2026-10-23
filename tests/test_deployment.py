"""Mocked orchestration: real private state, no FreeBSD commands or host writes."""

from contextlib import ExitStack, contextmanager
from dataclasses import replace
import io
import json
import shutil
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, call, patch

from installer.config import Config, Dataset, datasets
from installer.deploy import Deployment, OWNER, managed_block
from installer.state import Journal, Registry, atomic_json, atomic_write, private_json
from installer.version_runtime import dependency_text, package_text, runtime_versions
from version_fixtures import discovery_metadata, resolved_plan


def configuration(**changes):
    return replace(Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                          acme_email="admin@example.test", external_interface="igb0",
                          ingress_address="192.0.2.10", dns_server="192.0.2.53",
                          management_network="198.51.100.0/24", accept_microsoft_fonts=True), **changes)


def result(stdout="", returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="deployment-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        root = patch.object(Config, "bastille_root", new_callable=PropertyMock,
                            return_value=str(self.directory / "bastille"))
        root.start()
        self.addCleanup(root.stop)
        self.registry = Registry(self.directory / "registry")
        self.registry.initialize()
        self.secrets = {"admin_password": "test-only-password", "db_password": "a" * 64, "jwt_secret": "b" * 64}
        self.config = configuration()
        self.registry.save_new(self.config, self.secrets)
        self.runner = Mock(spec=["run", "output"])
        self.deployment = Deployment(self.config, self.secrets, self.runner, registry=self.registry, progress=Mock())
        self.runner.run.side_effect = self.run_command

    def run_command(self, *args, **kwargs):
        if args[:2] == ("jls", "-j"):
            jid = 11 if args[2] == self.config.nextcloud_jail else 12
            return result(f"{jid} {args[2]} {self.deployment.jail_root(args[2])}\n")
        if args[:2] == ("bastille", "config") and args[-2:] == ("get", "path"):
            return result(str(self.deployment.jail_root(args[2])))
        return result()

    def payload_roots(self):
        self.retain_versions()
        for jail in (self.config.nextcloud_jail, self.config.onlyoffice_jail):
            (self.deployment.jail_root(jail) / "root").mkdir(parents=True)

    def retain_versions(self):
        plan = resolved_plan(self.config)
        atomic_json(self.deployment.state / "versions.json", plan)
        self.deployment._versions = None
        self.assertEqual(self.deployment.versions, plan)
        return plan

    def matching_host_packages(self, plan):
        def identity(*args):
            self.assertEqual(args[:3], ("pkg", "query", "%v|%o"))
            record = plan["packages"]["host"][args[3]]
            return record["version"] + "|" + record["origin"]
        def run(*args, **kwargs):
            if args[:2] == ("pkg", "query"):
                return result(identity(*args))
            return self.run_command(*args, **kwargs)
        self.runner.run.side_effect = run
        self.runner.output.side_effect = identity

    def test_instance_state_lives_below_explicit_registry(self):
        self.assertEqual(self.deployment.state, self.registry.root / "instances/cloud")
        self.assertIs(self.deployment.registry, self.registry)

    def test_empty_plugin_selection_preserves_legacy_state_without_fetches(self):
        with patch("installer.plugins.prepare") as prepare:
            self.deployment.prepare_plugins()
            self.deployment.plugin_command("verify")
        prepare.assert_not_called()
        self.assertFalse((self.deployment.state / "plugins.json").exists())
        self.runner.run.assert_not_called()

    def test_selected_plugins_get_retained_lock_before_download(self):
        from installer.plugins import make_lock
        self.config.onlyoffice_plugins = "highlightcode"
        self.retain_versions()
        expected = make_lock(self.config.onlyoffice_plugins)
        def prepare(lock, cache):
            self.assertEqual(private_json(self.deployment.state / "plugins.json"), expected)
            self.assertEqual(lock, expected)
            self.assertEqual(cache, self.deployment.state / "plugin-artifacts")
        with patch("installer.plugins.prepare", side_effect=prepare) as download, \
                patch("installer.plugins.check_payloads") as payloads:
            self.deployment.prepare_plugins()
            self.deployment.prepare_plugins()
        self.assertEqual(download.call_count, 2)
        self.assertEqual(payloads.call_count, 2)
        self.runner.run.assert_not_called()
        self.config.onlyoffice_plugins = "ocr"
        with patch("installer.plugins.prepare") as download:
            with self.assertRaises(ValueError):
                self.deployment.prepare_plugins()
            download.assert_not_called()

    def test_missing_plugin_lock_cannot_be_guessed_on_resume(self):
        self.config.onlyoffice_plugins = "highlightcode"
        atomic_json(self.deployment.state / "deployment.json", {})
        with patch("installer.plugins.prepare") as download:
            with self.assertRaisesRegex(ValueError, "guessed plugin lock"):
                self.deployment.prepare_plugins()
            download.assert_not_called()

    def test_plugins_refuse_unreviewed_docs_version_before_download(self):
        self.config.onlyoffice_plugins = "highlightcode"
        plan = {"packages": {"onlyoffice": {"onlyoffice-documentserver": {"version": "9.5.0"}}}}
        with patch.object(Deployment, "versions", new_callable=PropertyMock, return_value=plan), \
                patch("installer.plugins.prepare") as download:
            with self.assertRaisesRegex(ValueError, "not reviewed"):
                self.deployment.prepare_plugins()
            download.assert_not_called()

    def test_plugin_worker_is_bound_to_host_lock_and_verify_never_installs(self):
        from installer.plugins import make_lock
        self.config.onlyoffice_plugins = "highlightcode"
        self.retain_versions()
        lock = make_lock(self.config.onlyoffice_plugins)
        atomic_json(self.deployment.state / "plugins.json", lock)
        payload = self.deployment.jail_root(self.config.onlyoffice_jail) / "root/cloud-installer"
        payload.mkdir(mode=0o700, parents=True)
        atomic_json(payload / "plugins.json", lock)
        self.deployment.plugin_command("verify")
        commands = [item.args for item in self.runner.run.call_args_list if item.args[0] == "jexec"]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][:5], ("jexec", "12", "python3", "/root/cloud-installer/installer/plugins.py", "verify"))
        self.assertNotIn("install", commands[0])
        self.assertIn("highlightcode", self.deployment.manifest["onlyoffice_plugins"])
        atomic_json(payload / "plugins.json", make_lock("ocr"))
        self.runner.reset_mock()
        with self.assertRaises(ValueError):
            self.deployment.plugin_command("verify")
        self.runner.run.assert_not_called()

    def test_selected_plugin_original_source_gate_precedes_fetch(self):
        from installer.plugins import make_lock
        self.config.onlyoffice_plugins = "highlightcode"
        lock = make_lock(self.config.onlyoffice_plugins)
        atomic_json(self.deployment.state / "plugins.json", lock)
        atomic_write(self.deployment.state / "source.sha256", "unrelated-source\n")
        with patch("installer.plugins.prepare") as fetch, \
                patch.object(self.deployment, "require_original_artifact", side_effect=ValueError("original artifact")):
            with self.assertRaisesRegex(ValueError, "original artifact"):
                self.deployment.prepare_plugins()
        fetch.assert_not_called()
        self.assertEqual(private_json(self.deployment.state / "plugins.json"), lock)

    def test_plugin_download_failure_prevents_any_provisioning(self):
        self.config.onlyoffice_plugins = "highlightcode"
        self.retain_versions()
        with patch("installer.plugins.prepare", side_effect=ValueError("locked input unavailable")), \
                patch.object(self.registry, "save_host") as host, \
                patch.object(self.deployment, "create_shared_storage") as storage:
            with self.assertRaisesRegex(ValueError, "locked input unavailable"):
                self.deployment.apply()
        host.assert_not_called()
        storage.assert_not_called()
        self.assertFalse((self.deployment.state / "deployment.json").exists())
        self.runner.run.assert_not_called()

    def test_selected_plugin_phase_order_failure_resume_and_completed_skip(self):
        self.config.onlyoffice_plugins = "highlightcode"
        self.retain_versions()
        phases = ("create_shared_storage", "install_manager", "create_storage", "configure_network", "configure_devfs",
                  "bootstrap_jails", "attach_storage", "stage_payloads", "install_nextcloud", "nextcloud_phase",
                  "restart_jails", "verify", "enable_boot", "validate_resume", "prepare_plugins")
        events = []
        def install(mode):
            events.append("plugins:" + mode)
            raise RuntimeError("plugin failure")
        with ExitStack() as stack:
            for name in phases:
                stack.enter_context(patch.object(self.deployment, name))
            stack.enter_context(patch("installer.operations.configure_ssh"))
            stack.enter_context(patch("installer.initialization.checkpoint_initialization"))
            office = stack.enter_context(patch.object(self.deployment, "install_onlyoffice", side_effect=lambda: events.append("office")))
            integration = stack.enter_context(patch.object(self.deployment, "integrate", side_effect=lambda: events.append("integration")))
            plugins = stack.enter_context(patch.object(self.deployment, "plugin_command", side_effect=install))
            with self.assertRaisesRegex(RuntimeError, "plugin failure"):
                self.deployment.apply()
            self.assertEqual(events, ["office", "plugins:install"])
            integration.assert_not_called()
            self.assertEqual(private_json(self.deployment.state / "deployment.json")["steps"]["selected ONLYOFFICE plugins"]["state"], "failed")
            plugins.side_effect = lambda mode: events.append("plugins:" + mode)
            self.deployment.apply()
            self.assertEqual(events, ["office", "plugins:install", "plugins:install", "integration"])
            office.assert_called_once()
            self.deployment.apply()
            self.assertEqual(plugins.call_count, 2)
            integration.assert_called_once()

    def test_plugin_staging_copies_only_selected_artifacts_into_office(self):
        self.config.onlyoffice_plugins = "highlightcode"
        self.payload_roots()
        lock = {"plugins": {"highlightcode": {"artifacts": [{"path": "plugin.zip"}]}}}
        cache = self.deployment.state / "plugin-artifacts"
        (cache / "highlightcode").mkdir(parents=True, mode=0o700)
        (cache / "highlightcode/plugin.zip").write_bytes(b"selected public bytes")
        (cache / "not-selected.zip").write_bytes(b"must not stage")
        with patch.object(Deployment, "plugin_lock", new_callable=PropertyMock, return_value=lock), \
                patch("installer.plugins.check_cache") as check:
            self.deployment.stage_payloads()
        nc = self.deployment.jail_root(self.config.nextcloud_jail) / "root/cloud-installer"
        office = self.deployment.jail_root(self.config.onlyoffice_jail) / "root/cloud-installer"
        self.assertFalse((nc / "plugins.json").exists())
        self.assertFalse((nc / "plugin-artifacts").exists())
        self.assertEqual(private_json(office / "plugins.json"), lock)
        self.assertEqual((office / "plugin-artifacts/highlightcode/plugin.zip").read_bytes(), b"selected public bytes")
        self.assertEqual((office / "plugin-artifacts/highlightcode/plugin.zip").stat().st_mode & 0o777, 0o600)
        self.assertFalse((office / "plugin-artifacts/not-selected.zip").exists())
        self.assertFalse((office / "secrets.json").exists())
        self.assertEqual(check.call_args_list, [call(lock, cache), call(lock, office / "plugin-artifacts")])

    def test_corrupt_plugin_cache_and_symlink_staging_fail_closed(self):
        lock = {"plugins": {"highlightcode": {"artifacts": [{"path": "plugin.zip"}]}}}
        target = self.directory / "payload"
        target.mkdir(mode=0o700)
        with patch.object(Deployment, "plugin_lock", new_callable=PropertyMock, return_value=lock), \
                patch("installer.plugins.check_cache", side_effect=ValueError("cache mismatch")):
            with self.assertRaisesRegex(ValueError, "cache mismatch"):
                self.deployment.stage_plugins(target)
        self.assertEqual(list(target.iterdir()), [])
        foreign = self.directory / "foreign"
        foreign.mkdir(mode=0o700)
        (target / "plugin-artifacts").symlink_to(foreign)
        with patch.object(Deployment, "plugin_lock", new_callable=PropertyMock, return_value=lock), \
                patch("installer.plugins.check_cache"):
            with self.assertRaises(ValueError):
                self.deployment.stage_plugins(target)
        self.assertEqual(list(foreign.iterdir()), [])

    def test_prepare_versions_retains_private_validated_plan_only_after_package_probe(self):
        metadata = discovery_metadata(self.config)
        expected = resolved_plan(self.config)
        self.matching_host_packages(expected)
        path = self.deployment.state / "versions.json"
        def probe(config, plan, runner, **kwargs):
            self.assertFalse(path.exists())
            self.assertEqual((config, plan, runner), (self.config, expected, self.runner))
        with patch("installer.discovery.discover", return_value=metadata) as discover, \
                patch("installer.discovery.probe_packages", side_effect=probe) as packages:
            self.assertEqual(self.deployment.prepare_versions(), expected)
        discover.assert_called_once_with(self.config, self.runner, directory=self.registry.root)
        packages.assert_called_once_with(self.config, expected, self.runner, directory=self.registry.root)
        self.assertEqual(private_json(path), expected)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.runner.run.call_args_list, [call("pkg", "query", "%v|%o", name, check=False)
                         for name in expected["packages"]["host"]])
        self.runner.output.assert_not_called()

    def test_resume_revalidates_retained_plan_without_discovering_newer_replacements(self):
        plan = self.retain_versions()
        self.matching_host_packages(plan)
        self.deployment._versions = None
        before = (self.deployment.state / "versions.json").read_bytes()
        with patch("installer.discovery.discover") as discover, \
                patch("installer.discovery.probe_packages") as probe:
            self.assertEqual(self.deployment.prepare_versions(), plan)
        discover.assert_not_called()
        probe.assert_called_once_with(self.config, plan, self.runner, directory=self.registry.root)
        self.assertEqual((self.deployment.state / "versions.json").read_bytes(), before)

    def test_host_dependency_drift_blocks_resolution_before_lock_or_deployment_state(self):
        metadata = discovery_metadata(self.config)
        for name in ("bastille", "fixture-library"):
            with self.subTest(package=name), patch("installer.discovery.discover", return_value=metadata), \
                    patch("installer.discovery.probe_packages"):
                self.runner.run.side_effect = lambda *args, **kwargs: result(
                    ("0.1" if args[-1] == name else metadata["packages"][args[-1]]["version"])
                    + "|" + metadata["packages"][args[-1]]["origin"])
                with self.assertRaisesRegex(ValueError, "Installed host package " + name):
                    self.deployment.prepare_versions()
                self.assertFalse((self.deployment.state / "versions.json").exists())
                self.assertFalse((self.deployment.state / "deployment.json").exists())
        self.assertTrue(all(item.args[:3] == ("pkg", "query", "%v|%o") for item in self.runner.run.call_args_list))

    def test_failed_resolution_or_probe_cannot_start_apply_or_publish_a_lock(self):
        metadata = discovery_metadata(self.config)
        for failing in ("discovery", "probe"):
            with self.subTest(failing=failing), \
                    patch("installer.discovery.discover", return_value=metadata,
                          side_effect=ValueError("metadata unavailable") if failing == "discovery" else None), \
                    patch("installer.discovery.probe_packages",
                          side_effect=ValueError("locked package unavailable") if failing == "probe" else None), \
                    patch.object(self.deployment, "create_shared_storage") as storage, \
                    patch.object(self.registry, "save_host") as host:
                with self.assertRaisesRegex(ValueError, "unavailable"):
                    self.deployment.apply()
                storage.assert_not_called()
                host.assert_not_called()
                self.assertFalse((self.deployment.state / "versions.json").exists())
                self.assertFalse((self.deployment.state / "deployment.json").exists())
                self.assertEqual(private_json(self.deployment.state / "status.json")["state"], "configured")
        self.runner.run.assert_not_called()
        self.runner.output.assert_not_called()

    def test_existing_deployment_without_a_lock_requires_original_artifact(self):
        for filename in ("deployment.json", "source.sha256"):
            path = self.deployment.state / filename
            atomic_write(path, "retained historical state\n")
            with self.subTest(filename=filename), patch("installer.discovery.discover") as discover, \
                    patch("installer.discovery.probe_packages") as probe, \
                    self.assertRaisesRegex(ValueError, "original artifact"):
                self.deployment.prepare_versions()
            discover.assert_not_called()
            probe.assert_not_called()
            path.unlink()
        self.assertFalse((self.deployment.state / "versions.json").exists())

    def test_versions_reject_missing_untrusted_or_changed_retained_plan(self):
        with self.assertRaisesRegex(ValueError, "No retained version lock"):
            _ = self.deployment.versions
        path = self.deployment.state / "versions.json"
        plan = resolved_plan(self.config)
        for fault in ("permissions", "symlink", "policy", "dependency"):
            with self.subTest(fault=fault):
                atomic_json(path, plan)
                if fault == "permissions":
                    path.chmod(0o644)
                elif fault == "symlink":
                    saved = path.with_name("untrusted.json")
                    path.rename(saved)
                    path.symlink_to(saved)
                else:
                    changed = json.loads(json.dumps(plan))
                    if fault == "policy":
                        changed["policy_sha256"] = "0" * 64
                    else:
                        del changed["packages"]["nextcloud"]["fixture-library"]
                    atomic_json(path, changed)
                with self.assertRaises(ValueError):
                    _ = self.deployment.versions
                path.unlink()
        self.runner.run.assert_not_called()
        self.runner.output.assert_not_called()

    def manager_runner(self, *, installed=None, remote=None, final=None, remote_dependencies=None):
        self.deployment._versions = resolved_plan(self.config)
        packages = self.deployment.versions["packages"]["host"]
        expected = {name: record["version"] + "|" + record["origin"] for name, record in packages.items()}
        installed = {} if installed is None else {**expected, **installed}
        remote = {name: name + "|" + (identity + "|" + packages[name]["checksum"] if len(identity.split("|")) == 2 else identity)
                  for name, identity in {**expected, **(remote or {})}.items()}
        final = {**expected, **(final or {})}
        edges = {name: "".join(f"{key}|{value['version']}|{value['origin']}\n"
                              for key, value in record["dependencies"].items()) for name, record in packages.items()}
        edges.update(remote_dependencies or {})
        def run(*args, **kwargs):
            if args[:3] == ("pkg", "query", "%v|%o"):
                identity = installed.get(args[3])
                return result(identity or "", returncode=1 if identity is None else 0)
            if "rquery" in args:
                self.assertIn("-U", args)
                return result(remote[args[-1]] if "%n|%v|%o|%u%d%{%|%}" in args else edges[args[-1]])
            return result()
        self.runner.run.side_effect = run
        self.runner.output.side_effect = lambda *args: (final[args[-1]] if "%v|%o" in args
                                                       else "bastille-" + packages["bastille"]["version"])
        return packages

    def test_manager_installs_exact_pin_after_dry_run_and_checks_final_identity(self):
        packages = self.manager_runner()
        self.deployment.install_manager()
        prefix = ("/usr/bin/env", "-i", "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C",
                  "pkg", "-C", "/dev/null", "-o", f"REPOS_DIR={self.registry.root / 'repos'}")
        calls = [item.args for item in self.runner.run.call_args_list]
        locked = [name + "-" + record["version"] for name, record in sorted(packages.items())]
        dry_run = (*prefix, "install", "-n", "-y", "-U", "-r", "FreeBSD-ports", *locked)
        install = (*prefix, "install", "-y", "-U", "-r", "FreeBSD-ports", *locked)
        self.assertLess(calls.index(dry_run), calls.index(install))
        self.assertEqual(self.deployment.manifest["bastille_package"], "bastille-1.4.4_1")
        for name in packages:
            self.runner.output.assert_any_call("pkg", "query", "%v|%o", name)
            self.assertIn((*prefix, "rquery", "-U", "-r", "FreeBSD-ports", "%n|%v|%o|%u%d%{%|%}", name), calls)
            self.assertIn((*prefix, "rquery", "-U", "-r", "FreeBSD-ports", "%dn|%dv|%do", name), calls)
        self.assertFalse(any("upgrade" in args for args in calls))

    def test_manager_refuses_repository_drift_before_install(self):
        for remote, dependencies in (({"bastille": "1.4.4|sysutils/bastille"}, {}),
                                     ({"bastille": "1.4.4_1|sysutils/bastille|2$changed"}, {}),
                                     ({"bastille": "1.4.4_2|sysutils/bastille"}, {}),
                                     ({"fixture-library": "1.2.4|devel/fixture-library"}, {}),
                                     ({"fixture-library": "1.2.3|devel/foreign"}, {}),
                                     ({}, {"bastille": ""}),
                                     ({}, {"bastille": "fixture-library|9.9.9|devel/fixture-library\n"})):
            with self.subTest(remote=remote, dependencies=dependencies):
                self.runner.reset_mock()
                self.manager_runner(remote=remote, remote_dependencies=dependencies)
                with self.assertRaisesRegex(ValueError, "repository version/dependencies differ"):
                    self.deployment.install_manager()
                self.assertFalse(any("install" in item.args or item.args[0] == "sysrc"
                                     for item in self.runner.run.call_args_list))

    def test_manager_refuses_implicit_upgrade_or_downgrade_of_installed_package(self):
        for installed in ({"bastille": "1.4.4|sysutils/bastille"}, {"bastille": "1.4.4_2|sysutils/bastille"},
                          {"bastille": "1.5.0|sysutils/bastille"},
                          {"fixture-library": "1.2.2|devel/fixture-library"},
                          {"fixture-library": "1.2.4|devel/fixture-library"},
                          {"fixture-library": "1.2.3|devel/foreign"}):
            with self.subTest(installed=installed):
                self.runner.reset_mock()
                self.manager_runner(installed=installed)
                with self.assertRaisesRegex(ValueError, "implicit upgrade/downgrade"):
                    self.deployment.install_manager()
                self.assertTrue(all(item.args[:3] == ("pkg", "query", "%v|%o")
                                    for item in self.runner.run.call_args_list))
                self.assertIn(self.runner.run.call_args.args[-1], installed)
                self.runner.output.assert_not_called()
        self.runner.reset_mock()
        self.manager_runner(installed={})
        self.deployment.install_manager()
        self.assertTrue(all(item.args[:2] == ("pkg", "query") or item.args[0] == "sysrc"
                            for item in self.runner.run.call_args_list))

    def test_installed_manager_does_not_hide_a_missing_locked_host_dependency(self):
        packages = self.manager_runner(installed={"fixture-library": None})
        self.deployment.install_manager()
        installs = [item.args for item in self.runner.run.call_args_list if "install" in item.args]
        self.assertEqual(len(installs), 2)
        for args in installs:
            self.assertTrue(all(name + "-" + record["version"] in args for name, record in packages.items()))

    def test_manager_post_install_mismatch_prevents_host_configuration(self):
        for final in ({"bastille": "1.4.4_2|sysutils/bastille"},
                      {"fixture-library": "1.2.4|devel/fixture-library"},
                      {"fixture-library": "1.2.3|devel/foreign"}):
            with self.subTest(final=final):
                self.runner.reset_mock()
                self.manager_runner(final=final)
                with self.assertRaisesRegex(RuntimeError, "does not match the resolved version/origin"):
                    self.deployment.install_manager()
                self.assertFalse(any(item.args[0] == "sysrc" for item in self.runner.run.call_args_list))
                self.assertNotIn("bastille_package", self.deployment.manifest)

    def test_provisioners_use_pinned_jexec_and_phase_specific_stdin(self):
        self.deployment.install_nextcloud()
        self.deployment.nextcloud_phase("database", ("db_password",))
        self.deployment.nextcloud_phase("install", ("admin_password", "db_password"))
        self.deployment.nextcloud_phase("publish")
        self.deployment.install_onlyoffice()
        commands = [item for item in self.runner.run.call_args_list if item.args[0] == "jexec"]
        nc = ("jexec", "11", "/bin/sh", "/root/cloud-installer/resources/jails/nextcloud.sh")
        self.assertEqual([item.args for item in commands], [
            (*nc, "prepare"), (*nc, "database"), (*nc, "install"), (*nc, "publish"),
            ("jexec", "12", "/bin/sh", "/root/cloud-installer/resources/jails/onlyoffice.sh")])
        self.assertNotIn("input", commands[0].kwargs)
        self.assertNotIn("input", commands[3].kwargs)
        for index, keys in ((1, ("db_password",)), (2, ("admin_password", "db_password")), (4, ("jwt_secret",))):
            self.assertEqual(json.loads(commands[index].kwargs["input"]), {key: self.secrets[key] for key in keys})
        argv = repr([item.args for item in self.runner.run.call_args_list])
        for secret in self.secrets.values():
            self.assertNotIn(secret, argv)
        self.assertFalse(any(item.args[:2] == ("bastille", "cmd") for item in self.runner.run.call_args_list))
        self.assertEqual(sum(item.args[0] == "jls" for item in self.runner.run.call_args_list), 10)

    def test_jexec_preserves_input_and_command_options(self):
        payload = '{"value":"spaces \\n and unicode é"}'
        self.deployment.jail("cloudnc", "private-helper", input=payload, capture=False, timeout=23, hide_output=True)
        self.assertEqual(self.runner.run.call_args_list[1],
                         call("jexec", "11", "private-helper", input=payload, capture=False, timeout=23, hide_output=True))

    def test_connector_is_streamed_and_only_public_apache_file_is_written(self):
        self.payload_roots()
        payload = self.deployment.jail_root("cloudnc") / "root/cloud-installer"
        payload.mkdir()
        with patch('installer.operations._database_guard'):
            self.deployment.integrate()
        commands = [item for item in self.runner.run.call_args_list if item.args[0] == "jexec"]
        self.assertEqual(commands[0].args[1:4], ("12", "python3", "-c"))
        self.assertEqual(commands[0].args[-1], "http://10.77.0.6:8081/healthcheck")
        command = commands[1]
        settings = json.loads(command.kwargs["input"])["apps"]["onlyoffice"]
        self.assertEqual(settings["DocumentServerInternalUrl"], "http://10.77.0.6:8081/")
        self.assertEqual(settings["StorageUrl"], "https://cloud.example.test/")
        self.assertEqual(settings["jwt_secret"], self.secrets["jwt_secret"])
        self.assertEqual(command.args[-1], "finish")
        self.assertEqual([path.name for path in payload.iterdir()], ["apache-onlyoffice.conf"])
        text = (payload / "apache-onlyoffice.conf").read_text()
        self.assertIn("http://10.77.0.6:8081/", text)
        for secret in self.secrets.values():
            self.assertNotIn(secret, text + repr(command.args))

    def test_unready_office_prevents_connector_import_on_resume(self):
        with patch.object(self.deployment, "wait_for_office", side_effect=RuntimeError("not ready")) as ready, \
                patch.object(self.deployment, "jail") as jail, \
                patch('installer.operations._database_guard'):
            with self.assertRaisesRegex(RuntimeError, "not ready"):
                self.deployment.integrate()
            ready.assert_called_once_with()
            jail.assert_not_called()

    def test_public_runtime_payloads_have_no_credentials_or_host_administration(self):
        self.payload_roots()
        with patch("installer.deploy.shutil.copytree") as copy:
            self.deployment.stage_payloads()
        runtimes = {}
        for jail in (self.config.nextcloud_jail, self.config.onlyoffice_jail):
            payload = self.deployment.jail_root(jail) / "root/cloud-installer"
            runtime = payload / "runtime.json"
            runtimes[jail] = private_json(runtime)
            self.assertEqual(payload.stat().st_mode & 0o777, 0o700)
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o600)
            for key, secret in self.secrets.items():
                self.assertNotIn(key, runtimes[jail])
                self.assertNotIn(secret, runtime.read_text())
            for key in ("management_network", "certificate_file", "private_key_file", "ssh_key_file", "dataset_root"):
                self.assertNotIn(key, runtimes[jail])
        self.assertEqual(set(runtimes["cloudoo"]), {"public_hostname", "public_url", "storage_url",
                          "nextcloud_ip", "onlyoffice_ip", "repository", "tls_mode", "font_profile", "additional_fonts",
                          "accept_microsoft_fonts", "versions"})
        for jail, group in (("cloudnc", "nextcloud"), ("cloudoo", "onlyoffice")):
            payload = self.deployment.jail_root(jail) / "root/cloud-installer"
            packages = package_text(self.deployment.versions, group)
            dependencies = dependency_text(self.deployment.versions, group)
            self.assertEqual((payload / "packages.lock").read_text(), packages)
            self.assertEqual((payload / "packages.dependencies").read_text(), dependencies)
            self.assertEqual(runtimes[jail]["versions"], runtime_versions(self.deployment.versions, packages, dependencies))
            for name in ("packages.lock", "packages.dependencies"):
                self.assertEqual((payload / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual([item.args[0].name for item in copy.call_args_list], ["installer", "resources"] * 2)
        self.assertEqual(private_json(self.deployment.state / "secrets.json"), self.secrets)

    def test_nextcloud_app_selection_is_public_and_staged_only_to_nextcloud(self):
        self.config.nextcloud_apps = "mail,notes,spreed"
        self.payload_roots()
        with patch("installer.deploy.shutil.copytree"):
            self.deployment.stage_payloads()
        nc = private_json(self.deployment.jail_root("cloudnc") / "root/cloud-installer/runtime.json")
        office = private_json(self.deployment.jail_root("cloudoo") / "root/cloud-installer/runtime.json")
        self.assertEqual(nc["nextcloud_apps"], "mail,notes,spreed")
        self.assertNotIn("nextcloud_apps", office)
        for secret in self.secrets.values():
            self.assertNotIn(secret, json.dumps(nc))

    def test_saved_initial_resource_choices_reach_runtime_without_retuning(self):
        self.config = configuration(php_memory_mb=768, php_budget_mb=3072, upload_max_mb=2048,
                                    db_buffer_mb=1024, redis_memory_mb=256, font_profile="standard")
        registry = Registry(self.directory / "initial-choices")
        registry.initialize()
        registry.save_new(self.config, self.secrets)
        saved = registry.load(self.config.instance)
        self.deployment = Deployment(saved, self.secrets, self.runner, registry=registry, progress=Mock())
        self.payload_roots()
        with patch("installer.deploy.shutil.copytree"):
            self.deployment.stage_payloads()
        runtime = private_json(self.deployment.jail_root("cloudnc") / "root/cloud-installer/runtime.json")
        for key, expected in (("php_memory_mb", 768), ("php_children", 4), ("upload_max_mb", 2048),
                              ("db_buffer_mb", 1024), ("redis_memory_mb", 256)):
            self.assertEqual(runtime[key], expected)
        office = private_json(self.deployment.jail_root("cloudoo") / "root/cloud-installer/runtime.json")
        self.assertEqual(office["font_profile"], "standard")
        self.assertEqual(registry.load(self.config.instance).to_json(), saved.to_json())

    @unittest.skipUnless(shutil.which("php"), "PHP CLI required for the runtime schema contract")
    def test_staged_public_runtimes_are_accepted_by_both_worker_validators(self):
        from installer.office import load_runtime
        self.payload_roots()
        with patch("installer.deploy.shutil.copytree"):
            self.deployment.stage_payloads()
        nc = self.deployment.jail_root("cloudnc") / "root/cloud-installer/runtime.json"
        helper = Path(__file__).resolve().parents[1] / "resources/jails/nextcloud-bootstrap.php"
        command = ["php", "-r", 'define("CLOUD_NEXTCLOUD_LIBRARY", true); require $argv[1]; cloudValidate(json_decode(stream_get_contents(STDIN), true));', str(helper)]
        result = subprocess.run(command, input=nc.read_text(), text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        oo = load_runtime(self.deployment.jail_root("cloudoo") / "root/cloud-installer/runtime.json")
        self.assertTrue(oo["accept_microsoft_fonts"])

    def test_supplied_tls_key_goes_only_to_nextcloud(self):
        self.payload_roots()
        for name, content in (("chain.pem", "PUBLIC CHAIN"), ("key.pem", "PRIVATE TLS KEY"), ("ca.pem", "PUBLIC CA")):
            atomic_write(self.directory / name, content)
        self.config.tls_mode = "provided"
        self.config.certificate_file = str(self.directory / "chain.pem")
        self.config.private_key_file = str(self.directory / "key.pem")
        self.config.ca_file = str(self.directory / "ca.pem")
        self.retain_versions()
        with patch("installer.deploy.shutil.copytree"):
            self.deployment.stage_payloads()
        nc = self.deployment.jail_root("cloudnc") / "root/cloud-installer/tls"
        oo = self.deployment.jail_root("cloudoo") / "root/cloud-installer/tls"
        self.assertEqual((nc / "privkey.pem").read_text(), "PRIVATE TLS KEY")
        self.assertEqual((nc / "privkey.pem").stat().st_mode & 0o777, 0o600)
        self.assertEqual({path.name for path in oo.iterdir()}, {"ca.pem"})

    def test_payload_symlink_cannot_redirect_writes(self):
        self.payload_roots()
        outside = self.directory / "foreign"
        outside.mkdir()
        (self.deployment.jail_root("cloudnc") / "root/cloud-installer").symlink_to(outside)
        with patch("installer.deploy.shutil.copytree") as copy, self.assertRaisesRegex(ValueError, "symlink"):
            self.deployment.stage_payloads()
        copy.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def temporary_storage(self):
        self.deployment.storage = [replace(item, mountpoint=str(self.directory / "storage" / item.name.rsplit("/", 1)[-1]))
                                   for item in self.deployment.storage]
        return self.deployment.storage

    def test_storage_creation_has_explicit_ownership_properties_and_actual_mount_check(self):
        storage = self.temporary_storage()
        self.runner.run.side_effect = lambda *args, **kwargs: result(returncode=1 if args[:2] == ("zfs", "list") else 0)
        self.runner.output.side_effect = lambda *args: (next(item.name for item in storage if item.mountpoint == args[-1])
                                                      + " 1 0 1 0% " + args[-1] if args[0] == "df" else "yes")
        self.deployment.create_storage()
        commands = [item.args for item in self.runner.run.call_args_list]
        creates = [args for args in commands if args[:2] == ("zfs", "create")]
        self.assertEqual(len(creates), len(storage))
        self.assertIn(("chmod", "700", storage[0].mountpoint), commands)
        for command, dataset in zip(creates, storage):
            self.assertIn(f"{OWNER}=cloud", command)
            self.assertIn("org.cloud-installer:owner=cloud-installer", command)
            for name, value in dataset.properties.items():
                self.assertIn(f"{name}={value}", command)
            self.assertNotIn("-p", command)
            self.assertEqual(command[-1], dataset.name)
            self.assertIn(call("df", "-P", dataset.mountpoint), self.runner.output.call_args_list)
        self.assertFalse(any("destroy" in args for args in commands))

    def test_optional_storage_uses_existing_creation_path_without_quota_options(self):
        c = replace(self.config, storage_policy="optional", data_quota_gib=0,
                    database_quota_gib=0, temporary_quota_gib=0,
                    office_quota_gib=0, logs_quota_gib=0, system_quota_gib=0)
        self.deployment.storage = datasets(c)
        storage = self.temporary_storage()
        self.runner.run.side_effect = lambda *args, **kwargs: result(returncode=1 if args[:2] == ("zfs", "list") else 0)
        self.runner.output.side_effect = lambda *args: (next(item.name for item in storage if item.mountpoint == args[-1])
                                                      + " 1 0 1 0% " + args[-1] if args[0] == "df" else "yes")
        self.deployment.create_storage()
        creates = [item.args for item in self.runner.run.call_args_list if item.args[:2] == ("zfs", "create")]
        self.assertEqual(len(creates), len(storage))
        for command in creates:
            self.assertFalse(any(arg.startswith(("quota=", "refquota=")) for arg in command))
            self.assertIn("org.cloud-installer:owner=cloud-installer", command)
        self.assertFalse(any(item.args[:2] in (("zfs", "set"), ("zfs", "destroy"))
                             for item in self.runner.run.call_args_list))

    def test_shared_parents_are_separate_and_owned_by_shared_registry(self):
        with patch.object(self.deployment, "ensure_dataset") as ensure:
            self.deployment.create_shared_storage()
        self.assertEqual([item.args[0].name for item in ensure.call_args_list], [
            "zroot/cloud-installer", "zroot/cloud-installer/instances", self.config.bastille_dataset])
        self.assertTrue(all(item.args[1] == "shared" for item in ensure.call_args_list))
        self.assertFalse(any(item.name == self.config.bastille_dataset for item in self.deployment.storage))

    def test_existing_dataset_cannot_be_adopted_or_cover_wrong_filesystem(self):
        dataset = Dataset("zroot/cloud-installer/instances/cloud/nc-data", str(self.directory / "data"))
        for owner, mountpoint, filesystem, error in (
                ("foreign", dataset.mountpoint, dataset.name, ValueError),
                ("cloud", str(self.directory / "elsewhere"), dataset.name, ValueError),
                ("cloud", dataset.mountpoint, "foreign/pool", RuntimeError)):
            with self.subTest(owner=owner, mountpoint=mountpoint, filesystem=filesystem):
                self.runner.reset_mock()
                self.runner.output.side_effect = lambda *args: (filesystem + " 1 0 1 0% /data" if args[0] == "df" else
                    {OWNER: owner, "mountpoint": mountpoint, "mounted": "yes"}[args[-2]])
                with self.assertRaises(error):
                    self.deployment.ensure_dataset(dataset, "cloud")
                self.assertFalse(any(item.args[:2] in (("zfs", "create"), ("zfs", "destroy"))
                                     for item in self.runner.run.call_args_list))

    def test_missing_dataset_cannot_cover_existing_files_or_symlinks(self):
        occupied = self.directory / "occupied"
        occupied.mkdir()
        (occupied / "user-data").write_text("retain")
        link = self.directory / "link"
        link.symlink_to(occupied)
        self.runner.run.side_effect = lambda *args, **kwargs: result(returncode=1)
        for path in (occupied, link):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "cover existing storage"):
                self.deployment.ensure_dataset(Dataset("pool/child", str(path)), "cloud")
        self.assertTrue(all(item.args[:2] == ("zfs", "list") for item in self.runner.run.call_args_list))
        self.assertEqual((occupied / "user-data").read_text(), "retain")

    def bootstrap_runner(self, *, complete=True, stop_succeeds=True):
        running = set()
        def run(*args, **kwargs):
            if args[:2] == ("bastille", "create"):
                jail = args[-4]
                root = self.deployment.jail_root(jail)
                root.mkdir(parents=True)
                if complete:
                    (root / "bin").mkdir()
                    (root / "bin/sh").write_text("mock shell")
                    (root.parent / "jail.conf").write_text("mock jail")
                running.add(jail)
            elif args[:2] == ("jls", "-j"):
                return self.run_command(*args, **kwargs) if args[2] in running else result(returncode=1)
            elif args[:2] == ("bastille", "stop") and stop_succeeds:
                running.discard(args[2])
            return result()
        self.runner.run.side_effect = run
        self.runner.output.side_effect = lambda *args: str(self.deployment.jail_root(args[2]))

    def test_bootstrap_reserves_thick_jails_stops_them_and_sets_dns_hostnames(self):
        self.config.nextcloud_hostname, self.config.onlyoffice_hostname = "nc.example.test", "office.example.test"
        self.bootstrap_runner()
        self.deployment.bootstrap_jails()
        commands = [item.args for item in self.runner.run.call_args_list]
        creates = [args for args in commands if args[:2] == ("bastille", "create")]
        self.assertEqual(len(creates), 2)
        for jail, hostname in (("cloudnc", "nc.example.test"), ("cloudoo", "office.example.test")):
            create = next(args for args in creates if jail in args)
            for flag in ("-T", "-B", "--no-boot"):
                self.assertIn(flag, create)
            self.assertNotIn("-V", create)
            self.assertIn(("bastille", "stop", jail), commands)
            self.assertIn(("bastille", "config", jail, "set", "host.hostname", hostname), commands)
            self.assertIn(("zfs", "set", f"{OWNER}=cloud", f"{self.config.bastille_dataset}/jails/{jail}"), commands)
            self.assertEqual(private_json(self.deployment.state / (jail + ".creating.json")),
                             {"name": jail, "root": str(self.deployment.jail_root(jail)), "release": self.config.release})
        self.assertFalse(any(args[-2:] == ("boot", "on") for args in commands))

    def test_bootstrap_refuses_unreserved_existing_jail_and_incomplete_creation(self):
        (self.deployment.jail_root("cloudnc").parent).mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "reservation"):
            self.deployment.bootstrap_jails()
        self.assertFalse(any(item.args[:2] == ("bastille", "create") for item in self.runner.run.call_args_list))
        atomic_json(self.deployment.state / "cloudnc.creating.json",
                    {"name": "cloudnc", "root": str(self.deployment.jail_root("cloudnc")), "release": self.config.release})
        with self.assertRaisesRegex(RuntimeError, "Incomplete"):
            self.deployment.bootstrap_jails()

    def test_optional_uncapped_jails_keep_bootstrap_order_without_quota_mutations(self):
        self.config.storage_policy = "optional"
        self.config.system_quota_gib = 0
        self.bootstrap_runner()
        self.deployment.bootstrap_jails()
        commands = [item.args for item in self.runner.run.call_args_list]
        self.assertEqual(sum(args[:2] == ("bastille", "create") for args in commands), 2)
        self.assertFalse(any(arg.startswith(("quota=", "refquota=")) for args in commands for arg in args))
        for jail in (self.config.nextcloud_jail, self.config.onlyoffice_jail):
            stop = commands.index(("bastille", "stop", jail))
            owner = commands.index(("zfs", "set", f"{OWNER}=cloud", f"{self.config.bastille_dataset}/jails/{jail}"))
            hostname = commands.index(("bastille", "config", jail, "set", "host.hostname",
                                        self.config.nextcloud_host if jail == self.config.nextcloud_jail else self.config.onlyoffice_host))
            self.assertLess(stop, owner)
            self.assertLess(owner, hostname)

    def test_operator_selected_jail_cap_is_still_applied(self):
        self.config.storage_policy = "optional"
        self.config.system_quota_gib = 50
        self.bootstrap_runner()
        self.deployment.bootstrap_jails()
        commands = [item.args for item in self.runner.run.call_args_list]
        for jail in (self.config.nextcloud_jail, self.config.onlyoffice_jail):
            self.assertIn(("zfs", "set", "quota=25G", f"{self.config.bastille_dataset}/jails/{jail}"), commands)

    def test_bootstrap_will_not_continue_if_jail_does_not_stop(self):
        self.bootstrap_runner(stop_succeeds=False)
        with self.assertRaisesRegex(RuntimeError, "did not stop"):
            self.deployment.bootstrap_jails()
        self.assertFalse(any(item.args[:2] == ("zfs", "set") for item in self.runner.run.call_args_list))

    def test_prepare_hook_uses_native_api_not_brace_replacement(self):
        with patch("installer.deploy.atomic_write") as write:
            self.deployment.install_prepare_guard("cloudnc", Path("/usr/local/libexec/cloud-storage-guard"))
        self.runner.run.assert_called_once_with("bastille", "config", "cloudnc", "set", "exec.prepare",
                                                "/usr/local/libexec/cloud-storage-guard cloudnc")
        write.assert_not_called()

    def test_unmanaged_or_stopped_jail_cannot_run_command(self):
        with self.assertRaisesRegex(ValueError, "unmanaged"):
            self.deployment.jail("othernc", "service", "apache24", "status")
        self.runner.run.assert_not_called()
        self.runner.run.side_effect = lambda *args, **kwargs: result(returncode=1)
        with self.assertRaisesRegex(RuntimeError, "stopped"):
            self.deployment.jail("cloudnc", "service", "apache24", "status")
        self.assertTrue(all(item.args[0] == "jls" for item in self.runner.run.call_args_list))

    def test_jail_identity_is_checked_before_command_and_same_jid_after(self):
        valid = f"11 cloudnc {self.deployment.jail_root('cloudnc')}\n"
        invalid = ("", "0 cloudnc /root", "not-a-jid cloudnc /root", valid.replace("cloudnc", "othernc"),
                   "11 cloudnc /unexpected/root\n", valid + "extra-field\n")
        for identity in invalid:
            with self.subTest(initial=identity):
                self.runner.run.reset_mock(side_effect=True)
                self.runner.run.side_effect = [result(identity)]
                with self.assertRaises(RuntimeError):
                    self.deployment.jail("cloudnc", "private-helper")
                self.assertEqual(self.runner.run.call_count, 1)
        for identity in (*invalid, valid.replace("11 ", "13 ")):
            with self.subTest(final=identity):
                self.runner.run.reset_mock(side_effect=True)
                self.runner.run.side_effect = [result(valid), result(), result(identity)]
                with self.assertRaises(RuntimeError):
                    self.deployment.jail("cloudnc", "private-helper")
                self.assertEqual(self.runner.run.call_args_list[1].args, ("jexec", "11", "private-helper"))

    def test_verify_rejects_either_stopped_jail_before_other_checks(self):
        for stopped in ("cloudnc", "cloudoo"):
            with self.subTest(stopped=stopped):
                self.runner.run.reset_mock()
                def run(*args, **kwargs):
                    self.assertEqual(args[:2], ("jls", "-j"))
                    return result(returncode=1) if args[2] == stopped else self.run_command(*args, **kwargs)
                self.runner.run.side_effect = run
                with self.assertRaisesRegex(RuntimeError, "stopped"):
                    self.deployment.verify()
                self.assertEqual(self.runner.run.call_count, 1 if stopped == "cloudnc" else 2)

    def test_database_redo_default_and_effective_value_are_checked_without_writes(self):
        template = (Path(__file__).resolve().parents[1] / "resources/templates/nextcloud/my.cnf").read_text()
        self.assertIn("innodb_log_file_size = 256M", template)
        self.assertIn("innodb_flush_log_at_trx_commit = 1", template)
        self.assertIn("innodb_doublewrite = ON", template)
        for value in ("100663296", "", "not-a-number", "134217728\n0", "-1", "9" * 21):
            with self.subTest(value=value), patch.object(self.deployment, "jail", return_value=result(value)) as jail:
                with self.assertRaisesRegex(RuntimeError, "at least 128 MiB"):
                    self.deployment.verify_database_configuration()
                self.assertEqual(jail.call_args.args[-1], "SELECT @@innodb_log_file_size")
                self.assertTrue(jail.call_args.kwargs["hide_output"])
        for value in (128 * 1024 * 1024, 256 * 1024 * 1024, 512 * 1024 * 1024):
            with patch.object(self.deployment, "jail", return_value=result(str(value) + "\n")):
                self.deployment.verify_database_configuration()
                self.assertEqual(self.deployment.manifest["database_configuration"]["innodb_log_file_size"], value)

    def test_connector_url_verification_preserves_tls_modes_and_never_repairs(self):
        for mode in ("provided", "external"):
            self.config.tls_mode = mode
            expected = {"DocumentServerUrl": self.config.public_url + "onlyoffice/",
                        "DocumentServerInternalUrl": f"http://{self.config.onlyoffice_ip}:8081/",
                        "StorageUrl": self.config.storage_url}
            for drift in (None, *expected):
                def jail(name, *args, **kwargs):
                    self.assertEqual(name, self.config.nextcloud_jail)
                    self.assertEqual(args[-3:-1], ("config:app:get", "onlyoffice"))
                    self.assertTrue(kwargs["hide_output"])
                    return result("unexpected" if args[-1] == drift else expected[args[-1]])
                with self.subTest(mode=mode, drift=drift), patch.object(self.deployment, "jail", side_effect=jail) as run:
                    if drift:
                        with self.assertRaisesRegex(RuntimeError, drift):
                            self.deployment.verify_connector_urls()
                    else:
                        self.deployment.verify_connector_urls()
                        self.assertEqual(run.call_count, 3)

    def test_verify_requires_nonempty_inventory_running_processes_and_ready_status(self):
        plan = self.retain_versions()
        self.matching_host_packages(plan)
        ready = {"installed": True, "maintenance": False, "needsDbUpgrade": False, "version": "35.0.0.0"}
        cases = [("cloudnc", ready, True), ("cloudoo", ready, True), (None, ready, False)]
        cases += [(None, value, True) for value in ("", [], {**ready, "installed": False},
                  {**ready, "maintenance": True}, {**ready, "needsDbUpgrade": True},
                  {**ready, "version": "34.0.0.0"}, {**ready, "version": "35.0.1.0"},
                  {**ready, "version": 35.0}, {**ready, "installed": 1})]
        cases.append((None, ready, True))
        for empty, status, processes in cases:
            with self.subTest(empty=empty, status=status, processes=processes):
                self.deployment.manifest = {}
                def jail(name, *args, **kwargs):
                    if args[0] == "supervisorctl":
                        return result("ds:docservice RUNNING\nds:metrics " + ("RUNNING\n" if processes else "STOPPED\n"))
                    if args[0] == "pkg":
                        group = "nextcloud" if name == "cloudnc" else "onlyoffice"
                        return result(" \n" if name == empty else "".join(
                            f"{package} {record['version']} {record['origin']}\n"
                            for package, record in plan["packages"][group].items()))
                    if args[-1] == "--output=json":
                        return result(status if isinstance(status, str) else json.dumps(status))
                    return result()
                with patch.object(self.deployment, "jail", side_effect=jail), \
                        patch.object(self.deployment, "verify_database_configuration"), \
                        patch.object(self.deployment, "verify_connector_urls"):
                    if empty is None and status is ready and processes:
                        self.deployment.verify()
                        self.assertEqual(self.deployment.manifest["nextcloud_status"], ready)
                    else:
                        with self.assertRaises(RuntimeError):
                            self.deployment.verify()
                        self.assertNotIn("nextcloud_status", self.deployment.manifest)

    def test_verify_refuses_missing_or_drifted_packages_in_the_full_locked_closure(self):
        plan = self.retain_versions()
        self.matching_host_packages(plan)
        for group, package in (("nextcloud", plan["roles"]["php"]), ("nextcloud", "fixture-library"),
                               ("onlyoffice", "nginx"), ("onlyoffice", "webfonts")):
            for missing in (False, True):
                with self.subTest(group=group, package=package, missing=missing):
                    def jail(name, *args, **kwargs):
                        if args[0] == "supervisorctl":
                            return result("ds:docservice RUNNING\nds:metrics RUNNING\n")
                        if args[0] == "pkg":
                            current = "nextcloud" if name == "cloudnc" else "onlyoffice"
                            inventory = {name: record["version"] for name, record in plan["packages"][current].items()}
                            if current == group:
                                if missing:
                                    del inventory[package]
                                else:
                                    inventory[package] += "_99"
                            return result("".join(f"{name} {version} {plan['packages'][current][name]['origin']}\n"
                                                  for name, version in inventory.items()))
                        return result()
                    with patch.object(self.deployment, "jail", side_effect=jail), \
                            patch.object(self.deployment, "verify_database_configuration"), \
                            patch.object(self.deployment, "verify_connector_urls"), \
                            self.assertRaisesRegex(RuntimeError, "Installed package versions differ from the retained version lock"):
                        self.deployment.verify()
                    self.assertNotIn("nextcloud_status", self.deployment.manifest)

    @contextmanager
    def network_sandbox(self):
        files = {}
        for name in ("/etc/rc.conf", "/etc/sysctl.conf", "/boot/loader.conf", "/etc/pf.cloud-installer.conf"):
            path = self.directory / Path(name).name
            atomic_write(path, "original " + name + "\n")
            files[name] = path
        def path(*parts):
            actual = Path(*parts)
            return files.get(str(actual), actual)
        self.runner.run.side_effect = lambda *args, **kwargs: result(returncode=1 if args[0] == "ifconfig" else 0)
        self.runner.output.side_effect = lambda *args: "" if args[0] == "pfctl" else "0"
        with patch("installer.deploy.Path", side_effect=path), \
                patch("installer.deploy.PF_FILE", files["/etc/pf.cloud-installer.conf"]):
            yield files

    def test_network_uses_unique_private_transaction_and_only_arms_worker(self):
        events, states = [], []
        controller = Mock()
        controller.wait_applied.side_effect = lambda: events.append("applied")
        def arm(state):
            self.assertTrue((state / "firewall-transition.json").is_file())
            states.append(state)
            events.append("armed")
            return controller
        def confirm(_):
            events.append("confirm")
            atomic_write(states[-1] / "firewall-confirmed", "confirmed\n")
            active = self.registry.root / "network/active"
            active.unlink(missing_ok=True)
            active.symlink_to(states[-1])
        with self.network_sandbox() as files, patch("installer.deploy.firewall.arm", side_effect=arm), \
                patch("installer.deploy.firewall.mutation") as mutation, \
                patch("installer.host.verify_managed_network"), \
                patch.object(self.deployment, "enable_firewall_with_confirmation", side_effect=confirm):
            self.deployment.configure_network()
            self.deployment.configure_network()
        self.assertEqual(events, ["armed", "applied", "confirm"] * 2)
        self.assertNotEqual(states[0], states[1])
        for state in states:
            self.assertEqual(state.parent, self.registry.root / "transactions")
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            transaction = private_json(state / "firewall-transition.json")
            self.assertEqual(transaction["instances"], ["cloud"])
            self.assertEqual(transaction["network"]["bridge_addresses"], {"bridge240": "10.77.0.1", "bridge241": "10.77.0.5"})
            for source, backup in transaction["backups"].items():
                expected = (private_json(Path(transaction["previous_active"]) / "firewall-transition.json")["network"]["pf_rules"]
                            if transaction["previous_active"] and source.endswith("pf.cloud-installer.conf")
                            else Path(source).read_text())
                self.assertEqual((state / backup).read_text(), expected)
                self.assertEqual((state / backup).stat().st_mode & 0o777, 0o600)
        mutation.assert_not_called()
        controller.cancel.assert_not_called()
        self.assertTrue(all(item.args[0] in ("kldload", "ifconfig") for item in self.runner.run.call_args_list))
        self.assertTrue(all(len(item.args) == 2 for item in self.runner.run.call_args_list if item.args[0] == "ifconfig"))
        for name, path in files.items():
            self.assertEqual(path.read_text(), "original " + name + "\n")

    def test_network_failure_cancels_supervisor_without_parent_rollback_or_lock(self):
        for failing in ("wait", "confirm"):
            controller = Mock()
            states = []
            def arm(state):
                states.append(state)
                return controller
            controller.cancel.side_effect = lambda: atomic_write(states[-1] / "firewall-rolled-back", "rolled back\n")
            if failing == "wait":
                controller.wait_applied.side_effect = RuntimeError("simulated failure")
            with self.subTest(failing=failing), self.network_sandbox(), \
                    patch("installer.deploy.firewall.arm", side_effect=arm), \
                    patch("installer.deploy.firewall.rollback") as rollback, \
                    patch("installer.deploy.firewall.mutation") as mutation, \
                    patch.object(self.deployment, "enable_firewall_with_confirmation", side_effect=RuntimeError("simulated failure")), \
                    self.assertRaisesRegex(RuntimeError, "simulated failure"):
                self.deployment.configure_network()
            controller.cancel.assert_called_once_with()
            rollback.assert_not_called()
            mutation.assert_not_called()

    def test_foreign_pf_state_prevents_transaction_or_policy_change(self):
        for foreign in (("-sr",), ("-sn",), ("-s", "Anchors"), ("-ss",)):
            with self.subTest(foreign=foreign), self.network_sandbox(), patch("installer.deploy.firewall.arm") as arm:
                self.runner.output.side_effect = lambda *args: "foreign" if args[1:] == foreign else ""
                with self.assertRaisesRegex(ValueError, "Foreign PF"):
                    self.deployment.configure_network()
                arm.assert_not_called()
            self.assertEqual(list((self.registry.root / "transactions").iterdir()), [])

    def test_changed_committed_policy_blocks_repeat_transition_before_backups_or_worker(self):
        previous = self.registry.root / "transactions/committed"
        previous.mkdir(mode=0o700)
        atomic_write(previous / "firewall-confirmed", "confirmed\n")
        (self.registry.root / "network/active").symlink_to(previous)
        with self.network_sandbox() as files, \
                patch("installer.host.verify_managed_network", side_effect=ValueError("disk policy differs")), \
                patch("installer.deploy.firewall.arm") as arm, self.assertRaisesRegex(ValueError, "disk policy differs"):
            self.deployment.configure_network()
        arm.assert_not_called()
        self.assertEqual(list((self.registry.root / "transactions").iterdir()), [previous])
        for name, path in files.items():
            self.assertEqual(path.read_text(), "original " + name + "\n")

    def test_unresolved_transaction_refuses_another_policy_before_any_host_command(self):
        pending = self.registry.root / "transactions/interrupted"
        pending.mkdir(mode=0o700)
        atomic_json(pending / "firewall-transition.json", {"instances": ["cloud"]})
        with patch("installer.deploy.firewall.arm") as arm, self.assertRaisesRegex(ValueError, "recover-network"):
            self.deployment.configure_network()
        arm.assert_not_called()
        self.runner.run.assert_not_called()
        self.runner.output.assert_not_called()

    def test_firewall_confirmation_requires_keep_before_deadline(self):
        for answer, readable, accepted in (("KEEP\n", True, True), ("keep\n", True, False),
                                           ("YES\n", True, False), ("", True, False), ("KEEP\n", False, False)):
            controller = Mock(deadline=200)
            stream = io.StringIO(answer)
            with self.subTest(answer=answer, readable=readable), \
                    patch("installer.deploy.time.monotonic", return_value=100), \
                    patch("installer.deploy.sys.stdin", stream), patch("installer.deploy.sys.stdout", io.StringIO()), \
                    patch("installer.deploy.select.select", return_value=([stream] if readable else [], [], [])) as wait:
                if accepted:
                    self.deployment.enable_firewall_with_confirmation(controller)
                    controller.confirm.assert_called_once_with()
                else:
                    with self.assertRaisesRegex(RuntimeError, "not confirmed"):
                        self.deployment.enable_firewall_with_confirmation(controller)
                    controller.confirm.assert_not_called()
                wait.assert_called_once_with([stream], [], [], 95)

    def test_skipped_network_or_jail_phase_is_validated_before_resume(self):
        for phase in ("private networking and PF", "FreeBSD jail roots"):
            journal = Journal(self.deployment.state / "deployment.json", self.config, Mock())
            journal.data["steps"][phase] = {"state": "complete"}
            with self.subTest(phase=phase), patch("installer.host.verify_managed_network", side_effect=ValueError("foreign policy")) as verify:
                self.runner.output.return_value = "foreign root"
                with self.assertRaises(ValueError):
                    self.deployment.validate_resume(journal)
                if phase == "private networking and PF":
                    verify.assert_called_once_with(self.registry, self.runner)
        self.runner.run.assert_not_called()

    def test_new_policy_membership_comes_from_committed_transaction_not_failed_instances(self):
        for instance, network, bridges in (("active", "10.78.0.0/29", ("bridge242", "bridge243")),
                                           ("failed", "10.79.0.0/29", ("bridge244", "bridge245"))):
            config = configuration(instance=instance, private_network=network,
                                   nextcloud_bridge=bridges[0], onlyoffice_bridge=bridges[1])
            self.registry.save_new(config, self.secrets)
            self.registry.set_status(instance, "failed")
        previous = self.registry.root / "transactions/committed"
        previous.mkdir(mode=0o700)
        committed_policy = "block log all\n# original committed policy\n"
        atomic_json(previous / "firewall-transition.json", {"instances": ["active"],
                                                          "network": {"pf_rules": committed_policy}})
        atomic_write(previous / "firewall-confirmed", "confirmed\n")
        (self.registry.root / "network/active").symlink_to(previous)
        with self.network_sandbox(), patch("installer.host.verify_managed_network") as verify, \
                patch("installer.deploy.firewall.arm", return_value=Mock()) as arm, \
                patch.object(self.deployment, "enable_firewall_with_confirmation"):
            self.deployment.configure_network()
        verify.assert_called_once_with(self.registry, self.runner)
        transaction = private_json(arm.call_args.args[0] / "firewall-transition.json")
        self.assertEqual(transaction["instances"], ["active", "cloud"])
        self.assertIn("10.78.0.2", transaction["network"]["pf_rules"])
        self.assertNotIn("10.79.0.2", transaction["network"]["pf_rules"])
        self.assertEqual(transaction["previous_active"], str(previous))
        self.assertEqual(Path(transaction["previous_pf_file"]).read_text(), committed_policy)

    def test_resume_validates_ownership_before_skipping_storage(self):
        self.retain_versions()
        journal = Journal(self.deployment.state / "deployment.json", self.config, Mock())
        journal.data["steps"]["instance ZFS storage"] = {"state": "complete"}
        journal.save()
        self.runner.output.return_value = "other"
        with patch.object(self.deployment, "create_shared_storage") as storage, \
                patch.object(self.registry, "save_host") as host, self.assertRaisesRegex(ValueError, "ownership"):
            self.deployment.apply()
        storage.assert_not_called()
        host.assert_not_called()
        self.assertEqual(private_json(self.deployment.state / "status.json")["state"], "configured")

    def test_source_changed_after_start_refuses_resume_before_host_changes(self):
        self.retain_versions()
        source = self.directory / "source"
        (source / "installer").mkdir(parents=True)
        (source / "resources").mkdir()
        payload = source / "installer/source.py"
        payload.write_text("original\n")
        with patch("installer.deploy.ROOT", source), patch("installer.deploy.RESOURCES", source / "resources"):
            self.deployment.verify_source()
            payload.write_text("changed\n")
            with patch.object(self.registry, "save_host") as host, self.assertRaisesRegex(ValueError, "same installer artifact"):
                self.deployment.apply()
        host.assert_not_called()
        self.runner.run.assert_not_called()

    def test_apply_checkpoints_phases_and_failure_stops_only_reserved_own_jail(self):
        self.retain_versions()
        phases = ("create_shared_storage", "install_manager", "create_storage", "configure_network", "configure_devfs",
                  "bootstrap_jails", "attach_storage", "stage_payloads", "install_nextcloud", "nextcloud_phase",
                  "install_onlyoffice", "integrate", "restart_jails", "verify", "enable_boot")
        atomic_json(self.deployment.state / "cloudnc.creating.json", {"name": "cloudnc"})
        with ExitStack() as stack:
            methods = {name: stack.enter_context(patch.object(self.deployment, name)) for name in phases}
            ssh = stack.enter_context(patch("installer.operations.configure_ssh"))
            methods["nextcloud_phase"].side_effect = RuntimeError("private failure " + self.secrets["db_password"])
            with self.assertRaises(RuntimeError):
                self.deployment.apply()
        self.assertEqual(private_json(self.deployment.state / "status.json")["state"], "failed")
        journal = private_json(self.deployment.state / "deployment.json")
        self.assertEqual(journal["steps"]["Nextcloud prerequisites"]["state"], "complete")
        self.assertEqual(journal["steps"]["Nextcloud database"]["state"], "failed")
        self.assertNotIn(self.secrets["db_password"], (self.deployment.state / "deployment.json").read_text())
        for name in ("install_onlyoffice", "integrate", "restart_jails", "verify", "enable_boot"):
            methods[name].assert_not_called()
        ssh.assert_not_called()
        commands = [item.args for item in self.runner.run.call_args_list]
        self.assertIn(("bastille", "config", "cloudnc", "get", "path"), commands)
        self.assertEqual(commands[-2:], [
            ("bastille", "config", "cloudnc", "set", "boot", "off"), ("bastille", "stop", "cloudnc")])
        self.assertFalse((self.deployment.state / "complete").exists())
        self.assertEqual(private_json(self.deployment.state / "secrets.json"), self.secrets)

    def test_failed_diagnostics_never_bypass_owned_jail_containment(self):
        self.retain_versions()
        atomic_json(self.deployment.state / "cloudnc.creating.json", {"name": "cloudnc"})
        original = RuntimeError("original private failure")
        with patch.object(self.deployment, "validate_resume"), \
                patch.object(self.registry, "save_host"), \
                patch.object(self.registry, "set_status", side_effect=[None, OSError("private write error")]), \
                patch("installer.deploy.Journal") as journal, \
                patch("sys.stderr", new_callable=io.StringIO) as output:
            journal.return_value.run.side_effect = original
            with self.assertRaises(RuntimeError) as caught:
                self.deployment.apply()
        self.assertIs(caught.exception, original)
        self.runner.run.assert_any_call("bastille", "stop", "cloudnc", capture=False)
        self.assertIn("Failed status could not be saved", output.getvalue())
        self.assertNotIn("private write error", output.getvalue())

    def test_final_checkpoint_failure_contains_before_reporting(self):
        self.retain_versions()
        atomic_json(self.deployment.state / "cloudnc.creating.json", {"name": "cloudnc"})
        with patch.object(self.deployment, "validate_resume"), \
                patch.object(self.registry, "save_host"), \
                patch("installer.deploy.Journal"), \
                patch.object(self.deployment, "checkpoint", side_effect=OSError("checkpoint failed")):
            with self.assertRaisesRegex(OSError, "checkpoint failed"):
                self.deployment.apply()
        self.runner.run.assert_any_call("bastille", "stop", "cloudnc", capture=False)
        self.assertEqual(self.registry.status("cloud")["state"], "failed")
        self.assertFalse((self.deployment.state / "complete").exists())

    def test_managed_block_preserves_foreign_contents_and_rejects_ambiguous_delimiters(self):
        path = self.directory / "fstab"
        path.write_text("# packaged defaults\nother /other nullfs ro 0 0\n")
        managed_block(path, "persistent mounts", "first /target nullfs rw 0 0")
        managed_block(path, "persistent mounts", "second /target nullfs rw 0 0")
        text = path.read_text()
        self.assertIn("other /other nullfs ro 0 0", text)
        self.assertNotIn("first /target", text)
        self.assertEqual(text.count("# BEGIN cloud-installer persistent mounts"), 1)
        path.write_text(text + "# BEGIN cloud-installer persistent mounts\n")
        previous = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            managed_block(path, "persistent mounts", "replacement")
        self.assertEqual(path.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
