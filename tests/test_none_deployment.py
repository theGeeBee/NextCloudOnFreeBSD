"""Guarded NC-only orchestration seams, with no native command execution."""

from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path
import ssl
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, PropertyMock, patch

from installer import host, lifecycle
from installer.config import Config
from installer.deploy import Deployment
from installer.resolution import resolve
from installer.state import Registry, private_json
from installer.version_runtime import dependency_text, package_text, runtime_versions
from test_backend_versions import none_metadata
from test_deployment import configuration, result
from test_host import HostModel
import test_deployment as deployment_fixtures


class NoneDeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="none-deployment-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.enterContext(patch.object(Config, "bastille_root", new_callable=PropertyMock,
                                       return_value=str(self.directory / "bastille")))
        self.config = configuration(office_backend="none", private_network="10.77.0.0/30",
                                    storage_policy="optional", accept_microsoft_fonts=False)
        self.registry = Registry(self.directory / "registry")
        self.registry.initialize()
        self.secrets = {"admin_password": "private-admin", "db_password": "a" * 64}
        self.runner = Mock(spec=["run", "output"])
        self.registry.save_new(self.config, self.secrets)
        self.deployment = Deployment(self.config, self.secrets, self.runner,
                                     registry=self.registry, progress=Mock())
        self.plan = resolve(self.config, none_metadata(self.config))
        self.deployment._versions = self.plan
        self.runner.run.return_value = result()

    def test_single_jail_constructor_does_not_probe_or_mutate_host(self):
        d = Deployment(self.config, self.secrets, self.runner, registry=self.registry)
        self.assertEqual(d.config.jails, (self.config.nextcloud_jail,))
        self.runner.run.assert_not_called()
        self.runner.output.assert_not_called()

    def test_only_selected_jail_can_be_addressed(self):
        for method in (self.deployment.jail_root, self.deployment.require_running_jail):
            with self.assertRaises(ValueError):
                method(self.config.onlyoffice_jail)
        self.runner.run.assert_not_called()

    def test_reservations_ignore_unallocated_office_names_and_bridge(self):
        other = replace(self.config, instance="other", private_network="10.78.0.0/30",
                        nextcloud_hostname=self.config.onlyoffice_jail,
                        nextcloud_bridge=self.config.onlyoffice_bridge,
                        public_hostname="other.example.test", ingress_address="192.0.2.11")
        registry = Mock()
        registry.entries.return_value = [(other, {"state": "configured"})]
        registry.host.return_value = None
        _, _, configs = host._registry_plan(self.config, {"memory_mb": 32768}, registry, False)
        self.assertEqual(configs, [other, self.config])
        registry.entries.return_value = [(replace(other, nextcloud_bridge=self.config.nextcloud_bridge),
                                          {"state": "configured"})]
        with self.assertRaisesRegex(ValueError, "Bridge name conflicts"):
            host._registry_plan(self.config, {"memory_mb": 32768}, registry, False)

    def test_storage_and_bridge_inspection_only_probe_selected_resources(self):
        model = HostModel(self.config)
        with patch("installer.host._exists", return_value=False):
            host._check_storage(self.config, [self.config], {}, False, False, model)
        self.assertEqual(host._check_bridges(self.config, [self.config], {}, {}, False, model), {})
        text = repr(model.calls)
        for absent in (self.config.onlyoffice_jail, self.config.onlyoffice_bridge, "/office-"):
            self.assertNotIn(absent, text)
        self.assertIn(self.config.nextcloud_jail, text)
        self.assertIn(self.config.nextcloud_bridge, text)

    def test_bootstrap_uses_one_thick_jail_and_entire_system_quota(self):
        c, d = self.config, self.deployment
        release = Path(c.bastille_root) / "releases" / c.release / "bin"
        release.mkdir(parents=True)
        (release / "sh").touch()
        def run(*args, **kwargs):
            if args[:2] == ("bastille", "create"):
                root = d.jail_root(c.nextcloud_jail)
                (root / "bin").mkdir(parents=True)
                (root / "bin/sh").touch()
                (root.parent / "jail.conf").touch()
            return result(returncode=1 if args[0] == "jls" else 0)
        self.runner.run.side_effect = run
        self.runner.output.return_value = str(d.jail_root(c.nextcloud_jail))
        d.bootstrap_jails()
        self.runner.run.assert_any_call("bastille", "create", "-T", "-B", "--no-boot", "-g", c.nextcloud_gateway,
                                        "-n", c.dns_server, c.nextcloud_jail, c.release,
                                        c.nextcloud_ip + "/30", c.nextcloud_bridge, capture=False)
        self.runner.run.assert_any_call("zfs", "set", f"quota={c.system_quota_gib}G",
                                        f"{c.bastille_dataset}/jails/{c.nextcloud_jail}")
        self.assertNotIn(c.onlyoffice_jail, repr(self.runner.mock_calls))

    def test_start_restart_boot_and_resume_only_address_nc(self):
        c, d = self.config, self.deployment
        def output(*args):
            if args[-1] == "host.hostname":
                return c.nextcloud_host
            if args[0] == "zfs":
                return c.instance
            return str(d.jail_root(c.nextcloud_jail))
        self.runner.output.side_effect = output
        self.runner.run.return_value = result(returncode=1)
        with patch.object(d, "require_running_jail") as running:
            d.ensure_running()
            running.assert_called_once_with(c.nextcloud_jail)
        d.restart_jails()
        d.enable_boot()
        d.validate_resume(SimpleNamespace(data={"steps": {"FreeBSD jail roots": {"state": "complete"}}}))
        self.runner.run.assert_any_call("bastille", "start", c.nextcloud_jail, capture=False)
        self.runner.run.assert_any_call("bastille", "restart", c.nextcloud_jail, capture=False)
        self.runner.run.assert_any_call("bastille", "config", c.nextcloud_jail, "set", "boot", "on")
        self.assertNotIn(c.onlyoffice_jail, repr(self.runner.mock_calls))

    def test_attach_storage_stages_only_nc_mounts_and_hosts(self):
        c, d = self.config, self.deployment
        root = d.jail_root(c.nextcloud_jail)
        (root / "var/log").mkdir(parents=True)
        (root / "etc").mkdir()
        (root / "var/log/messages").write_text("seeded log\n")
        (root.parent / "jail.conf").write_text('mount.fstab = "fstab";\n')
        d.storage = [replace(item, mountpoint=str(self.directory / "storage" / Path(item.mountpoint).name))
                     for item in d.storage]
        for item in d.storage:
            Path(item.mountpoint).mkdir(parents=True, exist_ok=True)
        local = self.directory / "local"
        local.mkdir()
        def path(*parts):
            value = Path(*parts)
            return local / value.relative_to("/usr/local") if value.is_relative_to("/usr/local") else value
        self.runner.run.return_value = result(returncode=1)
        with patch("installer.deploy.Path", side_effect=path), \
                patch("installer.deploy.storage_guard", return_value="# selected guard\n"), \
                patch.object(d, "ensure_running") as start:
            d.attach_storage()
        start.assert_called_once()
        hosts = (root / "etc/hosts").read_text()
        self.assertIn(c.nextcloud_ip, hosts)
        self.assertNotIn(c.onlyoffice_ip, hosts)
        fstab = (root.parent / "fstab").read_text()
        for item in d.storage:
            if item.jail:
                self.assertIn(item.mountpoint + " " + str(root) + item.target + " nullfs rw", fstab)
        self.assertNotIn(c.onlyoffice_jail, repr(self.runner.mock_calls))
        self.assertTrue((d.state / "allow-start").is_file())

    def test_payload_contains_nc_workers_and_exact_schema2_runtime_without_office(self):
        c, d = self.config, self.deployment
        (d.jail_root(c.nextcloud_jail) / "root").mkdir(parents=True)
        with patch("installer.version_runtime.connector_text", side_effect=AssertionError("office payload")):
            d.stage_payloads()
        payload = d.jail_root(c.nextcloud_jail) / "root/cloud-installer"
        runtime = private_json(payload / "runtime.json")
        self.assertNotIn("office_backend", runtime)
        self.assertEqual(runtime["versions"]["office_backend"], "none")
        self.assertEqual(runtime["versions"], runtime_versions(
            self.plan, package_text(self.plan, "nextcloud"), dependency_text(self.plan, "nextcloud")))
        for key in ("onlyoffice_ip", "storage_url", "jwt_secret", "font_profile", "instance"):
            self.assertNotIn(key, runtime)
        for file in ("connector.json", "fonts-unavailable", "apache-onlyoffice.conf", "secrets.json",
                     "resources/jails/onlyoffice.sh", "resources/templates/onlyoffice", "installer/office.py"):
            self.assertFalse((payload / file).exists(), file)
        for file in ("nextcloud.sh", "nextcloud-bootstrap.php", "versions.sh", "ssh.sh"):
            self.assertTrue((payload / "resources/jails" / file).is_file())
        self.assertFalse((Path(c.bastille_root) / "jails" / c.onlyoffice_jail).exists())

    def test_finish_sends_no_secrets_and_never_probes_office(self):
        d = self.deployment
        with patch.object(d, "jail") as jail, patch.object(d, "wait_for_office") as office:
            d._integrate()
        office.assert_not_called()
        self.assertEqual(jail.call_args.args, (self.config.nextcloud_jail, "/bin/sh",
                                              "/root/cloud-installer/resources/jails/nextcloud.sh", "finish"))
        self.assertEqual(jail.call_args.kwargs, {"capture": False})

    def test_verification_keeps_nc_services_inventory_and_status_checks(self):
        c, d = self.config, self.deployment
        packages = self.plan["packages"]["nextcloud"]
        inventory = "\n".join(f"{name} {item['version']} {item['origin']}" for name, item in packages.items())
        status = {"installed": True, "maintenance": False, "needsDbUpgrade": False,
                  "version": self.plan["applications"]["nextcloud"] + ".0"}
        def jail(name, *args, **kwargs):
            self.assertEqual(name, c.nextcloud_jail)
            if args[:2] == ("pkg", "query"):
                return result(inventory)
            if args[-1] == "--output=json":
                return result(json.dumps(status))
            if args[0] == "mariadb":
                return result(str(128 * 1024 * 1024))
            return result()
        self.runner.output.side_effect = lambda *args: "|".join(
            self.plan["packages"]["host"][args[-1]][key] for key in ("version", "origin"))
        with patch.object(d, "require_running_jail"), patch.object(d, "jail", side_effect=jail) as worker, \
                patch.object(d, "wait_for_office") as office, patch.object(d, "plugin_command") as plugins:
            d.verify()
            self.assertEqual(d.manifest["nextcloud_status"], status)
            office.assert_not_called()
            plugins.assert_not_called()
            for service in ("mysql-server", "redis", "php_fpm", "apache24", "cron"):
                worker.assert_any_call(c.nextcloud_jail, "service", service, "status", capture=False)
            self.assertNotIn("onlyoffice", repr(worker.call_args_list).lower())
            for invalid in ("", inventory + "\nunselected 1.0 misc/unselected"):
                inventory = invalid
                with self.assertRaises(RuntimeError):
                    d.verify()
            inventory = "\n".join(f"{name} {item['version']} {item['origin']}" for name, item in packages.items())
            status["needsDbUpgrade"] = True
            with self.assertRaisesRegex(RuntimeError, "not an installed, ready"):
                d.verify()

    def test_readiness_reports_unsupported_enrollment_after_nc_verification(self):
        with patch.object(self.deployment, "verify") as verify, \
                patch("installer.enrollment.capture_baseline") as capture:
            self.deployment.initial_readiness()
        verify.assert_called_once()
        capture.assert_not_called()
        record = private_json(self.deployment.state / "enrollment-unavailable.json")
        self.assertFalse(record["eligible"])
        self.assertIn("Not enrolled", record["reason"])

    def test_generated_health_python_uses_selected_listener_and_rejects_db_upgrade(self):
        class HealthScriptCaptured(Exception):
            pass

        d = self.deployment
        self.runner.output.side_effect = lambda *args: "|".join(
            self.plan["packages"]["host"][args[-1]][key] for key in ("version", "origin"))
        for mode, public_port in (("acme", 443), ("external", 443), ("acme", 8443)):
            with self.subTest(tls_mode=mode, public_port=public_port):
                d.config = replace(self.config, tls_mode=mode, public_https_port=public_port)
                scripts = []

                def jail(name, *args, **kwargs):
                    self.assertEqual(name, self.config.nextcloud_jail)
                    if args[:2] == ("python3", "-c"):
                        scripts.append(args[2])
                        raise HealthScriptCaptured()
                    if args[0] == "mariadb":
                        return result(str(128 * 1024 * 1024))
                    return result()

                with patch.object(d, "require_running_jail"), patch.object(d, "jail", side_effect=jail):
                    with self.assertRaises(HealthScriptCaptured):
                        d.verify()
                self.assertEqual(len(scripts), 1)
                runtime = {"tls_mode": mode, "nextcloud_ip": d.config.nextcloud_ip,
                           "public_hostname": d.config.public_hostname,
                           "public_url": d.config.public_url,
                           "versions": {"nextcloud": self.plan["applications"]["nextcloud"]}}
                status = {"installed": True, "maintenance": False, "needsDbUpgrade": False,
                          "version": self.plan["applications"]["nextcloud"] + ".0"}
                opener = MagicMock()
                response = opener.open.return_value.__enter__.return_value
                expected = ("http://" + d.config.nextcloud_ip if mode == "external"
                            else "https://" + d.config.public_hostname) + "/status.php"
                with patch("pathlib.Path.read_text", return_value=json.dumps(runtime)), \
                        patch("pathlib.Path.exists", return_value=False), \
                        patch("urllib.request.build_opener", return_value=opener) as build:
                    response.read.return_value = json.dumps(status).encode()
                    exec(compile(scripts[0], "<none-health>", "exec"), {})
                    opener.open.assert_called_once_with(expected, timeout=30)
                    response.read.assert_called_once_with(4096)
                    handlers = build.call_args.args
                    self.assertEqual(handlers[0].proxies, {})
                    self.assertTrue(handlers[1]._context.check_hostname)
                    self.assertEqual(handlers[1]._context.verify_mode, ssl.CERT_REQUIRED)
                    status["needsDbUpgrade"] = True
                    response.read.return_value = json.dumps(status).encode()
                    with self.assertRaisesRegex(SystemExit, "not ready"):
                        exec(compile(scripts[0], "<none-health>", "exec"), {})

    def test_apply_phase_order_omits_office_and_retains_initialization(self):
        d = self.deployment
        methods = ("create_shared_storage", "install_manager", "create_storage", "configure_network", "configure_devfs",
                   "bootstrap_jails", "attach_storage", "stage_payloads", "install_nextcloud", "nextcloud_phase",
                   "integrate", "restart_jails", "initial_readiness", "enable_boot", "verify_source", "validate_resume")
        with ExitStack() as stack:
            for method in methods:
                stack.enter_context(patch.object(d, method))
            stack.enter_context(patch("installer.operations.configure_ssh"))
            checkpoint = stack.enter_context(patch("installer.initialization.checkpoint_initialization"))
            office = stack.enter_context(patch.object(d, "install_onlyoffice"))
            journal = stack.enter_context(patch("installer.deploy.Journal"))
            d.apply()
            phases = journal.return_value.run.call_args.args[0]
            names = [name for name, _ in phases]
            self.assertEqual(names, ["shared ZFS hierarchy", "host prerequisites", "instance ZFS storage",
                "private networking and PF", "VNET devfs and boot ordering", "FreeBSD jail roots", "persistent mounts",
                "public provisioning payloads", "Nextcloud prerequisites", "Nextcloud database",
                "quiesced initialization checkpoint", "Nextcloud installation", "Nextcloud publication",
                "Nextcloud finish", "optional jail SSH", "jail restart persistence", "readiness checks", "boot activation"])
            dict(phases)["quiesced initialization checkpoint"]()
            checkpoint.assert_called_once_with(d)
            office.assert_not_called()

    def test_network_transaction_stages_only_nc_bridge(self):
        with deployment_fixtures.DeploymentTests.network_sandbox(self), \
                patch("installer.deploy.firewall.arm") as arm, \
                patch.object(self.deployment, "enable_firewall_with_confirmation"), \
                patch("installer.deploy.pf_rules", return_value="selected policy\n"):
            self.deployment.configure_network()
        transaction = private_json(arm.call_args.args[0] / "firewall-transition.json")
        self.assertEqual(transaction["bridges"], [self.config.nextcloud_bridge])
        self.assertEqual(transaction["network"]["bridge_addresses"],
                         {self.config.nextcloud_bridge: self.config.nextcloud_gateway})
        self.assertNotIn(self.config.onlyoffice_bridge, repr(self.runner.mock_calls))

    def test_removal_without_created_roots_never_targets_unallocated_office(self):
        c, d = self.config, self.deployment
        active = self.registry.root / "network/active"
        active.mkdir()
        self.runner.output.return_value = ""
        def run(*args, **kwargs):
            if '--libxo' in args:
                return result(json.dumps({'__version': '2', 'jail-information': {'jail': []}}))
            return result(returncode=1 if args[0] in ("zfs", "jls", "ifconfig") else 0)
        self.runner.run.side_effect = run
        self.registry.set_status(c.instance, "failed")
        with patch.object(self.registry, "network_configs", return_value=[]):
            lifecycle.remove_instance(d, confirmation="REMOVE " + c.instance)
        self.runner.run.assert_any_call("pfctl", "-k", c.nextcloud_ip)
        self.runner.run.assert_any_call("pfctl", "-k", "0.0.0.0/0", "-k", c.nextcloud_ip)
        self.assertEqual(self.registry.status(c.instance)["state"], "removed")
        commands = repr(self.runner.mock_calls)
        for absent in (c.onlyoffice_jail, c.onlyoffice_ip, c.onlyoffice_bridge):
            self.assertNotIn(absent, commands)

    def test_removal_stops_and_destroys_only_selected_checked_root(self):
        c, d = self.config, self.deployment
        self.registry.set_status(c.instance, "failed")
        self.runner.output.return_value = ""
        running = True
        def run(*args, **kwargs):
            nonlocal running
            if '--libxo' in args:
                rows = [{'jid': '11', 'name': c.nextcloud_jail, 'path': str(d.jail_root(c.nextcloud_jail)),
                         'dying': 'false'}] if running else []
                return result(json.dumps({'__version': '2', 'jail-information': {'jail': rows}}))
            if args[:2] == ('bastille', 'stop'):
                running = False
            if args[:2] == ("jls", "-j"):
                return result()
            return result(returncode=1 if args[0] in ("jls", "zfs", "ifconfig") else 0)
        self.runner.run.side_effect = run
        with patch.object(self.registry, "network_configs", return_value=[]), \
                patch("installer.lifecycle._checked_jails", return_value=[
                    (c.nextcloud_jail, f"{c.bastille_dataset}/jails/{c.nextcloud_jail}")]), \
                patch.object(d, "require_running_jail", return_value=11):
            lifecycle.remove_instance(d, confirmation="REMOVE " + c.instance)
        commands = [call.args for call in self.runner.run.call_args_list]
        stop = ("bastille", "stop", c.nextcloud_jail)
        destroy = ("bastille", "destroy", "-y", c.nextcloud_jail)
        self.assertLess(commands.index(stop), commands.index(destroy))
        self.assertIn(("bastille", "config", c.nextcloud_jail, "set", "boot", "off"), commands)
        self.assertNotIn(c.onlyoffice_jail, repr(commands))


if __name__ == "__main__":
    unittest.main()
