"""Fresh-install selection and temporary execution fences; no host operations."""

from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.config import Config, NO_OFFICE_FIELDS, NATIVE_OFFICE_FIELDS, OFFICE_APP_IDS, datasets, deployment_plan
from installer.deploy import Deployment
from installer.host import preflight
from installer.main import load_secrets, main, recipe_consent, show_status
from installer.operations import backup_database, restore_database
from installer.network import pf_rules, storage_guard
from installer.state import Registry, config_digest
from installer.upgrade_native import LiveTarget
from version_fixtures import LEGACY_CONFIG_JSON, LEGACY_CONFIG_SHA256


def selected(backend):
    value = json.loads(LEGACY_CONFIG_JSON)
    value['office_backend'] = backend
    if backend != 'onlyoffice':
        for key in NO_OFFICE_FIELDS if backend == 'none' else NATIVE_OFFICE_FIELDS:
            value.pop(key, None)
        value['storage_policy'] = 'optional'
        if backend == 'none':
            value['private_network'] = '10.77.0.0/30'
    return Config.from_json(json.dumps(value))


class BackendConfigTests(unittest.TestCase):
    def test_omission_preserves_exact_legacy_bytes_and_hash(self):
        config = Config.from_json(LEGACY_CONFIG_JSON)
        self.assertEqual(config.to_json(), LEGACY_CONFIG_JSON)
        self.assertEqual(config_digest(config), LEGACY_CONFIG_SHA256)
        self.assertNotIn('office_backend', json.loads(config.to_json()))
        self.assertEqual(config.backend, 'onlyoffice')
        explicit = replace(config, office_backend='onlyoffice')
        self.assertEqual(deployment_plan(config), deployment_plan(explicit))
        self.assertEqual(pf_rules(config), pf_rules(explicit))
        self.assertEqual(datasets(config), datasets(explicit))

    def test_none_has_one_real_jail_segment_and_no_office_storage(self):
        config = replace(selected('none'), private_network='10.77.0.0/30', jail_ssh=True,
                         ssh_key_file='/root/admin.pub')
        config.validate_provisioning()
        self.assertEqual(config.jails, (config.nextcloud_jail,))
        self.assertEqual(config.bridges, (config.nextcloud_bridge,))
        self.assertEqual(config.php_callback_children, 0)
        self.assertNotIn(config.ssh_onlyoffice_port, config.ingress_ports)
        self.assertFalse(any('/office-' in item.name for item in datasets(config)))
        self.assertEqual({item.jail for item in datasets(config) if item.jail}, {config.nextcloud_jail})
        self.assertEqual(config.memory_budget_mb,
                         replace(config, office_memory_mb=0).memory_budget_mb)
        plan = deployment_plan(config)
        self.assertIn('one Nextcloud jail', plan)
        self.assertIn('one private bridge', plan)
        for absent in ('webfonts', 'Fonts:', 'plugins requested', '2 office callback', config.onlyoffice_jail):
            self.assertNotIn(absent, plan)
        encoded = config.to_json()
        self.assertEqual(Config.from_json(encoded).to_json(), encoded)
        self.assertFalse(set(json.loads(encoded)) & set(NO_OFFICE_FIELDS))

    def test_four_choices_plan_without_discovery_or_host_probes(self):
        with patch('installer.discovery.discover', side_effect=AssertionError('discovery')):
            with patch('installer.host.Runner.run', side_effect=AssertionError('host probe')):
                for backend in ('onlyoffice', 'none', 'eurooffice', 'collabora'):
                    with self.subTest(backend=backend):
                        config = selected(backend)
                        plan = deployment_plan(config)
                        if backend in ('eurooffice', 'collabora'):
                            self.assertIn('not a Bastille jail', plan)
                            self.assertIn('Native end-to-end acceptance is pending', plan)
                            self.assertIn('do not treat this plan as production readiness', plan)
                            self.assertNotIn('webfonts', plan)
                            self.assertEqual(config.jails, (config.nextcloud_jail,))

    def test_none_accepts_two_web_workers_without_office_reservation(self):
        config = replace(selected('none'), php_budget_mb=1024)
        config.validate_provisioning()
        self.assertIn('2 workers (web only)', deployment_plan(config))

    def test_unknown_values_and_explicit_irrelevant_recipe_fields_fail(self):
        for backend in ('external', 'NONE', 'docker', 1, None):
            with self.subTest(backend=backend), self.assertRaises((ValueError, TypeError)):
                replace(selected('none'), office_backend=backend).validate()
        for backend in ('none', 'eurooffice', 'collabora'):
            value = json.loads(selected(backend).to_json())
            fields = NO_OFFICE_FIELDS if backend == 'none' else NATIVE_OFFICE_FIELDS
            for field in fields:
                with self.subTest(backend=backend, field=field), self.assertRaisesRegex(ValueError, 'recipe fields'):
                    Config.from_json(json.dumps({**value, field: getattr(Config(), field)}))

    def test_direct_config_cannot_discard_unsupported_options_or_change_storage_on_reload(self):
        for backend in ('none', 'eurooffice', 'collabora'):
            config = selected(backend)
            for field, value in (('onlyoffice_hostname', 'foreign.example.test'), ('ssh_onlyoffice_port', 9999),
                                 ('font_profile', 'standard'), ('accept_microsoft_fonts', True),
                                 ('storage_policy', '')):
                with self.subTest(backend=backend, field=field), self.assertRaises(ValueError):
                    replace(config, **{field: value}).validate_provisioning()
            restored = Config.from_json(config.to_json())
            self.assertEqual(datasets(restored), datasets(config))
            self.assertEqual(restored.memory_budget_mb, config.memory_budget_mb)
        for field, value in (('office_memory_mb', 8192), ('office_quota_gib', 42), ('onlyoffice_bridge', 'bridge999')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(selected('none'), **{field: value}).validate_provisioning()

    def test_conflicting_apps_refused_for_new_provisioning_not_historical_read(self):
        for app in OFFICE_APP_IDS:
            with self.subTest(app=app):
                config = replace(selected('none'), additional_nextcloud_apps=app)
                if app != 'onlyoffice':  # already forbidden by the historical reader
                    config = Config.from_json(config.to_json())
                with self.assertRaises(ValueError):
                    config.validate_provisioning()

    def test_fresh_vm_constructor_is_pure_but_native_upgrade_remains_fenced(self):
        for backend in ('eurooffice', 'collabora'):
            config = selected(backend)
            runner, registry = Mock(), Mock()
            registry.lifecycle_enabled.return_value = False
            registry.status.return_value = {'state': 'ready'}
            registry.load.return_value = config
            with self.subTest(backend=backend):
                deployment=Deployment(config, {}, runner, registry=registry)
                self.assertEqual(deployment.config.backend,backend)
                with self.assertRaisesRegex(ValueError, 'not yet supported'):
                    LiveTarget(registry, runner, config.instance)
                runner.assert_not_called()
                self.assertEqual(runner.mock_calls, [])
                registry.instance_path.assert_called_once_with(config.instance)
                rules=pf_rules(config)
                self.assertIn(f'from {config.onlyoffice_gateway} to {config.onlyoffice_ip} port 22',rules)
                guard=storage_guard(config,[])
                self.assertNotIn(config.onlyoffice_jail+')',guard)
                self.assertIn('vmnet/'+config.instance+'office/0/',guard)

    def test_vm_recipe_still_refuses_workstation_execution_before_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            for backend in ('eurooffice', 'collabora'):
                path.write_text(selected(backend).to_json())
                for command in ('install', 'configure'):
                    with self.subTest(backend=backend, command=command), \
                            patch('installer.main.Runner') as runner, \
                            patch('installer.main.Registry') as registry, \
                            patch('installer.main.create_secrets') as secrets:
                        with self.assertRaisesRegex(ValueError, 'target FreeBSD host'):
                            main([command, '--config', str(path)])
                        self.assertEqual(runner.return_value.mock_calls, [])
                        registry.assert_not_called()
                        secrets.assert_not_called()
            registry = Registry(Path(directory) / 'private-state')
            with registry.locked():
                for backend in ('eurooffice','collabora'):
                    config=replace(selected(backend),instance='euro' if backend=='eurooffice' else 'code')
                    registry.save_new(config, {})
                    self.assertEqual(registry.load(config.instance).backend,backend)
                    self.assertEqual(registry.status(config.instance)['state'],'configured')

    def test_actual_offline_cli_has_no_runtime_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'none.json'
            path.write_text(selected('none').to_json())
            with patch('installer.main.Runner', side_effect=AssertionError('probe')), \
                    patch('installer.main.Registry', side_effect=AssertionError('state')), \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(main(['plan', str(path)]), 0)
                self.assertIn('one Nextcloud jail', output.getvalue())

    def test_native_backup_restore_refuse_before_locks_or_helper_mutation(self):
        for backend in ('none', 'eurooffice', 'collabora'):
            deployment = SimpleNamespace(config=selected(backend))
            with self.subTest(backend=backend), patch('installer.operations._database_guard') as guard:
                with self.assertRaisesRegex(ValueError, 'not yet supported'):
                    backup_database(deployment)
                with self.assertRaisesRegex(ValueError, 'not yet supported'):
                    restore_database(deployment, '/not-read', confirmation='RESTORE cloud')
                guard.assert_not_called()

    def test_none_native_upgrade_and_lifecycle_registration_are_refused(self):
        config = selected('none')
        registry, runner = Mock(), Mock()
        registry.lifecycle_enabled.return_value = False
        registry.status.return_value = {'state': 'ready'}
        registry.load.return_value = config
        with self.assertRaisesRegex(ValueError, 'not yet supported'):
            LiveTarget(registry, runner, config.instance)
        self.assertEqual(runner.mock_calls, [])
        with tempfile.TemporaryDirectory() as directory:
            store = Registry(Path(directory) / 'uncreated')
            with patch.object(store, 'lifecycle_enabled', return_value=True), \
                    patch.object(store, '_register') as register:
                with self.assertRaisesRegex(ValueError, 'Lifecycle-enabled'):
                    store.save_new(config, {})
                register.assert_not_called()
            self.assertFalse(store.root.exists())

    def test_no_office_consent_or_secret_schema(self):
        config = replace(selected('none'), tls_mode='external', proxy_networks='192.0.2.20/32')
        ui = Mock()
        recipe_consent(config, SimpleNamespace(yes=True, accept_licenses=False), ui)
        ui.confirm.assert_not_called()
        ui.message.assert_not_called()
        credentials = {'admin_password': 'a-long-private-password', 'db_password': 'a' * 64}
        with patch('installer.main.read_private', return_value=json.dumps(credentials)):
            self.assertEqual(load_secrets('/not-read', backend='none'), credentials)
            with self.assertRaisesRegex(ValueError, 'schema'):
                load_secrets('/not-read')
        with patch('installer.main.read_private', return_value=json.dumps(dict(credentials, jwt_secret='b' * 64))):
            with self.assertRaisesRegex(ValueError, 'schema'):
                load_secrets('/not-read', backend='none')

    def test_none_status_does_not_display_a_missing_office_service(self):
        config = selected('none')
        with tempfile.TemporaryDirectory() as directory:
            registry = Mock()
            registry.entries.return_value = [(config, {'state': 'ready'})]
            registry.instance_path.return_value = Path(directory)
            with patch('sys.stdout', new_callable=io.StringIO) as output:
                show_status(registry, config.instance)
            self.assertIn('Nextcloud only — no integrated document server', output.getvalue())
            self.assertNotIn(config.onlyoffice_jail, output.getvalue())
