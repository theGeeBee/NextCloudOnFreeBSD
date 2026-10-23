"""Synthetic future versions test our selectors, not upstream/native acceptance."""

from copy import deepcopy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import compatibility, discovery, resolution, versions
from installer.config import Config
from test_backend_versions import none_metadata
from test_versions import catalog, change_version, configuration, signed_connector
from test_vm_resolution import vm_metadata
from version_fixtures import historic_policy, LEGACY_CONFIG_JSON, LEGACY_CONFIG_SHA256


BACKENDS = ('onlyoffice', 'none', 'eurooffice', 'collabora')


def future_metadata(config, policy):
    backend = config.office_backend
    data = (catalog(policy, config) if backend == 'onlyoffice' else
            none_metadata(config, policy) if backend == 'none' else vm_metadata(config, policy))
    data['nextcloud'] = ['35.0.9', '35.0.10', '35.1.2', '36.0.0', '35.2.0rc1']
    for name, value in (('php85', '8.5.19_2,1'), ('mariadb123-server', '12.3.10_1'),
                        ('mariadb123-client', '12.3.10_1'), ('apache24', '2.4.90_1'),
                        ('bastille', '1.4.9_2'), ('redis', '8.8.2')):
        change_version(data, name, value)
    if backend == 'onlyoffice':
        change_version(data, 'onlyoffice-documentserver', '9.4.12_7,2')
        data['onlyoffice'] = ['9.4.12', '9.5.0']
    elif backend in versions.VM_BACKENDS:
        change_version(data, 'vm-bhyve', '1.7.9_2')
        change_version(data, 'qemu-tools', '11.1.9_3,1')
    if backend != 'none':
        family = {'onlyoffice':'10.2', 'eurooffice':'11.0', 'collabora':'12.0'}[backend]
        data['connectors'] = {v: [signed_connector(
            version=family + '.' + patch_version,
            platformVersionSpec='>=35.0.0 <36.0.0',
            phpVersionSpec='>=8.5.0 <8.6.0') for patch_version in ('9', '10')]
            for v in data['nextcloud'] if not v.endswith('rc1')}
    return data


class FamilySyntaxTests(unittest.TestCase):
    def test_flat_map_is_copied_without_padding_family_components(self):
        families = {'nextcloud':'35', 'php':'8.5', 'php85-pecl-redis':'6'}
        result = versions.validate_families(families)
        self.assertEqual(result, families)
        result['php'] = '8.6'
        self.assertEqual(families['php'], '8.5')
        for value in (None, [], '', True, {'php':8.5}, {'php':None}, {'php':{'family':'8.5'}},
                      {'php':''}, {'php':'8.5.1'}, {'php':'08.5'}, {'php':'8.*'},
                      {'php':'8.5_1'}, {'php':'8.5,1'}, {'php':'8.5rc1'}, {'php':'8.5\n'},
                      {'bad/key':'8'}, {str(i):'1' for i in range(129)}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                versions.validate_families(value)

    def test_upstream_components_ignore_epoch_revision_but_not_minor_boundaries(self):
        for value, family, expected in (('35.9.12_99,2','35',True), ('9.4.12_7,3','9.4',True),
                                        ('9.40.0,99','9.4',False), ('10.4.0_1','9',False),
                                        ('8.5','8.5',True), ('8.6.0,9','8.5',False)):
            with self.subTest(value=value, family=family):
                self.assertEqual(versions.in_range(value, {'family':family}), expected)
        for value in ('g202508_3', '.10_1', '9.4.1rc1', 'v9.4.1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                versions.in_range(value, {'family':'9.4'})
        rule = {'family':'35', 'min':'35.0.2'}
        versions._range(rule)
        self.assertFalse(versions.in_range('35.0.1_99,9', rule))
        self.assertTrue(versions.in_range('35.9.0', rule))
        for rule in ({'family':'35.0.1'}, {'family':'35','min':'36.0.0'},
                     {'family':'35','exact':'35.0.1'}, {'min':'35.0.0'},
                     {'min':'36.0.0','max_exclusive':'35.0.0'}):
            with self.subTest(rule=rule), self.assertRaises(ValueError): versions._range(rule)
        for rule in ({'exact':'35.0.1'}, {'min':'35.0.0','max_exclusive':'36.0.0'}):
            versions._range(rule)
            self.assertTrue(versions.in_range('35.0.1_9,2', rule))

    def test_empty_family_map_preserves_historical_config_and_lock_shapes(self):
        import hashlib
        old = Config.from_json(LEGACY_CONFIG_JSON)
        self.assertEqual(hashlib.sha256(old.to_json().encode()).hexdigest(), LEGACY_CONFIG_SHA256)
        self.assertNotIn('version_families', json.loads(old.to_json()))
        first, second = Config(), Config()
        first.version_families['php'] = '8.5'
        self.assertEqual(second.version_families, {})
        config = configuration(version_families={})
        policy = historic_policy()
        plan = resolution.resolve(config, catalog(policy, config), policy=policy)
        self.assertNotIn('version_families', plan['constraints'])
        self.assertEqual(resolution.validate_plan(config, plan, policy), plan)
        self.assertEqual(plan['policy_sha256'], 'daa55a823bbe3f895504a8e5e6b0f274b6d02feb81d2a6835f2a8104bbc60efe')

    def test_nonempty_families_round_trip_without_nested_policy_or_string_coercion(self):
        config = Config.from_json(LEGACY_CONFIG_JSON)
        config.version_families = {'nextcloud':'35', 'php':'8.5', 'mariadb123-client':'12.3'}
        restored = Config.from_json(config.to_json())
        self.assertEqual(restored.version_families, config.version_families)
        serialized = json.loads(config.to_json())
        for value in ('php=8.5', None, [], {'php':8.5}, {'php':{'family':'8.5'}}):
            serialized['version_families'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): Config.from_json(json.dumps(serialized))


class FamilyResolutionTests(unittest.TestCase):
    def setUp(self):
        self.policy = versions.load_policy()

    def test_all_backends_select_future_family_releases_and_keep_exact_locks(self):
        for backend in BACKENDS:
            config = configuration(office_backend=backend, version_families={
                'nextcloud':'35.0', 'php':'8.5', 'database':'12.3', 'manager':'1.4',
                'web':'2.4', 'cache':'8', 'php85-pecl-redis':'6'})
            data = future_metadata(config, self.policy)
            before = deepcopy(data)
            with self.subTest(backend=backend), patch('subprocess.run', side_effect=AssertionError('execution')):
                plan = resolution.resolve(config, data, policy=self.policy)
                self.assertEqual(plan['applications']['nextcloud'], '35.0.10')
                self.assertEqual(resolution.validate_plan(config, plan, self.policy), plan)
                self.assertEqual(plan['constraints']['version_families'], config.version_families)
                self.assertEqual(plan['packages']['nextcloud']['php85']['version'], '8.5.19_2,1')
                self.assertEqual(plan['packages']['nextcloud']['php85']['checksum'], data['packages']['php85']['checksum'])
                self.assertIn(resolution.FAMILY_WARNING, plan['warnings'])
                self.assertIn('exact combination', resolution.FAMILY_WARNING)
                self.assertIn('untested', resolution.FAMILY_WARNING)
                if backend != 'none': self.assertTrue(plan['applications']['connector'].endswith('.10'))
                if backend == 'onlyoffice': self.assertEqual(plan['applications']['onlyoffice'], '9.4.12_7,2')
                changed = deepcopy(config)
                changed.version_families['nextcloud'] = '35'
                with self.assertRaises(ValueError): resolution.validate_plan(changed, plan, self.policy)
            self.assertEqual(data, before)

    def test_default_does_not_newly_pin_redis_to_one_family(self):
        config = configuration(office_backend='none')
        for value in ('4.0.0', '5.0.14', '6.2.99', '7.4.8', '8.9.9_9,1'):
            data = future_metadata(config, self.policy)
            change_version(data, 'redis', value)
            with self.subTest(value=value): resolution.resolve(config, data, policy=self.policy)

    def test_constraints_only_restrict_policy_and_never_add_roots(self):
        for families in ({'nextcloud':'36'}, {'php':'8.6'}, {'database':'12.4'}, {'web':'2.5'},
                         {'manager':'1.5'}, {'cache':'9'}, {'made-up-package':'1'},
                         {'libopaque':'1'}, {'php86':'8.6'}, {'connector':'10.2'}, {'onlyoffice':'9.4'}):
            config = configuration(office_backend='none', version_families=families)
            # Build availability without the invalid constraints, so failures
            # belong to resolution rather than the fixture's root enumeration.
            data = future_metadata(configuration(office_backend='none'), self.policy)
            with self.subTest(families=families), self.assertRaises(ValueError):
                resolution.resolve(config, data, policy=self.policy)
        config = configuration(office_backend='none', version_families={'unrelated':'1'})
        data = future_metadata(configuration(office_backend='none'), self.policy)
        from test_versions import record
        data['packages']['unrelated'] = record('unrelated')
        with self.assertRaises(ValueError): resolution.resolve(config, data, policy=self.policy)

    def test_family_constraints_do_not_relax_php_and_database_edges(self):
        config = configuration(office_backend='none', version_families={'php':'8.5','database':'12.3'})
        for failure in ('missing-extension', 'wrong-php-edge', 'database-revision', 'database-epoch', 'wrong-origin'):
            data = future_metadata(config, self.policy)
            if failure == 'missing-extension': data['packages'].pop('php85-xml')
            elif failure == 'wrong-php-edge': data['packages']['php85-xml']['dependencies']['php85']['version'] = '8.5.19'
            elif failure == 'wrong-origin': data['packages']['mariadb123-client']['origin'] = 'misc/foreign'
            else: change_version(data, 'mariadb123-client', '12.3.10_2' if failure == 'database-revision' else '12.3.10_1,1')
            with self.subTest(failure=failure), self.assertRaises(ValueError): resolution.resolve(config, data, policy=self.policy)

    def test_exact_pins_and_constraints_normalize_without_changing_package_identity(self):
        config = configuration(office_backend='onlyoffice', version_families={'nextcloud':'35','onlyoffice':'9.4'},
                               nextcloud_min='35', onlyoffice_exact='9.4.12_7,2', freebsd_release='15.1-RELEASE-p9')
        effective = versions.constraints(config, self.policy)
        self.assertEqual(effective['nextcloud_min'], '35.0.0')
        self.assertEqual(effective['onlyoffice_exact'], '9.4.12_7,2')
        self.assertEqual(effective['version_families'], config.version_families)
        data = future_metadata(config, self.policy)
        resolution.resolve(config, data, policy=self.policy)
        for pin in ('9.4.12_6,2', '9.4.12_7,1', '9.5.0'):
            config.onlyoffice_exact = pin
            with self.subTest(pin=pin), self.assertRaises(ValueError): resolution.resolve(config, data, policy=self.policy)

    def test_family_selected_signed_connector_uses_actual_runtime_manifest(self):
        for backend in ('onlyoffice', 'eurooffice', 'collabora'):
            config = configuration(office_backend=backend)
            data = future_metadata(config, self.policy)
            # Newest signed stable record is valid syntax but excludes PHP8.5;
            # choose the newest compatible record, not feed order or lexicography.
            for records in data['connectors'].values():
                records.insert(0, dict(records[-1], version=records[-1]['version'].rsplit('.',1)[0]+'.11', phpVersionSpec='>=8.6.0 <8.7.0'))
            with self.subTest(backend=backend):
                plan = resolution.resolve(config, data, policy=self.policy)
                self.assertTrue(plan['applications']['connector'].endswith('.10'))
                for field, value in (('signature',''), ('certificate',''), ('signatureDigest','sha256'),
                                     ('download','http://example.test/app'), ('phpVersionSpec','>=8.5'),
                                     ('platformVersionSpec','>=35.0.0')):
                    broken = deepcopy(data)
                    for records in broken['connectors'].values():
                        for record in records: record[field] = value
                    with self.subTest(field=field), self.assertRaises(ValueError): resolution.resolve(config, broken, policy=self.policy)

    def test_vm_numeric_families_do_not_make_opaque_firmware_float(self):
        for backend in ('eurooffice','collabora'):
            config = configuration(office_backend=backend, version_families={'vm_manager':'1.7','vm_image_tools':'11.1'})
            data = future_metadata(config, self.policy)
            resolution.resolve(config, data, policy=self.policy)
            for name, value in (('vm-bhyve','1.8.0'), ('qemu-tools','11.2.0'), ('edk2-bhyve','g202509_1')):
                broken = deepcopy(data)
                change_version(broken, name, value)
                with self.subTest(backend=backend, name=name), self.assertRaises(ValueError): resolution.resolve(config, broken, policy=self.policy)

    def test_all_backend_policy_boundaries_are_not_overridden_by_operator_families(self):
        for backend in BACKENDS:
            config = configuration(office_backend=backend, version_families={'nextcloud':'36'})
            data = future_metadata(configuration(office_backend=backend), self.policy)
            data['nextcloud'] = ['36.0.0']
            with self.subTest(backend=backend), self.assertRaises(ValueError):
                resolution.resolve(config, data, policy=self.policy)
        config = configuration(office_backend='onlyoffice', version_families={'onlyoffice':'9.5'})
        data = future_metadata(configuration(office_backend='onlyoffice'), self.policy)
        change_version(data, 'onlyoffice-documentserver', '9.5.0')
        with self.assertRaises(ValueError): resolution.resolve(config, data, policy=self.policy)

    def test_selected_package_names_constrain_optional_and_transitive_packages_without_new_roots(self):
        plain = configuration(office_backend='none', tls_mode='acme', jail_ssh=True,
                              ssh_shell='zsh', antivirus=True)
        data = future_metadata(plain, self.policy)
        baseline = resolution.resolve(plain, data, policy=self.policy)
        # Synthetic optional roots have 1.0 versions; the library is transitive.
        constrained = deepcopy(plain)
        constrained.version_families = {'py311-certbot':'1', 'zsh':'1', 'clamav':'1', 'fixture-library':'1.2'}
        plan = resolution.resolve(constrained, data, policy=self.policy)
        self.assertEqual(plan['roots'], baseline['roots'])
        self.assertEqual(plan['packages'], baseline['packages'])
        for name in constrained.version_families:
            broken = deepcopy(constrained)
            broken.version_families[name] = '99'
            with self.subTest(name=name), self.assertRaises(ValueError): resolution.resolve(broken, data, policy=self.policy)

    def test_connector_family_nightly_prerelease_and_duplicate_newest_rules(self):
        for backend in ('onlyoffice','eurooffice','collabora'):
            config = configuration(office_backend=backend)
            data = future_metadata(config, self.policy)
            for records in data['connectors'].values():
                family = records[-1]['version'].rsplit('.',1)[0]
                records.extend((dict(records[-1], version=family+'.999', isNightly=True),
                                dict(records[-1], version=family+'.1000rc1'),
                                dict(records[-1], version='99.0.0')))
            with self.subTest(backend=backend):
                plan = resolution.resolve(config, data, policy=self.policy)
                self.assertTrue(plan['applications']['connector'].endswith('.10'))
                config.version_families = {'connector':'99'}
                with self.assertRaises(ValueError): resolution.resolve(config, data, policy=self.policy)
                config.version_families = {}
                for records in data['connectors'].values(): records.append(deepcopy(records[1]))
                with self.assertRaises(ValueError): resolution.resolve(config, data, policy=self.policy)

    def test_conflicting_duplicate_connector_cannot_hide_behind_incompatible_manifest(self):
        for backend in ('onlyoffice', 'eurooffice', 'collabora'):
            config = configuration(office_backend=backend)
            data = future_metadata(config, self.policy)
            for records in data['connectors'].values():
                records.append(dict(records[-1], download='https://example.test/conflicting-release.tar.gz',
                                    phpVersionSpec='>=8.6.0 <8.7.0'))
            with self.subTest(backend=backend), self.assertRaisesRegex(ValueError, 'unique'):
                resolution.resolve(config, data, policy=self.policy)

    def test_vm_resource_profiles_respect_explicit_families_and_minima(self):
        for backend in versions.VM_BACKENDS:
            policy = deepcopy(self.policy)
            current = next(p for p in policy['profiles'] if p.get('office_backend') == backend)
            future = deepcopy(current)
            future['id'] += '-synthetic-nc36'
            future['applications']['nextcloud'] = {'family': '36'}
            future['office_runtime']['resources']['defaults']['memory_mb'] = 8192
            policy['profiles'].append(future)
            for family, memory in (('35', 4096), ('35.0', 4096), ('36', 8192)):
                config = configuration(office_backend=backend, version_families={'nextcloud': family})
                with self.subTest(backend=backend, family=family):
                    self.assertEqual(versions.vm_resource_policy(config, policy)['defaults']['memory_mb'], memory)
            config = configuration(office_backend=backend, version_families={'nextcloud': '35'}, nextcloud_min='36')
            with self.assertRaises(ValueError): versions.vm_resource_policy(config, policy)

    def test_policy_independent_lock_inspection_rejects_contradictory_families(self):
        for backend in BACKENDS:
            config = configuration(office_backend=backend)
            plan = resolution.resolve(config, future_metadata(config, self.policy), policy=self.policy)
            cases = {'php': '8.6', 'database': '12.4', 'apache24': '99', 'unselected-package': '1'}
            if backend != 'none': cases['connector'] = '99'
            for component, family in cases.items():
                changed = deepcopy(plan)
                changed['constraints']['version_families'] = {component: family}
                with self.subTest(backend=backend, component=component), self.assertRaises(ValueError):
                    resolution._plan_inventory(changed)

    def test_future_family_locks_still_require_exact_native_catalog_and_solver_identities(self):
        for backend in BACKENDS:
            config = configuration(office_backend=backend, version_families={'nextcloud':'35'})
            data = future_metadata(config, self.policy)
            plan = resolution.resolve(config, data, policy=self.policy)
            before = deepcopy(plan)
            runner = Mock()
            def dry_run(*args, **kwargs):
                selected = [record for record in data['packages'].values()
                            if record['name']+'-'+record['version'] in args[7:]]
                rows = ''.join(f"\t{record['name']}: {record['version']}\n" for record in selected)
                return SimpleNamespace(stdout=f'The following {len(selected)} package(s) will be affected (of 0 checked):\nNew packages to be INSTALLED:\n{rows}\nNumber of packages to be installed: {len(selected)}\n')
            runner.run.side_effect = dry_run
            with self.subTest(backend=backend), patch.object(discovery, '_catalog') as native:
                native.return_value.__enter__.return_value = (data['target'], data['packages'], ('pkg',))
                discovery.probe_packages(config, plan, runner)
                self.assertEqual(runner.run.call_count, 3 if backend=='onlyoffice' else 2)
                for field, value in (('version','1.4.10_1'), ('origin','misc/not-bastille'), ('checksum','2$'+'b'*103)):
                    changed = deepcopy(data['packages'])
                    changed['bastille'][field] = value
                    native.return_value.__enter__.return_value = (data['target'], changed, ('pkg',))
                    runner.reset_mock()
                    with self.subTest(field=field), self.assertRaises(ValueError): discovery.probe_packages(config, plan, runner)
                    runner.run.assert_not_called()
                self.assertEqual(plan, before)

    def test_future_family_retained_lock_rejects_missing_edges_and_checksum_corruption(self):
        for backend in BACKENDS:
            config = configuration(office_backend=backend)
            data = future_metadata(config, self.policy)
            plan = resolution.resolve(config, data, policy=self.policy)
            for failure in ('checksum', 'runtime-edge', 'missing-client'):
                changed = deepcopy(plan)
                packages = changed['packages']['nextcloud']
                if failure == 'checksum': packages['php85']['checksum'] = 'not-a-checksum'
                elif failure == 'runtime-edge': packages['php85-xml']['dependencies'].clear()
                else: packages.pop('mariadb123-client')
                with self.subTest(backend=backend, failure=failure), self.assertRaises(ValueError):
                    resolution.validate_plan(config, changed, self.policy)
