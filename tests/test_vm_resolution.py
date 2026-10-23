"""VM metadata/resolution boundaries; synthetic catalogs are not native acceptance."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import compatibility, discovery, resolution, versions, version_runtime
from test_backend_versions import none_metadata
from test_versions import configuration, record, signed_connector


def artifact_proof(runtime):
    return {'guest_image': {key: runtime['guest_image'][key] for key in ('url','sha512')} | {'available': True},
            'container': {key: runtime['container'][key] for key in ('reference','index_digest','architecture')} | {'os':'linux','available':True}}


def vm_metadata(config, policy=None):
    policy = versions.load_policy() if policy is None else policy
    profile = versions.selected_profiles(config, policy)[0]
    # Reuse the common NC fixture generator with the explicitly selected common
    # fields; this test helper is not production policy inheritance/overlay logic.
    nc_policy = deepcopy(policy)
    nc = nc_policy['profiles'][1]
    for key in ('applications','php_suffix','roots','php_extensions','extension_ranges','optional_roots'):
        nc[key] = deepcopy(profile[key])
    nc['roles'] = {role: deepcopy(rule) for role, rule in profile['roles'].items() if not role.startswith('vm_')}
    c = deepcopy(config)
    c.office_backend = 'none'
    c.version_families = {key: value for key, value in getattr(c, 'version_families', {}).items()
                          if not key.startswith('vm_') and key not in
                          {rule['package'] for role, rule in profile['roles'].items() if role.startswith('vm_')}}
    data = none_metadata(c, nc_policy)
    for role, rule in profile['roles'].items():
        if role.startswith('vm_'):
            bounds = rule.get('range', {})
            value = rule.get('version_exact') or bounds.get('exact') or bounds.get('min') or {
                'vm_manager': '1.7.5', 'vm_image_tools': '11.1.2_1'}[role]
            data['packages'][rule['package']] = record(rule['package'], value, rule['origin'])
    runtime = profile['office_runtime']
    app = profile['connector']['app_id']
    bounds = profile['connector']['nextcloud']
    data.update(schema_version=3, office_backend=config.office_backend, connector_app=app,
                 connectors={v: [signed_connector(version=(profile['connector']['version'].get('exact')
                         or profile['connector']['version'].get('min')
                         or {'eurooffice':'11.0.6','collabora':'12.0.1'}[config.office_backend]),
                        phpVersionSpec=profile['connector']['php_manifest'],
                        platformVersionSpec=f">={bounds['min']} <{bounds['max_exclusive']}",
                        download=f'https://example.test/{app}.tar.gz')]
                    for v in data['nextcloud'] if versions.in_range(v, profile['applications']['nextcloud'])},
                artifacts={profile['id']: artifact_proof(runtime)})
    return data


class VmResolutionTests(unittest.TestCase):
    def test_each_vm_plan_has_only_real_groups_connector_and_immutable_artifacts(self):
        for backend, app in (('eurooffice','eurooffice'), ('collabora','richdocuments')):
            config = configuration(office_backend=backend, accept_microsoft_fonts=False)
            metadata = vm_metadata(config)
            with self.subTest(backend=backend), patch('subprocess.run', side_effect=AssertionError('resolver execution')):
                plan = resolution.resolve(config, metadata)
                self.assertEqual(plan, resolution.validate_plan(config, plan))
                self.assertEqual(plan['schema_version'], 3)
                self.assertEqual(plan['office_backend'], backend)
                self.assertEqual(plan['connector_app'], app)
                self.assertEqual(set(plan['applications']), {'nextcloud','connector'})
                self.assertEqual(set(plan['packages']), {'host','nextcloud'})
                self.assertEqual(set(plan['roots']), {'host','nextcloud'})
                self.assertTrue({'vm-bhyve','qemu-tools','edk2-bhyve'} <= set(plan['packages']['host']))
                self.assertNotIn('onlyoffice', plan['roles'])
                self.assertNotIn('fonts_unavailable', plan)
                self.assertTrue(any('metadata inspection only' in w for w in plan['warnings']))
                self.assertIn('@sha256:', plan['office_runtime']['container']['reference'])
                self.assertFalse(any(name in plan['packages']['nextcloud'] for name in ('webfonts','onlyoffice-documentserver','fontconfig')))
                packages = version_runtime.package_text(plan,'nextcloud')
                edges = version_runtime.dependency_text(plan,'nextcloud')
                runtime = version_runtime.runtime_versions(plan, packages, edges)
                self.assertEqual(runtime['connector_app'], app)
                self.assertEqual(runtime['office_backend'], backend)
                self.assertNotIn('onlyoffice', runtime)
                self.assertEqual(json.loads(version_runtime.connector_text(plan)), plan['connector'])

    def test_php_manifest_forms_do_not_weaken_native_checks_or_runtime_policy(self):
        for backend in ('eurooffice','collabora'):
            config = configuration(office_backend=backend)
            data = vm_metadata(config)
            plan = resolution.resolve(config, data)
            with self.assertRaises(ValueError): compatibility.connector_record(plan['connector'])
            compatibility.connector_record(plan['connector'], plan['connector_app'])
            # Family policy accepts changed valid manifests, but never a manifest
            # which excludes the actual selected PHP runtime.
            for record_set in data['connectors'].values(): record_set[0]['phpVersionSpec'] = '>=8.6.0'
            with self.assertRaises(ValueError): resolution.resolve(config, data)
        for value in ('>=8.3', '>8.3.0', '<9.0.0', '8.*', '>=8.3.0 || >=9.0.0'):
            with self.assertRaises(ValueError): versions.connector_php_spec(value)

    def test_firmware_exact_version_and_complete_dependencies_are_not_guessed(self):
        c = configuration(office_backend='eurooffice')
        for failure in ('missing-tool','opaque-firmware','broken-dependency'):
            data = vm_metadata(c)
            if failure == 'missing-tool': data['packages'].pop('qemu-tools')
            elif failure == 'opaque-firmware': data['packages']['edk2-bhyve']['version'] = 'g202509_1'
            else: data['packages']['qemu-tools']['dependencies'] = {'missing':{'version':'1.0','origin':'misc/missing'}}
            with self.subTest(failure=failure), self.assertRaises(ValueError): resolution.resolve(c,data)

    def test_unavailable_mismatched_or_mutable_artifacts_are_refused(self):
        c = configuration(office_backend='collabora')
        for failure in ('unavailable','checksum','reference','platform'):
            data = vm_metadata(c)
            proof = next(iter(data['artifacts'].values()))
            if failure == 'unavailable': proof['guest_image']['available'] = False
            elif failure == 'checksum': proof['guest_image']['sha512'] = 'f'*128
            elif failure == 'reference': proof['container']['reference'] = 'docker.io/collabora/code:latest'
            else: proof['container']['architecture'] = 'arm64'
            with self.subTest(failure=failure), self.assertRaises(ValueError): resolution.resolve(c,data)
        p = versions.load_policy()
        p['profiles'][-1]['office_runtime']['container']['reference'] = 'docker.io/collabora/code:latest'
        with self.assertRaises(ValueError): versions.validate_policy(p)

    def test_retained_plan_backends_extra_groups_and_pin_drift_fail_closed(self):
        c = configuration(office_backend='eurooffice')
        original = resolution.resolve(c, vm_metadata(c))
        for field, value in (('office_backend','collabora'), ('connector_app','richdocuments'), ('fonts_unavailable',[])):
            plan = deepcopy(original); plan[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): resolution.validate_plan(c,plan)
        plan = deepcopy(original); plan['packages']['onlyoffice'] = {}
        with self.assertRaises(ValueError): resolution.validate_plan(c,plan)
        p = versions.load_policy(); p['profiles'][2]['office_runtime']['guest_image']['sha512'] = 'a'*128
        with self.assertRaisesRegex(ValueError,'policy changed'): resolution.validate_plan(c,original,p)
        self.assertFalse(resolution.assess_upgrade(original,original)['execution_authorized'])
        self.assertEqual(resolution.assess_upgrade(original,original)['status'],'blocked')

    def test_code_tag_is_not_guessed_to_be_its_reported_product_version(self):
        c=configuration(office_backend='collabora')
        plan=resolution.resolve(c,vm_metadata(c))
        container=plan['office_runtime']['container']
        self.assertEqual(container['release'],'26.04.5.1.1')
        self.assertEqual(container['product_version'],'26.04.5.1')
        for value in ('26.04.5.1-rc1',None,''):
            runtime=deepcopy(plan['office_runtime']);runtime['container']['product_version']=value
            with self.assertRaises(ValueError):versions.validate_office_runtime(runtime)

    def test_live_vm_discovery_branches_before_office_font_and_unselected_app_queries(self):
        for backend in ('eurooffice','collabora'):
            c = configuration(office_backend=backend)
            data = vm_metadata(c)
            calls = []
            def fetch(url):
                calls.append(url)
                if url == discovery.NEXTCLOUD_RELEASES:
                    return ''.join(f'<a href="nextcloud-{v}.tar.bz2{s}">x</a>' for v in data['nextcloud'] for s in ('','.asc'))
                if url == discovery.ONLYOFFICE_RELEASES: raise AssertionError('native office release query')
                release = next(v for v in data['nextcloud'] if discovery.CONNECTORS.format(version=v) == url)
                return json.dumps([{'id':data['connector_app'],'certificate':'fixture-certificate','releases':data['connectors'][release]}])
            with self.subTest(backend=backend), patch.object(discovery,'_catalog') as catalog, \
                    patch.object(discovery,'probe_vm_artifacts', side_effect=artifact_proof):
                catalog.return_value.__enter__.return_value = (data['target'], data['packages'], ())
                discovered = discovery.discover(c,Mock(),fetch=fetch)
                plan = resolution.resolve(c,discovered)
                self.assertEqual(plan['connector_app'],data['connector_app'])
                self.assertNotIn(discovery.ONLYOFFICE_RELEASES,calls)
                self.assertEqual(set(discovered['packages']), set(data['packages']))
                self.assertFalse(any('36.0.0' in url for url in calls))

    def test_future_compatible_policy_and_dependency_change_is_data_only_fixture(self):
        p = versions.load_policy()
        selected = p['profiles'][2]
        selected['applications']['nextcloud'] = {'min':'36.0.0','max_exclusive':'36.0.1'}
        selected['roots']['nextcloud'].append('future-compatible-library')
        selected['roles']['vm_image_tools'].pop('range', None)
        selected['roles']['vm_image_tools']['version_exact'] = '11.1.3_1'
        c = configuration(office_backend='eurooffice',nextcloud_min='36.0.0',nextcloud_exact='36.0.0')
        data = vm_metadata(c,p)
        plan = resolution.resolve(c,data,policy=p)
        self.assertEqual(plan['applications']['nextcloud'],'36.0.0')
        self.assertIn('future-compatible-library',plan['packages']['nextcloud'])
        self.assertEqual(plan['packages']['host']['qemu-tools']['version'],'11.1.3_1')
        c.nextcloud_exact = '36.0.1'
        with self.assertRaises(ValueError): resolution.resolve(c,data,policy=p)

    def test_newer_unavailable_artifact_does_not_poison_allowed_older_candidate(self):
        p = versions.load_policy()
        old = p['profiles'][2]
        old['applications']['nextcloud'] = {'exact':'35.0.0'}
        newer = deepcopy(old); newer['id'] += '-new'
        newer['applications']['nextcloud'] = {'exact':'35.0.1'}
        p['profiles'].append(newer)
        c = configuration(office_backend='eurooffice')
        data = vm_metadata(c,p)
        data['connectors']['35.0.1'] = deepcopy(data['connectors']['35.0.0'])
        data['artifacts'][newer['id']] = {'unavailable':True}
        plan = resolution.resolve(c,data,policy=p)
        self.assertEqual(plan['applications']['nextcloud'],'35.0.0')
        self.assertEqual(resolution.validate_plan(c,plan,p),plan)
        c.nextcloud_min = '35.0.1'
        with self.assertRaises(ValueError): resolution.resolve(c,data,policy=p)

    def test_native_solver_receives_only_host_and_nc_exact_closures(self):
        c = configuration(office_backend='collabora')
        data = vm_metadata(c); plan = resolution.resolve(c,data)
        runner = Mock()
        summaries = []
        for group in ('host','nextcloud'):
            values = plan['packages'][group]
            summaries.append(SimpleNamespace(stdout=f'The following {len(values)} package(s) will be affected (of 0 checked):\n\nNew packages to be INSTALLED:\n'
                + ''.join(f'\t{name}: {item["version"]}\n' for name,item in sorted(values.items()))
                + f'\nNumber of packages to be installed: {len(values)}\n'))
        runner.run.side_effect = summaries
        with patch.object(discovery,'_catalog') as catalog:
            catalog.return_value.__enter__.return_value = (data['target'],data['packages'],('pkg',))
            discovery.probe_packages(c,plan,runner)
        self.assertEqual(runner.run.call_count,2)
        commands = repr(runner.run.call_args_list)
        self.assertIn('edk2-bhyve-g202508_3',commands)
        self.assertNotIn('onlyoffice-documentserver',commands)
        self.assertNotIn('webfonts',commands)
        for call in runner.run.call_args_list:
            self.assertIn('-n',call.args)
            self.assertIn('-y',call.args)


class PinnedArtifactDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.runtime = deepcopy(versions.load_policy()['profiles'][2]['office_runtime'])
        self.manifest = json.dumps({'schemaVersion':2,'config':{'digest':'sha256:'+'a'*64},
                                    'layers':[{'digest':'sha256:'+'b'*64,'size':1}]}).encode()
        digest = 'sha256:' + hashlib.sha256(self.manifest).hexdigest()
        self.runtime['container']['reference'] = 'ghcr.io/euro-office/documentserver@' + digest
        self.index = json.dumps({'schemaVersion':2,'manifests':[{'digest':digest,'platform':{'os':'linux','architecture':'amd64'}}]}).encode()
        self.runtime['container']['index_digest'] = 'sha256:' + hashlib.sha256(self.index).hexdigest()
        self.calls = []

    def request(self,url,**kwargs):
        self.calls.append((url,kwargs))
        if url.endswith('.sha512'): return self.runtime['guest_image']['sha512'].encode(), {}
        if kwargs.get('method') == 'HEAD': return b'', {'Content-Length':'157220864'}
        if '/token?' in url: return b'{"token":"token-canary"}', {}
        if url.endswith(self.runtime['container']['index_digest']): return self.index, {}
        return self.manifest, {}

    def test_exact_pinned_index_platform_and_guest_checksum_only_no_image_download(self):
        proof = discovery.probe_vm_artifacts(self.runtime,request=self.request)
        self.assertEqual(proof,artifact_proof(self.runtime))
        self.assertNotIn('token-canary',json.dumps(proof))
        self.assertEqual(len(self.calls),5)
        for url,kwargs in self.calls:
            if 'headers' in kwargs: self.assertTrue(url.startswith('https://ghcr.io/v2/euro-office/documentserver/manifests/'))
            if url.endswith('.qcow2'): self.assertEqual(kwargs['method'],'HEAD')

    def test_bad_bytes_or_platform_never_become_available_or_leak_token(self):
        original = self.request
        def corrupt(url,**kwargs):
            body,head = original(url,**kwargs)
            return (b'wrong-manifest',head) if '/manifests/' in url else (body,head)
        with self.assertRaises(discovery.DiscoveryError) as caught:
            discovery.probe_vm_artifacts(self.runtime,request=corrupt)
        self.assertNotIn('token-canary',str(caught.exception))
        item=json.loads(self.index); item['manifests'][0]['platform']['architecture']='arm64'
        self.index=json.dumps(item).encode()
        self.runtime['container']['index_digest']='sha256:'+hashlib.sha256(self.index).hexdigest()
        with self.assertRaises(discovery.DiscoveryError): discovery.probe_vm_artifacts(self.runtime,request=self.request)
