"""Offline capture/fault tests: synthetic archives, no native provisioning."""

from copy import deepcopy
import base64
import hashlib
import io
import json
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_candidate as candidate
from installer import maintenance_admission as admission, maintenance_update
from installer import nextcloud_update as update, maintenance_preflight as preflight
from installer.generations import _encode
from installer.maintenance_state import NativeState
from installer.state import Registry
import test_nextcloud_update as archives
from test_maintenance_preflight import inputs
from version_fixtures import historical_maintenance_policy


OPERATION = "maint-" + "a" * 32
XML = b"<info><id>serverinfo</id><version>7.0.0</version><dependencies><nextcloud min-version='35' max-version='35'/></dependencies></info>"
CONNECTOR_XML = b"<info><id>onlyoffice</id><version>10.2.1</version><dependencies><php min-version='8.2' max-version='8.5'/><nextcloud min-version='33' max-version='35'/></dependencies></info>"
CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"synthetic DER certificate").decode() + "\n-----END CERTIFICATE-----\n"


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(historical_maintenance_policy())
        fixture = archives.NextcloudUpdateTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.config, self.versions, self.observed, self.repository, _ = inputs()
        self.versions["connector"].update(certificate=CERTIFICATE,
            signature=base64.b64encode(b"original archive signature fixture").decode())
        self.connector_files = {"appinfo/info.xml": CONNECTOR_XML, "lib/app.php": b"connector fixture"}
        self.connector_files["appinfo/signature.json"] = _encode(dict(
            certificate=CERTIFICATE, signature=base64.b64encode(b"tree signature fixture").decode(),
            hashes={name: hashlib.sha512(data).hexdigest() for name, data in self.connector_files.items()}))
        self.connector_archive = fixture.home / "onlyoffice.tar.gz"
        self.make_connector()
        for name, data in self.connector_files.items():
            fixture.write(fixture.context.host(update.APP + "/custom_apps/onlyoffice/" + name), data)
        fixture.files["apps/serverinfo/appinfo/info.xml"] = XML
        fixture.target_files["apps/serverinfo/appinfo/info.xml"] = XML
        fixture.make_tar()
        fixture.make_zip()
        fixture.write(fixture.context.host(update.APP + "/apps/serverinfo/appinfo/info.xml"), XML)
        checksum = update._digest_file(fixture.context.host(update.RETAINED), update.MAX_ARCHIVE)[0]
        fixture.write(fixture.context.host(update.SHA_PROOF), (checksum + "\n").encode())
        self.registry = Registry(fixture.home / "state")
        self.registry.root.mkdir(mode=0o700)
        self.native = NativeState(self.registry, {"fixture": "executor"})
        self.store = self.native.store
        self.directory = "maintenance/operations/" + OPERATION
        self.store._mkdir(self.directory)
        self.store._mkdir("fixture")
        graph = self.store._put("fixture/graph.json", {"fixture": "graph"})
        generation = self.store._put("fixture/generation.json", {"fixture": "generation"})
        versions = self.store._put("fixture/versions.json", self.versions)
        executor = dict(source_sha256="c" * 64, executor_sha256="d" * 64)
        self.retained = dict(graph=graph, generation=generation, versions=versions,
                             executor=executor, network={"fixture": "committed"})
        self.plan = dict(bindings=self.retained, artifacts=[{"fixture": "locked"}])
        plan_ref = self.store._put("fixture/plan.json", self.plan)
        self.parent = dict(operation=OPERATION, instance=self.config.instance, plan=plan_ref, executor=executor)
        self.store._put(self.directory + "/operation.json", self.parent)
        self.cache = dict(artifacts=[])
        self.journal = Mock()
        self.journal.read.return_value = dict(phase="staged", evidence={"artifacts": {"fixture": "receipt"}})
        self.pair = {self.config.nextcloud_jail: 42, self.config.onlyoffice_jail: 43}
        self.d = SimpleNamespace(config=self.config, versions=self.versions, registry=self.registry,
            jail_root=lambda jail: fixture.root, require_running_jail=Mock(side_effect=lambda jail: self.pair[jail]),
            require_original_artifact=Mock())
        self.config_output = dict(system={"datadirectory": "/var/nc-data", "dbtype": "mysql",
            "dbpassword": "PRIVATE-DO-NOT-RETAIN", "cloud_installer_connector_auth": dict(
                record_sha256=update._hash(candidate.connector_text(self.versions).encode()),
                manifest_sha256=update._hash(self.connector_files["appinfo/signature.json"]))},
            apps={"onlyoffice": {"enabled": "yes"}})
        config_hash = preflight.digest(dict(system=self.config_output["system"],
                                          onlyoffice=self.config_output["apps"]["onlyoffice"]))
        self.original = (graph, generation, {}, {}, {"trees": {}, "config:list": config_hash})
        self.harness = admission.SourceAdmission(self.native)
        self.evidence = self.store._put("fixture/admission.json", dict(recipe=preflight.recipe(),
            graph=graph, generation=generation))
        self.order = []
        self.admit = self.mock(admission.SourceAdmission, "admit_source", side_effect=self.admitted)
        self.mock(admission.SourceAdmission, "_original", return_value=self.original)
        self.trees = self.mock(admission, "_trees")
        self.mock(admission.fence, "_root_required")
        from installer import enrollment_start
        self.held = self.mock(enrollment_start, "_held")
        self.mock(type(self.store), "_active", return_value=graph)
        self.mock(candidate.operations, "load_operation", return_value=(self.parent, self.plan, self.journal))
        self.mock(candidate.operations, "bindings", return_value=(self.retained, self.config, self.versions))
        self.mock(candidate.operations, "_artifact_bindings", return_value={})
        self.verify_cache = self.mock(candidate.staging, "verify_stage", return_value=self.cache)
        self.mock(maintenance_update, "_hardened")  # Synthetic fixture uses test-user permissions.
        self.mock(candidate, "collect_php", side_effect=lambda _: deepcopy(self.observed["php"]))
        self.mock(candidate.time, "time", return_value=1000)
        self.mock(candidate.os, "statvfs", return_value=SimpleNamespace(f_bavail=100000000, f_frsize=4096))
        self.calls = []
        self.transport = self.mock(candidate.bounded_process, "run", side_effect=self.run_command)
        self.begin = self.mock(NativeState, "begin", side_effect=AssertionError("must remain pre-intent"))

    def mock(self, target, name, **kwargs):
        return self.enterContext(patch.object(target, name, **kwargs))

    def admitted(self, deployment):
        self.order.append("admitted")
        return dict(startup={}, evidence=self.evidence)

    def make_connector(self, extra=None, files=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in (self.connector_files if files is None else files).items():
                member = tarfile.TarInfo("onlyoffice/" + name)
                member.size, member.mode = len(data), 0o644
                archive.addfile(member, io.BytesIO(data))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b"x" * extra.size))
        self.fixture.write(self.connector_archive, output.getvalue())

    def run_command(self, argv, **kwargs):
        self.order.append("native")
        self.calls.append((argv, kwargs))
        self.assertIsNone(self.store.pending())
        self.assertEqual(kwargs["env"], candidate.bounded_process.ENV)
        self.assertEqual(kwargs["stdin"], b"")
        if argv[:1] == ("/usr/sbin/jexec",):
            args = argv[2:]
        else:
            args = argv
        if args[0] == "/usr/bin/id":
            output = b"8080\n"
        elif candidate._CONNECTOR_INTEGRITY in args:
            output = b"No errors found\n"
        elif candidate._CONNECTOR_SIGNATURE in args:
            output = b"Connector archive verified\n"
        elif args[:3] == ("/usr/local/sbin/pkg", "query", "%n %v %o"):
            group = "host" if args == argv else ("nextcloud" if argv[1] == "42" else "onlyoffice")
            output = "\n".join(" ".join(row[k] for k in ("name", "version", "origin"))
                                for row in self.observed["packages"][group]).encode()
        elif args == candidate.DB:
            db = self.observed["database"]
            output = (db["version"] + "-MariaDB\t" + db["isolation"] + "\n" + "\n".join(db["engines"]) + "\n").encode()
        elif "status" in args:
            output = _encode({k: v for k, v in self.observed["nextcloud"].items() if k != "apps"})
        elif "app:list" in args:
            output = _encode(dict(enabled={"onlyoffice": "10.2.1", "serverinfo": "7.0.0"}, disabled=[]))
        elif "config:list" in args:
            output = _encode(self.config_output)
        elif args[:2] == ("/sbin/sysctl", "-n"):
            output = b"4096" if args[-1] == "hw.pagesize" else b"100000000"
        elif "--verify" in args:
            output = self.fixture.pgp
        elif args[0] in ("/usr/bin/uname", "/bin/freebsd-version"):
            output = {"-s": b"FreeBSD", "-m": b"amd64", "-U": b"1501000",
                      "-u": b"15.1-RELEASE", "-r": b"15.1-RELEASE"}[args[-1]]
        elif "rquery" in args:
            packages = self.repository["packages"]
            if args[-1] == "%n|%dn|%dv|%do":
                output = "\n".join("|".join((name, dep, row["version"], row["origin"]))
                    for name, item in packages.items() for dep, row in item["dependencies"].items()).encode()
            else:
                output = "\n".join("|".join((name, item["version"], item["origin"], item["abi"],
                    str(len(item["dependencies"])), item["checksum"])) for name, item in packages.items()).encode()
        else:
            output = b""
        return update.NativeResult(0, output)

    def collect(self, **kwargs):
        with self.registry.locked():
            return candidate.collect(self.d, OPERATION, source_admission=self.harness,
                target_zip=self.fixture.zip, target_asc=self.fixture.asc, target_sig=self.fixture.sig,
                source_asc=self.fixture.source_asc, public_key=self.fixture.key, **kwargs)

    def authority(self):
        return candidate.ArtifactsOnlyAuthority(self.d, OPERATION, self.harness)

    def test_initial_capture_queries_again_after_final_checks_and_uses_query_start_time(self):
        clock=[1000];events=[]
        real_observations=candidate._observations
        real_recheck=candidate.ArtifactsOnlyAuthority.recheck_source
        real_bound=update._bound;real_source_bound=update._source_bound
        final=[False];calls=[]
        def observations(authority,now):
            calls.append(now);events.append('observations')
            value=real_observations(authority,now)
            if len(calls)==2:clock[0]=1260
            return value
        def recheck(authority):
            real_recheck(authority);events.append('source-recheck');final[0]=True
        def bound(*args):
            value=real_bound(*args)
            if final[0]:events.append('bundle-check')
            return value
        def source_bound(*args):
            value=real_source_bound(*args)
            if final[0]:events.append('archive-check');clock[0]=1250
            return value
        with patch.object(candidate.time,'time',side_effect=lambda:clock[0]), \
                patch.object(candidate,'_observations',side_effect=observations), \
                patch.object(candidate.ArtifactsOnlyAuthority,'recheck_source',new=recheck), \
                patch.object(update,'_bound',side_effect=bound), \
                patch.object(update,'_source_bound',side_effect=source_bound):
            captured=self.collect(connector_archive=self.connector_archive)
        record=json.loads(self.store._bound(captured.reference))
        self.assertEqual(calls,[1000,1250])
        self.assertEqual(record['observations']['captured_at'],1250)
        self.assertTrue(record['report']['eligible'])
        self.assertEqual(events[-4:],['source-recheck','bundle-check','archive-check','observations'])

    def assert_final_observation_drift(self,section):
        real=candidate._observations;count=[0]
        def capture(*args):
            value=real(*args);count[0]+=1
            if count[0]==2:value[section]['unreviewed-change']='changed'
            return value
        with patch.object(candidate,'_observations',side_effect=capture):
            with self.assertRaisesRegex(candidate.CandidateError,'candidate-inputs-changed'):
                self.collect(connector_archive=self.connector_archive)
        self.assertFalse(self.store._present('maintenance/operations/'+OPERATION+'/candidate.json'))
        self.begin.assert_not_called()

    def test_final_binding_drift_refuses(self):self.assert_final_observation_drift('bindings')
    def test_final_package_drift_refuses(self):self.assert_final_observation_drift('packages')
    def test_final_php_drift_refuses(self):self.assert_final_observation_drift('php')
    def test_final_database_drift_refuses(self):self.assert_final_observation_drift('database')
    def test_final_application_drift_refuses(self):self.assert_final_observation_drift('nextcloud')
    def test_final_integration_drift_refuses(self):self.assert_final_observation_drift('integrations')

    def test_initial_observation_failure_is_not_recovered_by_recapture(self):
        with patch.object(candidate,'_observations',side_effect=ValueError('unavailable')) as capture:
            captured=self.collect(connector_archive=self.connector_archive)
        record=json.loads(self.store._bound(captured.reference))
        capture.assert_called_once()
        self.assertEqual(record['observations'],{})
        self.assertIn('runtime-observation-unavailable',record['report']['blockers'])
        self.assertFalse(record['report']['eligible'])

    def test_final_observation_failure_retains_first_evidence_and_blocks(self):
        real=candidate._observations;count=[0]
        def capture(*args):
            count[0]+=1
            if count[0]==2:raise ValueError('unavailable')
            return real(*args)
        with patch.object(candidate,'_observations',side_effect=capture):
            captured=self.collect(connector_archive=self.connector_archive)
        record=json.loads(self.store._bound(captured.reference))
        self.assertEqual(record['observations']['captured_at'],1000)
        self.assertIn('runtime-observation-unavailable',record['report']['blockers'])
        self.assertFalse(record['report']['eligible'])

    def test_final_capture_preserves_repository_blocker(self):
        with patch.object(candidate,'_repository',side_effect=ValueError('unavailable')):
            captured=self.collect(connector_archive=self.connector_archive)
        record=json.loads(self.store._bound(captured.reference))
        self.assertIn('repository-or-manifest-unavailable',record['report']['blockers'])
        self.assertFalse(record['report']['eligible'])

    def assert_expiry_during_revalidation(self, boundary):
        captured=self.collect(connector_archive=self.connector_archive)
        before=self.store._bound(captured.reference);clock=[1299];source_calls=[0]
        if boundary=='repository':
            real=candidate._repository
            def call(*args):
                value=real(*args);clock[0]=1301;return value
            manager=patch.object(candidate,'_repository',side_effect=call)
        else:
            real=candidate.ArtifactsOnlyAuthority.recheck_source
            def call(authority):
                value=real(authority);source_calls[0]+=1
                if source_calls[0]==1:clock[0]=1301
                return value
            manager=patch.object(candidate.ArtifactsOnlyAuthority,'recheck_source',new=call)
        with self.registry.locked(),patch.object(candidate.time,'time',side_effect=lambda:clock[0]),manager:
            with self.assertRaisesRegex(candidate.CandidateError,'candidate-ineligible-or-stale'):
                candidate.revalidate(captured,self.d,source_admission=self.harness)
        self.assertEqual(self.store._bound(captured.reference),before)
        if boundary=='source':self.assertEqual(source_calls[0],1)
        self.begin.assert_not_called()

    def test_age_crossing_300_during_repository_is_refused(self):
        self.assert_expiry_during_revalidation('repository')

    def test_age_crossing_300_during_final_source_check_is_refused(self):
        self.assert_expiry_during_revalidation('source')

    def test_revalidation_keeps_final_tree_scan_after_candidate_queries(self):
        captured = self.collect(connector_archive=self.connector_archive)
        events = []
        real = candidate._observations
        def observations(*args):
            events.append("observations")
            return real(*args)
        self.trees.reset_mock()
        self.trees.side_effect = lambda *args: events.append("trees")
        with self.registry.locked(), patch.object(candidate, "_observations", side_effect=observations):
            candidate.revalidate(captured, self.d, source_admission=self.harness)
        self.assertEqual(events, ["observations", "trees"])
        self.trees.assert_called_once_with(self.d, self.original[4]["trees"])
        self.begin.assert_not_called()

    def test_tree_drift_during_candidate_queries_refuses_at_final_scan(self):
        captured = self.collect(connector_archive=self.connector_archive)
        real = candidate._observations
        def observations(*args):
            result = real(*args)
            self.trees.side_effect = ValueError("tree drift after installed queries")
            return result
        self.trees.reset_mock()
        with self.registry.locked(), patch.object(candidate, "_observations", side_effect=observations):
            with self.assertRaises(candidate.CandidateError):
                candidate.revalidate(captured, self.d, source_admission=self.harness)
        self.trees.assert_called_once()
        self.begin.assert_not_called()

    def test_saved_observation_age_299_accepts_but_301_never_refreshes_receipt(self):
        captured=self.collect(connector_archive=self.connector_archive)
        before=self.store._bound(captured.reference)
        with self.registry.locked(),patch.object(candidate.time,'time',return_value=1299):
            self.assertEqual(candidate.revalidate(captured,self.d,source_admission=self.harness),captured.reference)
        with self.registry.locked(),patch.object(candidate.time,'time',return_value=1301):
            with self.assertRaisesRegex(candidate.CandidateError,'candidate-ineligible-or-stale'):
                candidate.revalidate(captured,self.d,source_admission=self.harness)
        self.assertEqual(self.store._bound(captured.reference),before)
        self.begin.assert_not_called()

    def test_repository_keeps_complete_locked_closures_but_not_unrelated_ports(self):
        original = deepcopy(self.repository['packages'])
        extra = deepcopy(next(iter(original.values())))
        extra.update(name='unrelated-port', version='1.0', origin='misc/unrelated-port', dependencies={})
        self.repository['packages']['unrelated-port'] = extra
        captured = self.collect(connector_archive=self.connector_archive)
        record = json.loads(self.store._bound(captured.reference))
        self.assertEqual(record['repository']['packages'], original)
        self.assertNotIn('unrelated-port', record['repository']['available_packages'])
        self.assertEqual(record['repository']['catalog_sha256'], preflight.digest(dict(
            target=self.repository['target'],repository=self.config.repository,packages=self.repository['packages'])))
        for group in preflight.GROUPS:
            self.assertEqual(candidate.compatibility.closure(record['repository']['packages'], self.versions['roots'][group]),
                             self.versions['packages'][group])
        self.assertTrue(record['report']['eligible'])
        self.assertLessEqual(len(self.store._bound(captured.reference)), candidate.MAX_FILE_BYTES)

    def test_oversized_candidate_reports_bound_and_does_not_write_partial_record(self):
        with patch.object(candidate, 'MAX_FILE_BYTES', 1):
            with self.assertRaisesRegex(candidate.CandidateError, 'candidate-record-too-large'):
                self.collect(connector_archive=self.connector_archive)
        self.assertFalse(self.store._present('maintenance/operations/'+OPERATION+'/candidate.json'))

    def large_inventory_serializer(self, *, oversized):
        from installer import generations
        self.assertEqual(candidate.MAX_FILE_BYTES, generations.MAX_FILE_BYTES)
        serialize = update.bundle_record
        measured = {}

        def expanded(bundle):
            # Only the inventory-volume seam is synthetic: archive authentication
            # still uses the small fixture. The complete candidate envelope,
            # canonical encoder, size guard, Store and decoder remain real.
            record = json.loads(_encode(serialize(bundle)))
            inventories = [record[key] for key in ('source_inventory', 'target_inventory')]
            base = len(_encode({'bundle': record}))
            def row(index, target):
                return dict(path=f'apps/serverinfo/appinfo/fixture-resource-{index:05d}.json',
                            size=4096, sha256=('b' if target else 'a') * 64,
                            executable=False)
            for target, inventory in enumerate(inventories):
                inventory['files'].append(row(0, target))
            pair_bytes = len(_encode({'bundle': record})) - base
            # Leave room for actual observations/catalog/report metadata below
            # the bound; the negative case exceeds it using inventory alone.
            budget = generations.MAX_FILE_BYTES + (128 * 1024 if oversized else -256 * 1024)
            count = (budget - base) // pair_bytes
            for target, inventory in enumerate(inventories):
                inventory['files'].extend(row(index, target) for index in range(1, count))
                self.assertLess(len(inventory['files']), update.MAX_ENTRIES)
            measured['bundle_sha256'] = hashlib.sha256(_encode(record)).hexdigest()
            measured['added_files_per_inventory'] = count
            measured['bundle_envelope_bytes'] = len(_encode({'bundle': record}))
            # Validate every inventory field/path through the real public decoder.
            update.decode_bundle(record)
            return record

        return expanded, measured

    def test_near_16mib_complete_candidate_envelope_store_load_roundtrip(self):
        from installer import generations
        expanded, measured = self.large_inventory_serializer(oversized=False)
        with patch.object(update, 'bundle_record', side_effect=expanded):
            captured = self.collect(connector_archive=self.connector_archive)
        encoded = self.store._bound(captured.reference)
        size = len(encoded)
        self.assertGreater(size, generations.MAX_FILE_BYTES - 512 * 1024)
        self.assertLess(size, generations.MAX_FILE_BYTES)
        record = json.loads(encoded)
        self.assertTrue(record['report']['eligible'])
        for key in ('observations', 'repository', 'bindings', 'report'):
            self.assertTrue(record[key])
        loaded = candidate.load(self.store, OPERATION)
        self.assertEqual(loaded.reference, captured.reference)
        self.assertEqual(hashlib.sha256(_encode(update.bundle_record(loaded.bundle))).hexdigest(),
                         measured['bundle_sha256'])
        self.assertEqual(hashlib.sha256(self.store._bound(loaded.reference)).hexdigest(),
                         hashlib.sha256(encoded).hexdigest())
        print(f'complete candidate bytes={size}; limit={generations.MAX_FILE_BYTES}; '
              f'added files per inventory={measured["added_files_per_inventory"]}')

    def test_over_16mib_complete_candidate_envelope_refuses_without_partial_record(self):
        from installer import generations
        expanded, measured = self.large_inventory_serializer(oversized=True)
        encode = candidate._encode
        envelope_sizes = []
        def observe(value):
            encoded = encode(value)
            if isinstance(value, dict) and value.get('kind') == 'captured-maintenance-candidate':
                envelope_sizes.append(len(encoded))
            return encoded
        with patch.object(update, 'bundle_record', side_effect=expanded), \
                patch.object(candidate, '_encode', side_effect=observe):
            with self.assertRaisesRegex(candidate.CandidateError, 'candidate-record-too-large'):
                self.collect(connector_archive=self.connector_archive)
        self.assertEqual(len(envelope_sizes), 1)
        self.assertGreater(envelope_sizes[0], generations.MAX_FILE_BYTES)
        self.assertFalse(self.store._present(self.directory + '/candidate.json'))
        self.begin.assert_not_called()
        print(f'refused complete candidate bytes={envelope_sizes[0]}; limit={generations.MAX_FILE_BYTES}; '
              f'added files per inventory={measured["added_files_per_inventory"]}')

    def test_captures_actual_inputs_private_and_pre_intent_without_faking_connector_hash(self):
        captured = self.collect()
        record = json.loads(self.store._bound(captured.reference))
        self.assertEqual(self.order[0], "admitted")
        self.assertEqual(record["observations"]["database"], self.observed["database"])
        self.assertEqual(record["observations"]["php"], self.observed["php"])
        self.assertEqual(record["repository"]["packages"], self.repository["packages"])
        self.assertEqual(record["repository"]["available_packages"], self.repository["available_packages"])
        self.assertEqual(record["repository"]["apps"]["serverinfo"]["phpVersionSpec"], ">=8.3.0 <8.6.0")
        self.assertNotIn("connector", record["repository"]["artifacts"])
        self.assertNotIn("artifact_sha256", record["observations"]["nextcloud"]["apps"]["onlyoffice"])
        self.assertIn(candidate.CONNECTOR_BLOCKER, record["report"]["blockers"])
        self.assertFalse(record["report"]["eligible"])
        self.assertFalse(record["execution_authorized"])
        self.assertNotIn(b"PRIVATE-DO-NOT-RETAIN", self.store._bound(captured.reference))
        self.assertEqual(record["recipe"], preflight.recipe())
        self.assertEqual(record["observations_sha256"], preflight.digest(record["observations"]))
        self.assertEqual(record["repository_sha256"], preflight.digest(record["repository"]))
        self.assertEqual(captured.bundle.operation, OPERATION)
        self.assertEqual((self.store.root / captured.reference["path"]).stat().st_mode & 0o777, 0o600)
        self.assertIsNone(self.store.pending())
        self.begin.assert_not_called()
        with self.assertRaises(ValueError):
            self.store._write_once(captured.reference["path"], b"replace", recover=False)
        self.assertTrue(any("rquery" in argv for argv, _ in self.calls))
        self.assertFalse(any(set(argv) & {"install", "upgrade", "service", "sysrc", "/bin/sh"}
                             for argv, _ in self.calls))

    def test_incompatible_php_and_db_reported_before_any_boot_pending_effect(self):
        self.observed["php"]["main_fpm"]["loaded_modules"].remove("curl")
        self.observed["database"]["engines"] = ["MyISAM"]
        captured = self.collect()
        report = json.loads(self.store._bound(captured.reference))["report"]
        self.assertIn("php-runtime-incompatible", report["blockers"])
        self.assertIn("database-runtime-incompatible", report["blockers"])
        self.assertIsNone(self.store.pending())
        self.begin.assert_not_called()

    def test_bindings_use_canonical_documents_matching_successor_contract(self):
        from installer.maintenance_generations import inspection_bindings
        captured = self.collect()
        record = json.loads(self.store._bound(captured.reference))
        intent = dict(base_graph=self.retained["graph"], executor_sha256="d" * 64)
        bindings = inspection_bindings(self.store, self.retained["generation"], intent,
            dict(network=self.retained["network"]), self.config.to_json().encode(), self.versions)
        self.assertEqual(record["bindings"], bindings)
        self.assertNotEqual(bindings["graph_sha256"], self.retained["graph"]["sha256"])
        self.assertNotEqual(bindings["generation_sha256"], self.retained["generation"]["sha256"])

    def test_disabled_mail_marker_is_not_an_unmanaged_integration(self):
        self.config_output['system']['mail_smtpmode'] = 'null'
        self.config_output['apps']['backgroundjob'] = {'lastjob':'1000'}
        self.original[4]['config:list'] = preflight.digest(dict(system=self.config_output['system'],
                                                              onlyoffice=self.config_output['apps']['onlyoffice']))
        captured = self.collect(connector_archive=self.connector_archive)
        record = json.loads(self.store._bound(captured.reference))
        self.assertFalse(record['observations']['integrations']['unmanaged_integrations'])
        self.assertTrue(record['report']['eligible'])

    def test_backgroundjob_unknown_fields_remain_unmanaged(self):
        self.config_output['apps']['backgroundjob'] = {'lastjob':'1000','unknown':'not-reviewed'}
        captured = self.collect(connector_archive=self.connector_archive)
        record = json.loads(self.store._bound(captured.reference))
        self.assertTrue(record['observations']['integrations']['unmanaged_integrations'])
        self.assertFalse(record['report']['eligible'])

    def test_disabled_mail_with_configured_smtp_fields_still_blocks(self):
        self.config_output['system'].update(mail_smtpmode='null',mail_smtphost='smtp.example.test')
        self.original[4]['config:list'] = preflight.digest(dict(system=self.config_output['system'],
                                                              onlyoffice=self.config_output['apps']['onlyoffice']))
        captured = self.collect(connector_archive=self.connector_archive)
        record = json.loads(self.store._bound(captured.reference))
        self.assertTrue(record['observations']['integrations']['unmanaged_integrations'])
        self.assertFalse(record['report']['eligible'])

    def test_active_mail_remains_an_unmanaged_integration(self):
        self.config_output['system']['mail_smtpmode'] = 'smtp'
        self.original[4]['config:list'] = preflight.digest(dict(system=self.config_output['system'],
                                                              onlyoffice=self.config_output['apps']['onlyoffice']))
        captured = self.collect(connector_archive=self.connector_archive)
        record = json.loads(self.store._bound(captured.reference))
        self.assertTrue(record['observations']['integrations']['unmanaged_integrations'])
        self.assertFalse(record['report']['eligible'])

    def test_load_retained_candidate_is_read_only_and_not_admission(self):
        captured = self.collect(connector_archive=self.connector_archive)
        retained = self.store._bound(captured.reference)
        bundle = json.loads(retained)["bundle"]
        for field in ("source_inventory", "target_inventory"):
            self.assertNotIn("links", bundle[field])
        self.transport.reset_mock()
        self.admit.reset_mock()
        with patch.object(type(self.store), "_write_once", side_effect=AssertionError("read-only")):
            self.assertEqual(candidate.load(self.store, OPERATION), captured)
        self.transport.assert_not_called()
        self.admit.assert_not_called()
        self.begin.assert_not_called()
        with self.registry.locked():
            self.assertEqual(candidate.revalidate(candidate.load(self.store, OPERATION), self.d,
                source_admission=self.harness), captured.reference)
        self.assertEqual(self.store._bound(captured.reference), retained)

    def test_execution_revalidation_returns_its_single_fresh_admission(self):
        captured = self.collect(connector_archive=self.connector_archive)
        self.admit.reset_mock()
        with self.registry.locked():
            checked = candidate.revalidate_for_execution(captured, self.d, source_admission=self.harness)
        self.assertIs(type(checked), candidate.RevalidatedCandidate)
        self.assertEqual(checked.reference, captured.reference)
        self.assertEqual(checked.admission['evidence'], self.evidence)
        self.admit.assert_called_once_with(self.d)
        self.begin.assert_not_called()

    def test_load_refuses_unknown_fields_changed_hashes_or_executable_claim(self):
        captured = self.collect()
        original = json.loads(self.store._bound(captured.reference))
        for change in ({"execution_authorized": True}, {"schema_version": True},
                       {"operation": "maint-" + "b" * 32}, {"unexpected": True},
                       {"observations_sha256": "a" * 64}, {"bundle": {"eligible": True}}):
            with self.subTest(change=change):
                self.store._put(captured.reference["path"], {**original, **change}, replace=True)
                with self.assertRaises(candidate.CandidateError):
                    candidate.load(self.store, OPERATION)
        self.begin.assert_not_called()

    def test_incompatible_target_manifest_is_reported_even_without_connector_archive(self):
        self.fixture.target_files["apps/serverinfo/appinfo/info.xml"] = XML.replace(
            b"<dependencies>", b"<dependencies><php max-version='8.4'/>")
        with patch.object(candidate.time, "time", return_value=1800000000):
            self.fixture.make_zip()
        captured = self.collect()
        report = json.loads(self.store._bound(captured.reference))["report"]
        self.assertIn("shipped-application-incompatible-or-unknown", report["blockers"])
        self.begin.assert_not_called()

    def test_insufficient_real_host_memory_refuses_before_staging(self):
        original = self.transport.side_effect
        def low_memory(argv, **kwargs):
            if argv == ("/sbin/sysctl", "-n", "vm.stats.vm.v_free_count"):
                return update.NativeResult(0, b"0")
            return original(argv, **kwargs)
        self.transport.side_effect = low_memory
        with self.assertRaisesRegex(candidate.CandidateError, "actual-free-memory-insufficient"):
            self.collect()
        self.assertFalse(self.fixture.context.host(update.STAGING + "/" + OPERATION).exists())
        self.begin.assert_not_called()

    def test_stopped_pair_and_unverified_package_cache_refuse_before_artifacts(self):
        self.pair[self.config.onlyoffice_jail] = 0
        with self.assertRaises(candidate.CandidateError):
            self.collect()
        self.transport.assert_not_called()
        self.pair[self.config.onlyoffice_jail] = 43
        self.verify_cache.side_effect = ValueError("private-cache-fault")
        with self.assertRaisesRegex(candidate.CandidateError, "capture-incomplete"):
            self.collect()
        self.transport.assert_not_called()
        self.begin.assert_not_called()

    def test_catalog_drift_is_observed_not_replaced_with_retained_package_lock(self):
        name = next(iter(self.repository["packages"]))
        self.repository["packages"][name]["version"] = "999.0.0"
        captured = self.collect()
        record = json.loads(self.store._bound(captured.reference))
        self.assertEqual(record["repository"]["packages"][name]["version"], "999.0.0")
        self.assertIn("repository-or-artifact-unavailable", record["report"]["blockers"])
        self.begin.assert_not_called()

    def test_source_admission_failure_precedes_every_native_capture_and_stage(self):
        self.admit.side_effect = ValueError("PRIVATE")
        with self.assertRaisesRegex(candidate.CandidateError, "capture-incomplete"):
            self.collect()
        self.transport.assert_not_called()
        self.assertFalse(self.fixture.context.host(update.STAGING + "/" + OPERATION).exists())
        self.begin.assert_not_called()

    def test_unlocked_pending_missing_db_lock_and_forged_admission_refuse(self):
        with self.assertRaises(ValueError):
            self.authority()
        with self.registry.locked():
            with self.assertRaisesRegex(candidate.CandidateError, "trusted-source-admission-required"):
                candidate.ArtifactsOnlyAuthority(self.d, OPERATION, {"eligible": True})
            with patch.object(type(self.store), "pending", return_value={"operation": "other"}):
                with self.assertRaisesRegex(candidate.CandidateError, "pre-intent-only"):
                    self.authority()
            self.held.side_effect = ValueError("database lock absent")
            with self.assertRaises(ValueError):
                self.authority()
        self.transport.assert_not_called()

    def test_artifact_authority_rejects_every_mutation_phase_and_arbitrary_php(self):
        with self.registry.locked():
            authority = self.authority()
            for phase in update.Phase:
                if phase is not update.Phase.ARTIFACTS:
                    with self.assertRaisesRegex(candidate.CandidateError, "artifacts-only-authority"):
                        authority.validate(authority.context, phase)
            with self.assertRaisesRegex(candidate.CandidateError, "unreviewed-artifact-command"):
                authority._artifact_run(("/usr/sbin/jexec", "42", "/usr/local/bin/php", "/source/script.php"),
                    env=candidate.bounded_process.ENV, stdin=b"", timeout=30, output_limit=1000)
            with self.assertRaisesRegex(candidate.CandidateError, "unexpected-artifact-effect"):
                authority.checkpoint(authority.context, "suppress-appstore", "before", "a" * 64)

    def test_numeric_jid_is_rechecked_after_even_a_failed_command(self):
        with self.registry.locked():
            authority = self.authority()
            def changed(*args, **kwargs):
                self.pair[self.config.onlyoffice_jail] = 99
                raise RuntimeError("PRIVATE")
            self.transport.side_effect = changed
            with self.assertRaisesRegex(candidate.CandidateError, "pair-identity-changed"):
                authority.output("/sbin/sysctl", "-n", "hw.pagesize")

    def test_revalidation_ignores_no_saved_eligibility_and_never_begins(self):
        captured = self.collect()
        with self.registry.locked():
            with self.assertRaisesRegex(candidate.CandidateError, "candidate-ineligible-or-stale"):
                candidate.revalidate(captured, self.d, source_admission=self.harness)
            with self.assertRaisesRegex(candidate.CandidateError, "captured-receipt-required"):
                candidate.revalidate({"eligible": True}, self.d, source_admission=self.harness)
        self.begin.assert_not_called()
        self.assertIsNone(self.store.pending())

    def test_revalidation_rehashes_exact_archive_before_native_begin(self):
        captured = self.collect()
        staged = self.fixture.root / (update.STAGING + "/" + OPERATION + "/nextcloud-35.0.2.zip").lstrip("/")
        staged.write_bytes(b"replacement archive")
        with self.registry.locked():
            with self.assertRaisesRegex(candidate.CandidateError, "candidate-revalidation-failed"):
                candidate.revalidate(captured, self.d, source_admission=self.harness)
        self.begin.assert_not_called()

    def test_capture_failure_retains_fixed_blocker_not_private_diagnostics(self):
        with patch.object(candidate, "collect_php", side_effect=ValueError("PRIVATE-ERROR")):
            captured = self.collect()
        data = self.store._bound(captured.reference)
        self.assertNotIn(b"PRIVATE-ERROR", data)
        self.assertIn("runtime-observation-unavailable", json.loads(data)["report"]["blockers"])
        self.begin.assert_not_called()

    def test_original_config_change_is_never_adopted_as_no_integrations(self):
        self.config_output["system"]["objectstore"] = {"PRIVATE": "credentials"}
        captured = self.collect()
        record = json.loads(self.store._bound(captured.reference))
        self.assertEqual(record["observations"], {})
        self.assertIn("runtime-observation-unavailable", record["report"]["blockers"])

    def test_source_signature_failure_never_reaches_fixed_php_or_observation(self):
        self.fixture.pgp = b"[GNUPG:] BADSIG private\n"
        with self.assertRaises(candidate.CandidateError):
            self.collect()
        self.assertFalse(any("-r" in argv and "openssl_verify" in " ".join(argv) for argv, _ in self.calls))
        self.assertFalse(any("status" in argv for argv, _ in self.calls))
        self.begin.assert_not_called()

    def test_catalog_command_allowlist_rejects_package_install_and_foreign_cache(self):
        with self.registry.locked():
            runner = candidate._CatalogRunner(self.authority())
            with self.assertRaises(candidate.CandidateError):
                runner.run("pkg", "install", "php85")
            self.calls.clear()
            with self.assertRaises(candidate.CandidateError):
                runner.run("/usr/bin/env", "-i", "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
                    "LC_ALL=C", "pkg", "-C", "/dev/null", "-o", "REPOS_DIR=/unowned/repos",
                    "-o", "PKG_DBDIR=/unowned/db", "-o", "PKG_CACHEDIR=/unowned/cache", "-o",
                    "ABI=FreeBSD:15:amd64", "-o", "OSVERSION=1501000", "update", "-r", "FreeBSD-ports")
            self.assertEqual(self.calls, [])

    def test_authenticated_local_connector_produces_real_eligible_candidate(self):
        captured = self.collect(connector_archive=self.connector_archive)
        record = json.loads(self.store._bound(captured.reference))
        self.assertTrue(record["report"]["eligible"], record["report"])
        self.assertEqual(record["report"]["blockers"], [])
        self.assertFalse(record["report"]["execution_authorized"])
        self.assertEqual(record["report"], preflight.assess(self.config, self.versions,
            record["observations"], record["repository"], bindings=record["bindings"], now=1000))
        digest = update._hash(self.connector_archive.read_bytes())
        self.assertEqual(record["repository"]["artifacts"]["connector"]["sha256"], digest)
        self.assertEqual(record["observations"]["nextcloud"]["apps"]["onlyoffice"]["artifact_sha256"], digest)
        stage = self.fixture.context.host(update.STAGING + "/" + OPERATION)
        connector = json.loads((stage / "connector-receipt.json").read_bytes())
        self.assertNotEqual(connector["tree_sha256"], digest)
        self.assertEqual(connector["original"], self.config_output["system"]["cloud_installer_connector_auth"])
        self.assertEqual((stage / "connector-receipt.json").stat().st_mode & 0o777, 0o600)
        before = {p.name: p.read_bytes() for p in stage.iterdir() if p.is_file()}
        with self.registry.locked():
            self.assertEqual(candidate.revalidate(captured, self.d, source_admission=self.harness), captured.reference)
        self.assertEqual(before, {p.name: p.read_bytes() for p in stage.iterdir() if p.is_file()})
        self.assertIsNone(self.store.pending())
        self.begin.assert_not_called()
        # The native checker has null persistent stores; the artifact verifier
        # contains no bootstrap, installer call, arbitrary certificate or code.
        self.assertIn("null, null, $factory", candidate._CONNECTOR_INTEGRITY)
        self.assertIn("NullCache", candidate._CONNECTOR_INTEGRITY)
        self.assertNotIn("require", candidate._CONNECTOR_SIGNATURE)
        self.assertNotIn("connector-install", " ".join(" ".join(argv) for argv, _ in self.calls))

    def test_forged_connector_archive_signature_refuses_before_tar_inspection(self):
        original = self.transport.side_effect
        def forged(argv, **kwargs):
            if candidate._CONNECTOR_SIGNATURE in argv:
                return update.NativeResult(1, b"Connector archive verified\n")
            return original(argv, **kwargs)
        self.transport.side_effect = forged
        with patch.object(candidate, "_connector_inventory") as inspect:
            with self.assertRaises(candidate.CandidateError):
                self.collect(connector_archive=self.connector_archive)
            inspect.assert_not_called()
        self.begin.assert_not_called()
        self.assertIsNone(self.store.pending())

    def test_missing_or_mismatched_installed_certificate_precedes_native_checker(self):
        path = self.fixture.context.host(update.APP + "/custom_apps/onlyoffice/appinfo/signature.json")
        signed = json.loads(path.read_bytes())
        signed.pop("certificate")
        self.fixture.write(path, _encode(signed))
        with self.assertRaises(candidate.CandidateError):
            self.collect(connector_archive=self.connector_archive)
        self.assertFalse(any(candidate._CONNECTOR_INTEGRITY in argv for argv, _ in self.calls))
        self.begin.assert_not_called()

    def test_native_empty_success_and_skipped_signature_never_authenticate(self):
        # Exercise the same verifier without recopy/replaying one-shot staging.
        captured = self.collect(connector_archive=self.connector_archive)
        original = self.transport.side_effect
        for output in (b"", b"[]\n", b"onlyoffice: App signature not found, skipping app integrity check\nNo errors found\n"):
            with self.subTest(output=output):
                def unproven(argv, **kwargs):
                    if candidate._CONNECTOR_INTEGRITY in argv:
                        return update.NativeResult(0, output)
                    return original(argv, **kwargs)
                self.transport.side_effect = unproven
                with self.registry.locked():
                    with self.assertRaisesRegex(candidate.CandidateError, "connector-native-integrity-unproven"):
                        candidate.revalidate(captured, self.d, source_admission=self.harness)
        self.begin.assert_not_called()

    def test_missing_signature_file_and_original_receipt_are_not_adopted(self):
        path = self.fixture.context.host(update.APP + "/custom_apps/onlyoffice/appinfo/signature.json")
        path.unlink()
        with self.assertRaises(candidate.CandidateError):
            self.collect(connector_archive=self.connector_archive)
        self.assertFalse(any(candidate._CONNECTOR_INTEGRITY in argv for argv, _ in self.calls))
        self.begin.assert_not_called()

    def test_valid_archive_signature_cannot_adopt_a_different_installed_tree(self):
        self.make_connector(files={**self.connector_files, "lib/app.php": b"different archive bytes"})
        with self.assertRaisesRegex(candidate.CandidateError, "connector-archive-tree-mismatch"):
            self.collect(connector_archive=self.connector_archive)
        self.begin.assert_not_called()

    def test_revalidation_detects_connector_archive_metadata_receipt_and_tree_drift(self):
        captured = self.collect(connector_archive=self.connector_archive)
        stage = self.fixture.context.host(update.STAGING + "/" + OPERATION)
        paths = [stage / name for name in ("onlyoffice-10.2.1.tar.gz", "connector-record.json", "connector-receipt.json")]
        paths.append(self.fixture.context.host(update.APP + "/custom_apps/onlyoffice/lib/app.php"))
        for path in paths:
            before = path.read_bytes()
            try:
                path.write_bytes(b"changed")
                with self.registry.locked():
                    with self.assertRaises(candidate.CandidateError):
                        candidate.revalidate(captured, self.d, source_admission=self.harness)
            finally:
                path.write_bytes(before)
        self.begin.assert_not_called()

    def test_eligible_candidate_still_expires_without_refreshing_capture_age(self):
        captured = self.collect(connector_archive=self.connector_archive)
        with patch.object(candidate.time, "time", return_value=1301), self.registry.locked():
            with self.assertRaisesRegex(candidate.CandidateError, "candidate-ineligible-or-stale"):
                candidate.revalidate(captured, self.d, source_admission=self.harness)
        self.begin.assert_not_called()

    def test_connector_jid_change_during_positive_check_is_refused(self):
        original = self.transport.side_effect
        def changed(argv, **kwargs):
            result = original(argv, **kwargs)
            if candidate._CONNECTOR_INTEGRITY in argv:
                self.pair[self.config.nextcloud_jail] = 99
            return result
        self.transport.side_effect = changed
        with self.assertRaises(candidate.CandidateError):
            self.collect(connector_archive=self.connector_archive)
        self.assertFalse(any(candidate._CONNECTOR_SIGNATURE in argv for argv, _ in self.calls))
        self.begin.assert_not_called()

    def test_mismatched_certificate_and_original_receipt_refuse_without_checker(self):
        with self.registry.locked():
            authority = self.authority()
            record, cert = candidate._connector_record(authority)
            path = self.fixture.context.host(update.APP + "/custom_apps/onlyoffice/appinfo/signature.json")
            original = path.read_bytes()
            changed = json.loads(original)
            changed["certificate"] = "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"other cert").decode() + "\n-----END CERTIFICATE-----\n"
            self.fixture.write(path, _encode(changed))
            with self.assertRaisesRegex(candidate.CandidateError, "connector-certificate-mismatch"):
                candidate._connector_live(authority, record, cert)
            self.fixture.write(path, original)
            self.config_output["system"].pop("cloud_installer_connector_auth")
            # Even a different admitted first-readiness config cannot supply the
            # missing initial installer receipt. This fixture isolates that gate.
            self.original[4]["config:list"] = preflight.digest(dict(system=self.config_output["system"],
                onlyoffice=self.config_output["apps"]["onlyoffice"]))
            with self.assertRaisesRegex(candidate.CandidateError, "original-connector-receipt-mismatch"):
                candidate._connector_live(authority, record, cert)
        self.assertFalse(any(candidate._CONNECTOR_INTEGRITY in argv for argv, _ in self.calls))

    def test_archive_duplicate_traversal_links_pax_special_and_oversize_refuse(self):
        with self.registry.locked():
            tree = maintenance_update._custom(self.authority().context)
        cases = []
        for name in ("onlyoffice/../escape", "/onlyoffice/absolute", "other/file", "onlyoffice/lib/app.php"):
            entry = tarfile.TarInfo(name)
            cases.append(entry)
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.XHDTYPE, tarfile.CHRTYPE):
            entry = tarfile.TarInfo("onlyoffice/unreviewed")
            entry.type, entry.linkname = kind, "onlyoffice/lib/app.php"
            cases.append(entry)
        for entry in cases:
            with self.subTest(name=entry.name, kind=entry.type):
                self.make_connector(extra=entry)
                with self.assertRaises((ValueError, tarfile.TarError)):
                    candidate._connector_inventory(self.connector_archive, tree)
        self.make_connector()
        with patch.object(candidate, "CONNECTOR_FILES", 1):
            with self.assertRaisesRegex(candidate.CandidateError, "unsafe-connector-archive"):
                candidate._connector_inventory(self.connector_archive, tree)

    def test_revalidation_requires_original_private_connector_modes(self):
        captured = self.collect(connector_archive=self.connector_archive)
        stage = self.fixture.context.host(update.STAGING + "/" + OPERATION)
        for name in ("onlyoffice-10.2.1.tar.gz", "connector-record.json", "connector-receipt.json"):
            path = stage / name
            try:
                path.chmod(0o644)
                with self.registry.locked(), self.assertRaises(candidate.CandidateError):
                    candidate.revalidate(captured, self.d, source_admission=self.harness)
            finally:
                path.chmod(0o600)
        self.begin.assert_not_called()


class ProjectionTests(unittest.TestCase):
    def test_source_manifest_and_inventory_retain_exact_original_build_labels(self):
        xml = b'<info><id>files</id><version>3.0.0-dev.0</version></info>'
        self.assertEqual(candidate._manifest(xml, 'files', source=True)['version'], '3.0.0-dev.0')
        with self.assertRaises(candidate.CandidateError):
            candidate._manifest(xml, 'files')
        with self.assertRaises(candidate.CandidateError):
            candidate._manifest(xml.replace(b'dev.0', b'dev.1'), 'files', source=True)
        apps = candidate._app_list({'enabled': {'onlyoffice':'10.2.1','files':'3.0.0-dev.0'}, 'disabled':{}})
        self.assertEqual(apps['files']['version'], '3.0.0-dev.0')
        with self.assertRaises(candidate.CandidateError):
            candidate._app_list({'enabled': {'onlyoffice':'10.2.1','files':'3.0.0-dev.1'}, 'disabled':{}})

    def test_only_empty_array_is_normalized_and_duplicate_apps_fail(self):
        actual = candidate._app_list(dict(enabled={"onlyoffice": "10.2.1"}, disabled=[]))
        self.assertNotIn("artifact_sha256", actual["onlyoffice"])
        for disabled in (["something"], {"onlyoffice": "10.2.1"}, None):
            with self.assertRaises(candidate.CandidateError):
                candidate._app_list(dict(enabled={"onlyoffice": "10.2.1"}, disabled=disabled))

    def test_authenticated_vendor_manifest_defaults_are_exact_core35_policy(self):
        result = candidate._manifest(XML, "serverinfo")
        self.assertEqual(result["phpVersionSpec"], ">=8.3.0 <8.6.0")
        self.assertEqual(result["platformVersionSpec"], ">=35.0.0 <36.0.0")
        explicit = XML.replace(b"<dependencies>", b"<dependencies><php min-version='8.3' max-version='8.4'/>")
        self.assertEqual(candidate._manifest(explicit, "serverinfo")["phpVersionSpec"], ">=8.3.0 <8.5.0")
        for bad in (XML.replace(b"min-version='35'", b"min-version='35rc1'"),
                    b"<!DOCTYPE info [<!ENTITY x 'unsafe'>]>" + XML,
                    XML.replace(b"<dependencies>", b"<dependencies><php min-version='8.3'/><php/>")):
            with self.assertRaises(candidate.CandidateError):
                candidate._manifest(bad, "serverinfo")

    def test_original_observation_age_is_preserved_in_report(self):
        config, versions, observations, repository, bindings = inputs()
        authority = SimpleNamespace(c=config, d=SimpleNamespace(versions=versions), bindings=bindings)
        report = candidate._report(authority, observations, repository, [], 1301)
        self.assertIn("observations-missing-stale-or-unbound", report["blockers"])
        self.assertFalse(report["eligible"])


if __name__ == "__main__":
    unittest.main()
