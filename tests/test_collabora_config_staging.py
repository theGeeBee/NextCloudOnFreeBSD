"""Actual mapped public-file staging; no guest, container or TLS bypass."""
from contextlib import redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer.config import Config
from installer.office_vm import prepare_collabora_configuration
from installer.state import Registry,config_digest
from test_collabora_configuration import XML


class CollaboraConfigStagingTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='code-public-files-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.guest=self.root/'guest-collabora'
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/collabora.json').read_text())
        self.registry=Registry(self.root/'registry');self.registry.initialize()
        self.state=self.registry.instance_path(self.c.instance);self.state.mkdir(mode=0o700)
        self.d=SimpleNamespace(config=self.c,state=self.state,registry=self.registry,versions={})
        self.default=self.enterContext(patch('installer.office_vm.collabora_default_configuration',return_value=XML))
        self.enterContext(patch('installer.office_vm.collabora_container_arguments',return_value={'configuration_sha256':hashlib.sha256(XML.encode()).hexdigest()}))
        self.proof=self.enterContext(patch('installer.office_vm.prepare_collabora_proof',side_effect=self.prepare_proof))
        self.remote=self.enterContext(patch('installer.office_vm.run_native_guest',side_effect=self.guest_program))

    def prepare_proof(self,*args,**kwargs):
        if not self.guest.exists():
            self.guest.mkdir(mode=0o700)
            identity=self.guest/'identity.json';identity.write_text(json.dumps({'schema_version':1,'config_sha256':config_digest(self.d.config),'kind':'collabora-proof'}));identity.chmod(0o600)

    def guest_program(self,d,args,**kwargs):
        self.assertEqual(set(json.loads(kwargs['input'])),{'xml','ca'})
        self.assertFalse(any(any(ord(c)<32 for c in value) for value in args))
        code=args[2].replace("Path('/var/lib/cloud-installer/office/collabora')",'Path('+repr(str(self.guest))+')').replace('s.st_uid==0','s.st_uid==os.geteuid()')
        old=os.umask(0o077)
        try:
            with patch('sys.argv',['-',*args[3:]]),patch('sys.stdin',io.StringIO(kwargs['input'])),redirect_stdout(io.StringIO()) as out:
                exec(compile(code,'mapped-code-public-files','exec'),{})
        finally:os.umask(old)
        return SimpleNamespace(returncode=0,stdout=out.getvalue())

    def prepare(self,**kwargs):
        with self.registry.locked():return prepare_collabora_configuration(self.d,**kwargs)

    def test_public_xml_is_service_readable_hash_bound_and_retry_preserves_bytes(self):
        first=self.prepare();xml=self.guest/'coolwsd.xml'
        self.assertEqual(xml.stat().st_mode & 0o777,0o644)
        self.assertIn('<ssl_verification>true</ssl_verification>',xml.read_text())
        self.assertEqual(hashlib.sha256(xml.read_bytes()).hexdigest(),first['xml_sha256'])
        before=xml.stat().st_mtime_ns
        self.assertEqual(self.prepare(require_existing=True),first)
        self.assertEqual(xml.stat().st_mtime_ns,before)
        self.default.assert_called_with(self.d,require_existing=True)
        self.proof.assert_called_with(self.d,require_existing=True)
        self.assertNotIn('private',json.dumps(first))

    def test_completed_public_file_loss_or_content_change_refuses_repair(self):
        self.prepare();xml=self.guest/'coolwsd.xml';xml.rename(self.root/'retained-xml')
        with self.assertRaises(AssertionError):self.prepare(require_existing=True)
        self.assertFalse(xml.exists())
        (self.root/'retained-xml').rename(xml);xml.write_text('operator-change')
        with self.assertRaises(AssertionError):self.prepare(require_existing=True)
        self.assertEqual(xml.read_text(),'operator-change')

    def test_public_ca_staged_readonly_ready_and_private_key_input_refused(self):
        ca=self.root/'public-ca.pem';ca.write_text('-----BEGIN CERTIFICATE-----\npublic-fixture\n')
        self.d.config=replace(self.c,ca_file=str(ca))
        record=self.prepare();native=self.guest/'nextcloud-ca.pem'
        self.assertEqual(native.read_text(),ca.read_text());self.assertEqual(native.stat().st_mode & 0o777,0o644)
        self.assertEqual(record['ca_sha256'],hashlib.sha256(ca.read_bytes()).hexdigest())

    def test_private_key_or_missing_completed_receipt_fails_before_guest_write(self):
        with self.assertRaisesRegex(ValueError,'no reconstruction'):self.prepare(require_existing=True)
        self.remote.assert_not_called()
        ca=self.root/'private-in-ca.pem';ca.write_text('-----BEGIN PRIVATE KEY-----\nsecret-canary\n')
        self.d.config=replace(self.c,ca_file=str(ca))
        with self.assertRaisesRegex(ValueError,'never a private key'):self.prepare()
        self.proof.assert_not_called();self.remote.assert_not_called()
