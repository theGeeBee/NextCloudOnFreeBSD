"""Proof-file decisions using mapped guest state; native Alpine evidence is separate."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import base64
import hashlib
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer.config import Config
from installer.office_vm import prepare_collabora_proof,_rsa_public_spki
from installer.state import Registry


@unittest.skipUnless(Path('/usr/bin/ssh-keygen').is_file(),'OpenSSH keygen unavailable')
class CollaboraProofTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='code-proof-files-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.guest=self.root/'guest-office';self.guest.mkdir(mode=0o700)
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/collabora.json').read_text())
        self.registry=Registry(self.root/'registry');self.registry.initialize()
        self.state=self.registry.instance_path(self.c.instance);self.state.mkdir(mode=0o700)
        self.d=SimpleNamespace(config=self.c,registry=self.registry,state=self.state)
        self.calls=[]
        self.remote=self.enterContext(patch('installer.office_vm.run_native_guest',side_effect=self.guest_program))

    def guest_program(self,d,args,**kwargs):
        self.calls.append((args,kwargs))
        self.assertFalse(any(any(ord(c)<32 for c in value) for value in args))
        code=args[2].replace("Path('/var/lib/cloud-installer/office')",'Path('+repr(str(self.guest))+')')
        code=code.replace('s.st_uid==0','s.st_uid==os.geteuid()').replace('s.st_uid==1001','s.st_uid==os.geteuid()').replace('s.st_gid==1001','s.st_gid==os.getegid()').replace('os.chown(p,1001,1001)','os.chown(p,os.geteuid(),os.getegid())')
        old=os.umask(0o077)
        try:
            with patch('sys.argv',['-',*args[3:]]),redirect_stdout(io.StringIO()) as output:
                exec(compile(code,'mapped-code-proof','exec'),{})
        finally:os.umask(old)
        return SimpleNamespace(returncode=0,stdout=output.getvalue())

    def prepare(self,**kwargs):
        with self.registry.locked():return prepare_collabora_proof(self.d,**kwargs)

    def test_new_pair_native_verification_and_stable_retry_never_return_private_material(self):
        first=self.prepare()
        private=self.guest/'collabora/proof_key';public=self.guest/'collabora/proof_key.pub'
        self.assertEqual(private.stat().st_mode & 0o777,0o600)
        self.assertEqual(public.stat().st_mode & 0o777,0o644)
        self.assertTrue(private.read_text().startswith('-----BEGIN RSA PRIVATE KEY-----'))
        self.assertTrue(public.read_text().startswith('-----BEGIN PUBLIC KEY-----'))
        before=(private.stat().st_ino,private.stat().st_mtime_ns,public.stat().st_mtime_ns)
        self.assertEqual(self.prepare(require_existing=True),first)
        self.assertEqual((private.stat().st_ino,private.stat().st_mtime_ns,public.stat().st_mtime_ns),before)
        self.assertEqual(set(first),{'schema_version','config_sha256','public_sha256','public_key_sha256'})
        self.assertEqual(first['schema_version'],2)
        der=base64.b64decode(''.join(public.read_text().splitlines()[1:-1]),validate=True)
        self.assertEqual(first['public_key_sha256'],hashlib.sha256(der).hexdigest())
        ssh=subprocess.check_output(['/usr/bin/ssh-keygen','-i','-m','PKCS8','-f',str(public)],text=True,stderr=subprocess.DEVNULL)
        wire=base64.b64decode(ssh.split()[1],validate=True);parts=[]
        while wire:
            size=struct.unpack('>I',wire[:4])[0];parts.append(wire[4:4+size]);wire=wire[4+size:]
        self.assertEqual(parts[0],b'ssh-rsa')
        self.assertEqual(_rsa_public_spki(int.from_bytes(parts[2],'big'),int.from_bytes(parts[1],'big')),der)
        self.assertNotIn(private.read_text(),repr(self.calls))
        self.assertFalse(list((self.guest/'collabora').glob('.public-check-*')))

    def test_completed_key_loss_or_public_mode_refuses_without_regeneration(self):
        self.prepare()
        private=self.guest/'collabora/proof_key'
        private.rename(self.root/'retained-private-key')
        with self.assertRaises(AssertionError):self.prepare(require_existing=True)
        self.assertFalse(private.exists())
        (self.root/'retained-private-key').rename(private)
        private.chmod(0o644)
        with self.assertRaises(AssertionError):self.prepare(require_existing=True)
        self.assertEqual(private.stat().st_mode & 0o777,0o644)

    def test_missing_host_receipt_cannot_reconstruct_completed_identity(self):
        with self.assertRaisesRegex(ValueError,'no regeneration'):self.prepare(require_existing=True)
        self.remote.assert_not_called()

    def test_partial_or_unreserved_guest_directory_is_refused_not_reset(self):
        (self.guest/'collabora').mkdir(mode=0o700)
        unrelated=self.guest/'collabora/operator-note';unrelated.write_text('retained')
        with self.assertRaises(OSError):self.prepare()
        self.assertEqual(unrelated.read_text(),'retained')
