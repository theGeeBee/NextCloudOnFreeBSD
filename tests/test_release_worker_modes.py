"""Verified archive script modes cross the trusted jail-helper boundary."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from test_installer import ROOT,archive_module,build_module


class ReleaseWorkerModeTests(unittest.TestCase):
    def guard(self,worker,metadata):
        text=worker.read_text()
        match=re.search(r'case "\$\(stat -f [^\n]+versions\.sh[^\n]+\n.*?\besac',text,re.S)
        self.assertIsNotNone(match)
        script="fail() { exit 1; }; stat() { printf '%s\\n' "+repr(metadata)+"; }; PAYLOAD=/unused\n"+match.group(0)
        return subprocess.run(['sh','-c',script],capture_output=True,text=True).returncode

    def test_verified_release_script_copy_is_accepted_by_both_workers(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);archive=base/'candidate.tar.gz'
            digest=build_module().build_release(ROOT,archive)
            destination=base/'unpacked';destination.mkdir(mode=0o700)
            release=archive_module().verify_and_extract(archive,digest,destination)
            staged=base/'staged-versions.sh';shutil.copy2(release/'resources/jails/versions.sh',staged)
            mode=staged.stat().st_mode&0o7777
            self.assertEqual(mode,0o700)
            for name in ('nextcloud.sh','onlyoffice.sh'):
                with self.subTest(worker=name):
                    self.assertEqual(self.guard(release/'resources/jails'/name,'0:'+format(mode,'o')),0)

    def test_nonroot_or_writable_helpers_still_refuse(self):
        for name in ('nextcloud.sh','onlyoffice.sh'):
            worker=ROOT/'resources/jails'/name
            for metadata in ('1000:700','0:770','0:775','0:777','0:660','0:602','0:1700'):
                with self.subTest(worker=name,metadata=metadata):self.assertNotEqual(self.guard(worker,metadata),0)
            for mode in ('400','444','555','600','644','700','755'):
                with self.subTest(worker=name,mode=mode):self.assertEqual(self.guard(worker,'0:'+mode),0)
