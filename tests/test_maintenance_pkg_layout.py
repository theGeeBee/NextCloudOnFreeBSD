"""Real local files/FD races; only root/mysql ownership is simulated, no chown."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer import maintenance_pkg_layout as layout


class MariaDBPamLayoutTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='pam-layout-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / 'root'
        self.parent = self.root / layout.PAMDIR.lstrip('/')
        self.parent.mkdir(parents=True, mode=0o700)
        self.helper = self.root / layout.PAMFILE.lstrip('/')
        self.helper.write_bytes(b'authenticated synthetic helper\n')
        self.helper.chmod(0o4755)
        (self.root / 'etc').mkdir()
        self.passwd = self.root / 'etc/passwd'
        self.passwd.write_text('root:*:0:0:root:/root:/bin/sh\nmysql:*:88:88:MySQL:/var/db/mysql:/usr/sbin/nologin\n')
        self.passwd.chmod(0o644)
        self.arguments = dict(package_name='mariadb123-server', package_version='12.3.3',
                              package_origin='databases/mariadb123-server')
        self.real_stat, self.real_fstat = os.stat, os.fstat
        self.overrides = {self.key(self.parent): {'st_uid': 88}}
        # Test temp ancestors are not production root-owned deployment paths.
        # Simulate that one environmental boundary, retaining actual fixture modes.
        self.ancestors = {self.key(p) for p in self.root.parents}
        self.enterContext(patch.object(layout.os, 'geteuid', return_value=0))
        self.enterContext(patch.object(layout.os, 'stat', side_effect=lambda *a, **kw: self.info(self.real_stat(*a, **kw))))
        self.enterContext(patch.object(layout.os, 'fstat', side_effect=lambda fd: self.info(self.real_fstat(fd))))

    def key(self, path):
        value = self.real_stat(path, follow_symlinks=False)
        return value.st_dev, value.st_ino

    def info(self, value):
        data = {name: getattr(value, name) for name in (
            'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size',
            'st_mtime_ns', 'st_ctime_ns')}
        data.update(st_uid=0, st_gid=0)
        key = value.st_dev, value.st_ino
        if key in self.ancestors:
            data['st_mode'] &= ~0o022
        data.update(self.overrides.get(key, {}))
        return SimpleNamespace(**data)

    def capture(self, **changes):
        return layout.capture_mariadb_pam(self.root, **(self.arguments | changes))

    def test_exact_reviewed_pair_and_passwd_return_runtime_file_shapes(self):
        observed = self.capture()
        self.assertEqual(set(observed), {layout.PAMDIR, layout.PAMFILE, layout.PASSWD})
        self.assertEqual(observed[layout.PAMDIR], dict(type='directory', uid=88, gid=0, mode=0o700))
        self.assertEqual(observed[layout.PAMFILE], dict(type='file', uid=0, gid=0, mode=0o4755,
            size=self.helper.stat().st_size, sha256=hashlib.sha256(self.helper.read_bytes()).hexdigest()))
        self.assertEqual(observed[layout.PASSWD]['sha256'], hashlib.sha256(self.passwd.read_bytes()).hexdigest())
        self.assertNotIn('mysql', str(observed[layout.PASSWD]))

    def test_wrong_package_version_origin_and_nonroot_caller_refuse(self):
        for changes in ({'package_name': 'other'}, {'package_version': '12.3.4'},
                        {'package_version': '12.3.3_1'}, {'package_origin': 'other/mariadb123-server'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.capture(**changes)
        with patch.object(layout.os, 'geteuid', return_value=80), self.assertRaises(ValueError):
            self.capture()

    def test_wrong_owner_group_modes_and_second_mysql_ancestor_refuse(self):
        cases = ((self.parent, 'st_uid', 0), (self.parent, 'st_gid', 88),
                 (self.parent, 'st_mode', stat.S_IFDIR | 0o750),
                 (self.helper, 'st_uid', 88), (self.helper, 'st_gid', 88),
                 (self.helper, 'st_mode', stat.S_IFREG | 0o755),
                 (self.helper, 'st_mode', stat.S_IFREG | 0o4775),
                 (self.parent.parent, 'st_uid', 88),
                 (self.parent.parent, 'st_mode', stat.S_IFDIR | 0o775),
                 (self.passwd, 'st_uid', 88), (self.passwd, 'st_mode', stat.S_IFREG | 0o666))
        for path, field, value in cases:
            key = self.key(path)
            previous = self.overrides.get(key, {}).copy()
            self.overrides[key] = previous | {field: value}
            with self.subTest(path=path.name, field=field, value=value), self.assertRaises(ValueError):
                self.capture()
            self.overrides[key] = previous

    def test_missing_duplicate_wrong_uid_and_malformed_mysql_account_refuse(self):
        for text in ('root:*:0:0:root:/root:/bin/sh\n',
                     'mysql:*:89:88:MySQL:/var/db/mysql:/usr/sbin/nologin\n',
                     'mysql:*:88:88:MySQL:/var/db/mysql:/usr/sbin/nologin\n' * 2,
                     'mysql:*:88:88\n'):
            self.passwd.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.capture()

    def test_symlink_root_parent_and_leaf_refuse(self):
        alias = self.root.parent / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            layout.capture_mariadb_pam(alias, **self.arguments)
        saved = self.parent.with_name('saved-parent')
        self.parent.rename(saved)
        self.parent.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.capture()
        self.parent.unlink()
        saved.rename(self.parent)
        saved_file = self.root / 'saved-helper'
        self.helper.rename(saved_file)
        self.helper.symlink_to(saved_file)
        with self.assertRaises(ValueError):
            self.capture()

    def test_hardlink_extra_child_and_passwd_size_bound_refuse(self):
        alias = self.root / 'helper-alias'
        os.link(self.helper, alias)
        with self.assertRaises(ValueError):
            self.capture()
        alias.unlink()
        extra = self.parent / 'unexpected'
        extra.write_bytes(b'x')
        with self.assertRaises(ValueError):
            self.capture()
        extra.unlink()
        with self.passwd.open('wb') as stream:
            stream.truncate(1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            self.capture()

    def test_changed_helper_and_passwd_hashes_are_observations_not_adoption(self):
        original = self.capture()
        self.helper.write_bytes(b'changed fixture helper\n')
        self.helper.chmod(0o4755)
        changed = self.capture()
        self.assertNotEqual(changed[layout.PAMFILE]['sha256'], original[layout.PAMFILE]['sha256'])
        self.passwd.write_text(self.passwd.read_text() + 'other:*:90:90:Other:/nonexistent:/usr/sbin/nologin\n')
        self.assertNotEqual(self.capture()[layout.PASSWD]['sha256'], original[layout.PASSWD]['sha256'])
        self.assertEqual(original[layout.PAMDIR], changed[layout.PAMDIR])

    def race(self, mutate):
        read = os.read
        helper_key = self.key(self.helper)
        fired = []
        def changed(fd, length):
            data = read(fd, length)
            value = self.real_fstat(fd)
            if (value.st_dev, value.st_ino) == helper_key and not fired:
                fired.append(True)
                mutate()
            return data
        with patch.object(layout.os, 'read', side_effect=changed), self.assertRaises(ValueError):
            self.capture()
        self.assertEqual(fired, [True])

    def test_named_parent_replacement_during_fd_read_refuses(self):
        def replace():
            saved = self.parent.with_name('moved-parent')
            self.parent.rename(saved)
            self.parent.symlink_to(saved, target_is_directory=True)
        self.race(replace)

    def test_leaf_replacement_during_fd_read_refuses(self):
        def replace():
            self.helper.rename(self.root / 'moved-helper')
            self.helper.write_bytes(b'other inode\n')
            self.helper.chmod(0o4755)
        self.race(replace)

    def test_inplace_leaf_change_during_fd_read_refuses(self):
        self.race(lambda: self.helper.write_bytes(b'changed while open\n'))


if __name__ == '__main__':
    unittest.main()
