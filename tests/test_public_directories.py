"""Public mount ancestors must remain traversable under the private entrypoint umask."""

import os
from pathlib import Path
import tempfile
import unittest

from installer.deploy import public_directories


class PublicDirectoryTests(unittest.TestCase):
    def test_workers_create_repository_ancestors_with_public_umask(self):
        root = Path(__file__).resolve().parents[1]
        for worker in ("nextcloud", "onlyoffice"):
            source = (root / "resources/jails" / (worker + ".sh")).read_text()
            lines = [line.strip() for line in source.splitlines()
                     if "install -d" in line and "/usr/local/etc/pkg/repos" in line]
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].startswith("(umask 022; install -d"))
            self.assertTrue(lines[0].endswith(")"))

    def test_new_ancestors_are_public_but_existing_modes_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            previous = os.umask(0o077)
            try:
                target = root / "usr/local/www/nextcloud"
                public_directories(target, root)
            finally:
                os.umask(previous)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            for path in (target, *list(target.parents)[:3]):
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            target.chmod(0o750)
            public_directories(target, root)
            self.assertEqual(target.stat().st_mode & 0o777, 0o750)

    def test_symlinks_escape_and_files_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "link").symlink_to(root, target_is_directory=True)
            (root / "file").write_text("keep")
            for target in (root / "link/child", root / "../outside", root / "file/child"):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    public_directories(target, root)
            with self.assertRaises(ValueError):
                public_directories(root / "link/child", root / "link")
            self.assertEqual((root / "file").read_text(), "keep")
