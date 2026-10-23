"""FreeBSD 15.1 decimal-byte storage fixtures; no native command execution."""

import unittest
from types import SimpleNamespace

from installer.host import inspect_storage


class StorageInspectionTests(unittest.TestCase):
    def inspect(self, *, pool="105763569664\t17533550592\t88230019072\tONLINE",
                datasets=None, existing=("zroot/cloud-installer", "zroot/cloud-installer/instances")):
        if datasets is None:
            datasets = ("zroot\t17534283776\t84942147584\t434176\t0\t0\t0\t0\t0\n"
                        "zroot/cloud-installer\t14002286592\t84942147584\t98304\t0\t0\t0\t0\t0\n"
                        "zroot/cloud-installer/instances\t1161117696\t84942147584\t98304\t522506240\t0\t0\t0\t0\n")
        calls = []

        class NativeModel:
            def run(self, *args, **kwargs):
                calls.append(args)
                if args[:3] == ("zfs", "list", "-H") and len(args) == 4 and kwargs == {"check": False}:
                    return SimpleNamespace(returncode=0 if args[-1] in existing else 1)
                raise AssertionError(f"Unexpected or mutating command: {args}")

            def output(self, *args):
                calls.append(args)
                if args == ("zpool", "list", "-Hp", "-o", "size,allocated,free,health", "zroot"):
                    return pool
                if args == ("zfs", "list", "-Hp", "-t", "filesystem", "-o",
                            "name,used,available,referenced,usedbysnapshots,quota,refquota,reservation,refreservation",
                            "zroot", *existing):
                    return datasets
                raise AssertionError(f"Unexpected or mutating command: {args}")

        return inspect_storage(NativeModel(), "zroot"), calls

    def test_native_output_keeps_usage_and_snapshot_accounting_separate(self):
        facts, calls = self.inspect()
        self.assertEqual(len(calls), 6)
        self.assertFalse(any("-r" in call for call in calls))
        self.assertEqual(facts["health"], "ONLINE")
        self.assertEqual(facts["allocated"], 17533550592)
        self.assertEqual(facts["datasets"]["zroot"]["available"], 84942147584)
        self.assertNotIn("zroot/usr", facts["datasets"])
        parent = facts["datasets"]["zroot/cloud-installer/instances"]
        self.assertEqual(parent["usedbysnapshots"], 522506240)
        self.assertEqual(parent["quota"], 0)

    def test_fresh_destination_uses_its_own_capacity_without_managed_datasets(self):
        facts, _ = self.inspect(pool="10000 1000 9000 ONLINE",
                               datasets="zroot 1000 8000 100 0 0 0 0 0", existing=())
        self.assertEqual(facts["size"], 10000)
        self.assertEqual(facts["datasets"]["zroot"]["available"], 8000)
        self.assertEqual(set(facts["datasets"]), {"zroot"})

    def test_malformed_or_human_output_is_not_sizing_evidence(self):
        for pool in ("", "98.5G 16.3G 82.2G ONLINE", "1 2 3", "1 2 3 ONLINE extra"):
            with self.subTest(pool=pool), self.assertRaises(ValueError):
                self.inspect(pool=pool)
        for datasets in ("", "zroot 10 20", "zroot 1 2 3 4 none 0 0 0",
                         "zroot 1 2 3 4 0 0 0 0\nzroot 1 2 3 4 0 0 0 0"):
            with self.subTest(datasets=datasets), self.assertRaises(ValueError):
                self.inspect(datasets=datasets)


if __name__ == "__main__":
    unittest.main()
