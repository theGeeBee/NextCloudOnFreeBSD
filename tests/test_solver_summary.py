"""pkg 2.8.4 dry-run text is reviewed, bounded and fail-closed, not generic JSON."""
import unittest

from installer.discovery import check_solver_plan, DiscoveryError


class SolverSummaryTests(unittest.TestCase):
    def summary(self, rows="\tapp-name: 1.2_3,1\n\tdep: .1:2", count=2):
        return (f"The following {count} package(s) will be affected (of 0 checked):\n\n"
                f"New packages to be INSTALLED:\n{rows}\n\n"
                f"Number of packages to be installed: {count}\n\n"
                "The process will require 6 GiB more space.\n1 GiB to be downloaded.\n"
                "The most recent versions of packages are already installed\n")

    def setUp(self):
        self.packages = {"app-name": {"version": "1.2_3,1"}, "dep": {"version": ".1:2"}}

    def test_exact_plan_and_reviewed_annotations(self):
        check_solver_plan(self.summary(), self.packages)
        check_solver_plan(self.summary("\tdep: .1:2 [FreeBSD-ports]\n\tapp-name: 1.2_3,1 (vulnerable!)"), self.packages)
        check_solver_plan("Updating database digests format: . done\n" + self.summary(), self.packages)

    def test_added_missing_changed_and_same_count_substitution(self):
        for rows, count in (("\tapp-name: 1.2_3,1", 1),
                            ("\tapp-name: 1.2_3,1\n\tdep: .1:2\n\tlibuv: 1.52.1", 3),
                            ("\tapp-name: 1.2_3,1\n\tdep: 2", 2),
                            ("\tapp-name: 1.2_3,1\n\tother: .1:2", 2)):
            with self.subTest(rows=rows), self.assertRaisesRegex(DiscoveryError, "differs"):
                check_solver_plan(self.summary(rows, count), self.packages)

    def test_malformed_truncated_or_additional_actions_fail(self):
        valid = self.summary()
        invalid = [None, "", "The most recent versions of packages are already installed",
                   valid[:valid.index("Number of packages")], valid + valid,
                   valid.replace("\tdep: .1:2", "\tapp-name: 1.2_3,1"),
                   valid.replace("\tdep: .1:2", "\tdep: .1:2 [foreign]"),
                   valid.replace("installed: 2", "installed: 3"),
                   valid.replace("following 2", "following 3"),
                   valid + "Unexpected trailer\n", valid + "\tother: 1\n"]
        invalid.extend(valid.replace("New packages to be INSTALLED:", label)
                       for label in ("Installed packages to be UPGRADED:", "Installed packages to be REINSTALLED:",
                                     "Installed packages to be REMOVED:", "Installed packages to be DOWNGRADED:"))
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(DiscoveryError):
                check_solver_plan(text, self.packages)
