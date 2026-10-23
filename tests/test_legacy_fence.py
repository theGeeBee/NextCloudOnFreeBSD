"""Offline evidence for the lifecycle registration's historical-reader fence.

Reviewed 2026-10-15, using git show at development time only. The strings below
retain the complete historical main() and the exact Config field declarations,
Config.from_json(), private_json(), and Registry read methods. They are compiled
in an isolated module with native/UI/mutation boundaries replaced by tripwires.
Config validation beyond from_json's unknown-field check is deliberately absent;
these excerpts are refusal fixtures, not historical deployment implementations.
No Git, old checkout, network, root privileges, or native commands are required.

Source evidence (SHA-256 of the original complete files):
4194baa5757ddd4bff5d430a6621be50a5b6ee8f:
  installer/config.py e3bdb472c38a08f4f548fc66dde8dee57df5b4faf8862b676d389f3059466a0f
  installer/main.py   419b3d98e16518fcf8542267ac2f60e57c8c632df2b2d7a378518f4c87a968ea
cf6433057e2d09eb70838803ae88fa901454b81a:
  installer/config.py c81c9be3721cdc21eb0169a44b33c150f01ca4ce39e118ce29fdbc3d4547dd9c
  installer/main.py   419b3d98e16518fcf8542267ac2f60e57c8c632df2b2d7a378518f4c87a968ea
71c3bc15b412c6007ebb02c2bc64b21ef77320cd:
  installer/config.py c81c9be3721cdc21eb0169a44b33c150f01ca4ce39e118ce29fdbc3d4547dd9c
  installer/main.py   1ac15a4f11966671a3dd9772e3c6b9a524687bcc598c00aa37ed472939fe3797
All three installer/state.py:
  181e87c14ef49454c83e24568ac607878ebe5d02a416c1ef34f782cf5aa6d9ed

Scope: explicit Python commands against instances/NAME/config.json. Historical
install/configure probe the host before reading the registry; those read-only
probes and the operation lock are mocked. No claim of zero preliminary writes,
shell-bootstrap refusal, arbitrary-root isolation, or native FreeBSD acceptance.
Historical install.sh can bootstrap pkg/Python before Python reads this file.
Historical recover-network follows transaction state without loading Config and
is NOT fenced by the descriptor (covered below with a mocked recovery call).
Old entrypoints must therefore remain unsupported after lifecycle registration.
"""

import argparse
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, fields
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.config import Config


REVISIONS = ("4194baa", "cf64330", "71c3bc1")
REFUSAL = r"^Unknown configuration fields \(secrets belong in the separate secret file\)$"

# The descriptor API is not finalized: this is the proposed public wire shape,
# intentionally independent of any new descriptor loader or lifecycle helpers.
DESCRIPTOR = {
    "schema_version": 1,
    "record_type": "lifecycle-registration",
    "instance": "cloud",
    "generation": 1,
    "manifest_sha256": "a" * 64,
}

# Exact 4194baa field declarations and from_json, excluding unrelated methods.
CONFIG_SOURCE = '''@dataclass
class Config:
    schema_version: int = SCHEMA_VERSION
    instance: str = "cloud"
    pool: str = "zroot"
    public_hostname: str = ""
    nextcloud_hostname: str = ""
    onlyoffice_hostname: str = ""
    admin_username: str = "admin"
    admin_email: str = ""
    timezone: str = "UTC"
    repository: str = "latest"
    external_interface: str = ""
    ingress_address: str = ""
    dns_address: str = ""
    private_network: str = "10.77.0.0/29"
    nextcloud_bridge: str = "bridge240"
    onlyoffice_bridge: str = "bridge241"
    dns_server: str = ""
    management_network: str = ""
    management_port: int = 22
    http_port: int = 80
    https_port: int = 443
    public_https_port: int = 443
    tls_mode: str = "acme"
    proxy_networks: str = ""
    acme_email: str = ""
    certificate_file: str = ""
    private_key_file: str = ""
    ca_file: str = ""
    jail_ssh: bool = False
    ssh_username: str = "cloudop"
    ssh_key_file: str = ""
    ssh_nextcloud_port: int = 2201
    ssh_onlyoffice_port: int = 2202
    ssh_shell: str = "sh"
    ssh_admin: bool = False
    font_profile: str = "comprehensive"
    accept_microsoft_fonts: bool = False
    additional_fonts_dir: str = ""
    data_quota_gib: int = 100
    database_quota_gib: int = 20
    temporary_quota_gib: int = 10
    office_quota_gib: int = 10
    logs_quota_gib: int = 5
    system_quota_gib: int = 32
    host_reserved_mb: int = 2048
    office_memory_mb: int = 3072
    php_budget_mb: int = 1536
    php_memory_mb: int = 512
    db_buffer_mb: int = 768
    redis_memory_mb: int = 128
    upload_max_mb: int = 1024
    # Empty additions are omitted on serialization to preserve schema-2 digests.
    freebsd_release: str = ""
    architecture: str = ""
    nextcloud_min: str = ""
    onlyoffice_min: str = ""
    nextcloud_exact: str = ""
    onlyoffice_exact: str = ""

    @classmethod
    def from_json(cls, text):
        value = json.loads(text)
        if not isinstance(value, dict) or set(value) - {field.name for field in fields(cls)}:
            raise ValueError("Unknown configuration fields (secrets belong in the separate secret file)")
        config = cls(**value)
        if not any(key in value for key in ("freebsd_release", "architecture", "nextcloud_min", "onlyoffice_min", "nextcloud_exact", "onlyoffice_exact")):
            from .versions import load_policy
            config._legacy_target = load_policy()["legacy_target"]
        return config.validate()
'''

# Exact read functions, identical in all three revisions. Write/lock methods are
# not retained: the test supplies a temporary registry and a null operation lock.
STATE_SOURCE = '''def private_json(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError(f"Expected an owner-only regular state file: {path}")
    return json.loads(path.read_text())


class Registry:
    def __init__(self, root=STATE_DIR):
        self.root = Path(root)

    def instance_path(self, instance):
        if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", instance):
            raise ValueError("Invalid instance identifier")
        return self.root / "instances" / instance

    def load(self, instance):
        path = self.instance_path(instance)
        if not path.is_dir() or path.is_symlink():
            raise ValueError(f"Unknown instance: {instance}")
        config = Config.from_json(json.dumps(private_json(path / "config.json")))
        if config.instance != instance:
            raise ValueError("Instance identity does not match its registry directory")
        journal = path / "deployment.json"
        if journal.exists() and private_json(journal).get("config_sha256") != config_digest(config):
            raise ValueError("A registered deployment's immutable configuration/schema changed")
        return config

    def entries(self, *, include_removed=False):
        directory = self.root / "instances"
        if not directory.exists():
            return []
        entries = []
        for path in sorted(directory.iterdir()):
            if path.name.startswith(".pending-"):
                continue  # Interrupted unpublished registration, never an active instance.
            config = self.load(path.name)
            status = private_json(path / "status.json")
            if include_removed or status["state"] != "removed":
                entries.append((config, status))
        return entries

    def host(self):
        path = self.root / "host.json"
        return private_json(path) if path.exists() else None
'''

# Complete, unmodified main() from 4194baa and cf64330. Keep a raw string so
# historical string escapes survive verbatim in the compiled fixture.
MAIN_SOURCE = r'''def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    plain = "--plain" in argv
    argv = [value for value in argv if value != "--plain"]
    aliases = {"--plan": "plan", "--configure-only": "configure", "--verify": "verify"}
    if argv and argv[0] in aliases:
        argv[0] = aliases[argv[0]]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plain", action="store_true", help="Use numbered terminal prompts instead of bsddialog")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("install", help="Configure and install an additional instance")
    commands.add_parser("configure", help="Save a new configuration without provisioning")
    commands.add_parser("list", help="List registered instances")
    commands.add_parser("recover-network", help="Recover an expired/reboot-interrupted unconfirmed PF transaction")
    for name in ("resume", "status", "verify", "add-user", "recover-install"):
        commands.add_parser(name).add_argument("instance")
    remove = commands.add_parser("remove", help="Remove jail roots/networking; retain application datasets by default")
    remove.add_argument("instance")
    remove.add_argument("--purge-data", action="store_true", help="Also permanently destroy instance datasets and snapshots")
    backup = commands.add_parser("backup", help="Consistent full database/configuration backup, including every user's DAV data")
    backup.add_argument("instance")
    backup.add_argument("--output", type=Path)
    restore = commands.add_parser("restore", help="Restore a compatible database/configuration backup; explicit confirmation required")
    restore.add_argument("instance")
    restore.add_argument("backup", type=Path)
    commands.add_parser("plan", help="Offline, read-only plan validation").add_argument("config", type=Path)
    resolution = commands.add_parser("resolve", help="Inspect version compatibility without installing or upgrading")
    resolution.add_argument("config", type=Path)
    resolution.add_argument("--metadata", type=Path, help="Use saved discovery metadata for offline assessment only")
    resolution.add_argument("--installed", type=Path, help="Compare a retained version lock; report only, never execute an upgrade")
    args = parser.parse_args(argv)
    if args.command == "plan":
        print(deployment_plan(Config.from_json(args.config.read_text())))
        return 0
    if args.command == "resolve":
        from .discovery import discover, probe_packages
        from .resolution import resolve, assess_upgrade
        config = Config.from_json(args.config.read_text())
        if args.metadata:
            if args.metadata.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Saved discovery metadata exceeds its size limit")
            metadata = json.loads(args.metadata.read_text())
        else:
            runner = Runner()
            require_host(runner)
            metadata = discover(config, runner)
        selected = resolve(config, metadata)
        if not args.metadata:
            probe_packages(config, selected, runner)
        if args.installed:
            if args.installed.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Installed version lock exceeds its size limit")
            assessment = assess_upgrade(json.loads(args.installed.read_text()), selected)
            print(json.dumps({"plan": selected, "upgrade_assessment": assessment}, indent=2, sort_keys=True))
        else:
            print(json.dumps(selected, indent=2, sort_keys=True))
        return 0
    runner = Runner()
    require_host(runner)
    registry, ui = Registry(), TerminalUI(plain=plain)
    if args.command in ("list", "status"):
        show_status(registry, getattr(args, "instance", None))
        return 0
    if args.command not in ("verify", "backup") and not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError("An interactive terminal is required for configuration, secrets and destructive-operation approval")
    with registry.locked():
        if args.command is None:
            args = menu(ui, registry)
        from .firewall import pending_transactions, recover_pending
        pending = pending_transactions(registry.root)
        if args.command == "recover-network":
            if not pending:
                ui.message("No unconfirmed network transactions need recovery.")
                return 0
            if len(pending) != 1:
                raise ValueError("Multiple unconfirmed network transactions require console review; their restoration order cannot be guessed")
            ui.message("This restores the prior managed PF/network configuration and removes only unconfirmed new bridges.\n"
                       "Keep console access available. Live/in-progress transactions are refused; instance data is not changed.")
            if ui.input("Type RECOVER to restore the preceding network policy") != "RECOVER":
                ui.message("No recovery changes applied.")
                return 0
            boot = runner.output("sysctl", "-n", "kern.boottime")
            for transaction in reversed(pending):
                recover_pending(transaction, boot)
            ui.message("Network recovery completed. Use Resume for the affected instance.")
            return 0
        if pending and args.command not in ("list", "status"):
            raise ValueError("An unconfirmed network transaction remains. Allow its watchdog to finish, or use recover-network after expiry/reboot")
        if args.command == "list":
            show_status(registry)
            return 0
        if args.command in ("install", "configure"):
            facts = inspect_host(runner)
            wizard_facts = {**facts, "managed_host": registry.host(),
                            "reserved_instances": [config.instance for config, _ in registry.entries(include_removed=True)]}
            existing = [config for config, _ in registry.entries()]
            config = None
            while True:
                config = configure(wizard_facts, config, registered=existing, ui=ui)
                try:
                    preflight(config, facts, runner, registry=registry)
                except (ValueError, RuntimeError, OSError) as error:
                    ui.message(f"Preflight failed: {error}")
                    if ui.confirm("Return to configuration with these values preserved?"):
                        continue
                    return 1
                break
            credentials = create_secrets(ui=ui)
            state = registry.save_new(config, credentials)
            ui.message(f"Configuration and generated credentials saved privately on the host: {state}")
            if args.command == "configure":
                ui.message(f"No deployment resources changed. Use: sh install.sh resume {config.instance}")
                return 0
        else:
            config = registry.load(args.instance)
            state = registry.instance_path(config.instance)
            status = private_json(state / "status.json")["state"]
            if args.command == "status":
                show_status(registry, config.instance)
                return 0
            if args.command in ("resume", "verify", "backup", "restore", "add-user", "recover-install") and status in ("removed", "removing"):
                raise ValueError("Instance is removed/removing; only removal continuation and retained-data inspection are allowed")
            if args.command in ("verify", "backup", "restore", "add-user") and status != "ready":
                raise ValueError("This operation requires a completed instance; resume its installation first")
            restore_journal = state / "restore.json"
            if (args.command in ("verify", "backup", "add-user") and restore_journal.exists()
                    and private_json(restore_journal).get("state") == "pending"):
                raise ValueError("A database restore is pending; correct its cause and repeat Restore with the same trusted backup before other operations")
            if args.command == "resume" and status == "ready":
                raise ValueError("Instance is already ready; use Verify instead of replaying its installation")
            credentials = load_secrets(state / "secrets.json")
            facts = inspect_host(runner) if args.command in ("resume", "remove") else {}
        deployment = Deployment(config, credentials, runner, facts.get("ssh_connection"), registry=registry, progress=ui.progress)
        if args.command in ("install", "resume"):
            if args.command == "resume":
                preflight(config, facts, runner, registry=registry, resume=True)
            ui.message("\n" + deployment_plan(config))
            selected = deployment.prepare_versions()
            ui.message("Resolved immutable version plan (no upgrades applied):\n" + json.dumps(selected, indent=2, sort_keys=True))
            ui.message("This changes host storage/networking and creates or resumes two jails. Keep console access available.\n"
                       "Each PF transition needs a timed KEEP after checking a second SSH session. Application data is never reset on retry.")
            if ui.input("Type APPLY to proceed") != "APPLY":
                ui.message("Saved only; no provisioning performed.")
                return 0
            deployment.apply()
            ui.message(f"\nInstaller checks passed. Login: {config.public_url}\nAdministrator: {config.admin_username}\n"
                       f"Credentials: {state / 'secrets.json'} (host-only; not printed).")
            ui.message("External HTTPS/proxy routing, browser editing/save and reboot acceptance still need testing.\n"
                       "SMTP delivery is disabled; schedule and test backups before production use.")
            if ui.confirm("Create an additional non-admin Nextcloud user now?"):
                add_user(ui, deployment)
        elif args.command == "verify":
            deployment.verify()
            deployment.checkpoint()
            ui.message("Local service, mount, transport and connector checks passed. External/browser/reboot acceptance remains separate.")
        elif args.command == "recover-install":
            from .initialization import recover_initialization
            deployment.verify_source()
            ui.message("This resets an interrupted, unpublished Nextcloud initialization to its quiesced app/data/database checkpoint.\n"
                       "Partial initialization data will be lost. Published/completed installations are refused.\n"
                       "No other instance is changed; a partial rollback leaves this jail stopped for recovery.")
            phrase = ui.input(f"Type RESET-INITIALIZATION {config.instance} to continue")
            recover_initialization(deployment, confirmation=phrase)
            ui.message(f"Initialization checkpoint restored. Continue with: sh install.sh resume {config.instance}")
        elif args.command == "backup":
            from .operations import backup_database
            ui.message("Backing up the complete database and application configuration. User file contents are NOT included.")
            path = backup_database(deployment, getattr(args, "output", None))
            ui.message(f"Backup complete: {path}")
        elif args.command == "restore":
            from .operations import restore_database
            ui.message("RESTORE replaces every user's database state, including contacts/calendars, and restores app configuration.\n"
                       "It does not restore user files. Use a matching file backup; incompatible versions are refused.\n"
                       "A pre-restore backup is retained. A failed import leaves maintenance enabled for recovery.")
            phrase = ui.input(f"Type RESTORE {config.instance} to continue")
            restore_database(deployment, args.backup, confirmation=phrase)
            ui.message("Database/configuration restored. Validate calendars, contacts and matching user files before reopening access.")
        elif args.command == "add-user":
            add_user(ui, deployment)
        elif args.command == "remove":
            from .lifecycle import remove_instance
            purge = args.purge_data
            ui.message("This stops the instance and removes its jail roots, private bridges and firewall access.\n"
                       + ("ALL instance application datasets and their snapshots will be permanently destroyed.\n" if purge else
                          "Application datasets are retained for manual recovery; removing a jail is not a backup.\n")
                       + "Other instances, shared Bastille releases, host credentials and existing backups are retained.")
            phrase = ("PURGE " if purge else "REMOVE ") + config.instance
            remove_instance(deployment, purge_data=purge, confirmation=ui.input(f"Type {phrase} to continue"))
            ui.message("Instance removed. Its name stays reserved in the audit registry; retained backup/credential files remain private.")
    return 0
'''


def historical_sources(revision):
    """Reconstruct exact excerpts; deduplicate the unchanged historical text."""
    config, main = CONFIG_SOURCE, MAIN_SOURCE
    if revision != "4194baa":
        config = config.replace('    onlyoffice_exact: str = ""\n',
                                '    onlyoffice_exact: str = ""\n    onlyoffice_plugins: str = ""\n')
    if revision == "71c3bc1":
        main = main.replace('    args = parser.parse_args(argv)\n', '''    updates = commands.add_parser("check-updates", help="Inspect retained update reports; refresh metadata only when requested")
    updates.add_argument("instance", nargs="?")
    updates.add_argument("--all", action="store_true", help="Assess all registered non-removed instances")
    updates.add_argument("--refresh", action="store_true", help="Read current upstream/signed catalog metadata; never install")
    updates.add_argument("--save-report", action="store_true", help="Explicitly save refreshed results in private host state")
    updates.add_argument("--json", action="store_true", help="Print the structured report")
    args = parser.parse_args(argv)
    if args.command == "check-updates":
        if args.instance and args.all:
            parser.error("Choose one instance or --all, not both")
        if args.instance and not re.fullmatch(r"[a-z][a-z0-9]{0,7}", args.instance):
            parser.error("Invalid instance name")
        if args.save_report and not args.refresh:
            parser.error("--save-report requires --refresh; viewing cached reports never writes")
''')
        main = main.replace('args.command not in ("verify", "backup")',
                            'args.command not in ("verify", "backup", "check-updates")')
        main = main.replace('''    with registry.locked():
        if args.command is None:
            args = menu(ui, registry)
''', '''    if args.command is None:
        from .dashboard import snapshot, render
        from .updates import check_updates
        view = snapshot(registry)
        names = [row["instance"] for row in view["instances"] if not row["error"] and row["state"] != "removed"]
        reports = check_updates(registry, names) if names else None
        ui.message(render(view, host_release=runner.output("freebsd-version", "-u"), updates=reports))
        args = menu(ui, registry, view=view)
        if args.command in ("install", "configure", "resume"):
            return launch_selected_install(args, plain=plain)
    if args.command in ("list", "status"):
        show_status(registry, getattr(args, "instance", None))
        return 0
    if args.command == "check-updates":
        return show_updates(args, registry, runner, ui)
    with registry.locked():
''')
    return config, main


@contextmanager
def historical_reader(revision, root):
    """Run authentic reader/control flow, never a historical host implementation."""
    package = ModuleType("_legacy_fence_fixture")
    package.__path__ = []
    module = ModuleType(package.__name__ + ".main")
    module.__package__ = package.__name__
    module.__dict__.update(
        argparse=argparse, json=json, os=os, stat=stat, re=re, Path=Path,
        dataclass=dataclass, fields=fields, SCHEMA_VERSION=2, STATE_DIR=root,
        sys=SimpleNamespace(argv=[], stdin=SimpleNamespace(isatty=lambda: True),
                            stdout=SimpleNamespace(isatty=lambda: True)))
    modules = {package.__name__: package, module.__name__: module}
    traps = {}

    def tripwire(name):
        trap = Mock(name=name, side_effect=AssertionError("Unexpected historical boundary: " + name))
        traps[name] = trap
        return trap

    for name, functions in {
        "firewall": ("recover_pending",),
        "operations": ("backup_database", "restore_database"),
        "lifecycle": ("remove_instance",),
        "initialization": ("recover_initialization",),
        "versions": ("load_policy",),
    }.items():
        dependency = ModuleType(package.__name__ + "." + name)
        for function in functions:
            setattr(dependency, function, tripwire(name + "." + function))
        modules[dependency.__name__] = dependency
    firewall = modules[package.__name__ + ".firewall"]
    firewall.pending_transactions = Mock(return_value=[])
    runner = SimpleNamespace(run=tripwire("Runner.run"), output=tripwire("Runner.output"))
    ui = SimpleNamespace(**{name: tripwire("UI." + name)
                            for name in ("input", "confirm", "message", "progress")})
    module.Runner = Mock(return_value=runner)
    module.TerminalUI = Mock(return_value=ui)
    module.require_host = Mock()
    module.inspect_host = Mock(return_value={})
    for name in ("Deployment", "preflight", "configure", "create_secrets", "load_secrets",
                 "deployment_plan", "add_user", "config_digest", "show_status", "menu",
                 "launch_selected_install", "show_updates"):
        setattr(module, name, tripwire(name))
    with patch.dict(sys.modules, modules):
        config, main = historical_sources(revision)
        for label, source in (("config", config), ("state", STATE_SOURCE), ("main", main)):
            exec(compile(source, f"<legacy:{revision}:installer/{label}.py>", "exec"), module.__dict__)
        module.Config.validate = tripwire("Config.validate")
        module.Registry.locked = lambda self: nullcontext()
        module.Registry.save_new = tripwire("Registry.save_new")
        module.private_json = Mock(wraps=module.private_json)
        yield module, traps, firewall, runner, ui


class LegacyFenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "instances" / "cloud" / "config.json"
        self.path.parent.mkdir(parents=True, mode=0o700)
        self.path.write_text(json.dumps(DESCRIPTOR))
        self.path.chmod(0o600)

    def test_retained_source_matches_reviewed_excerpts(self):
        # Hash complete main(), not a hand-written model of its dispatch order.
        self.assertEqual(hashlib.sha256(CONFIG_SOURCE.encode()).hexdigest(),
                         "37842867803a5d642333da6513575cce413060e439779a11e89729880eeac6e7")
        self.assertEqual(hashlib.sha256(STATE_SOURCE.encode()).hexdigest(),
                         "eccaff855ce2bc418fbd75c60c065c97cce0dc68de6914eb337ca3b55ab06c3f")
        for revision in REVISIONS:
            with self.subTest(revision=revision):
                config, main = historical_sources(revision)
                config_hash = ("37842867803a5d642333da6513575cce413060e439779a11e89729880eeac6e7"
                               if revision == "4194baa" else
                               "e709f2f640aad8828593fc3b538e33fe1478be64c9edaa7903cc0442ca0bc052")
                self.assertEqual(hashlib.sha256(config.encode()).hexdigest(), config_hash)
                expected = ("2956ad7c53ef2ff292eda132dec4da1fe439b2415504ec2c0b44ded980b88686"
                            if revision == "71c3bc1" else
                            "b7180d0dce31e6e88fd65fa3a35170f583031f362136ca614204e0008b3dff70")
                self.assertEqual(hashlib.sha256(main.encode()).hexdigest(), expected)

    def test_current_config_rejects_registration_descriptor(self):
        with self.assertRaisesRegex(ValueError, REFUSAL):
            Config.from_json(self.path.read_text())

    def test_descriptor_fields_are_independently_unknown_even_with_schema_two(self):
        for key in ("record_type", "generation", "manifest_sha256"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, REFUSAL):
                Config.from_json(json.dumps({"schema_version": 2, key: DESCRIPTOR[key]}))

    def test_historical_config_readers_reject_descriptor_before_validation(self):
        for revision in REVISIONS:
            with self.subTest(revision=revision), historical_reader(revision, self.root) as (old, traps, *_):
                with self.assertRaisesRegex(ValueError, REFUSAL):
                    old.Config.from_json(self.path.read_text())
                for trap in traps.values():
                    trap.assert_not_called()
                # Control: the authentic loader does accept known field names
                # and reaches validation, which this bounded fixture omits.
                with self.assertRaisesRegex(AssertionError, "Config.validate"):
                    old.Config.from_json('{"schema_version": 2, "freebsd_release": "15.1-RELEASE"}')

    def test_historical_python_commands_refuse_before_mutation_boundaries(self):
        commands = (
            ("install",), ("configure",), ("--configure-only",),
            ("resume", "cloud"), ("remove", "cloud"), ("remove", "cloud", "--purge-data"),
            ("restore", "cloud", str(self.root / "backup")), ("add-user", "cloud"),
            ("verify", "cloud"), ("--verify", "cloud"), ("backup", "cloud"),
            ("recover-install", "cloud"),
        )
        for revision in REVISIONS:
            for command in commands:
                with self.subTest(revision=revision, command=command):
                    with historical_reader(revision, self.root) as (old, traps, firewall, runner, _):
                        with self.assertRaisesRegex(ValueError, REFUSAL):
                            old.main(["--plain", *command])
                        old.private_json.assert_called_once_with(self.path)
                        old.require_host.assert_called_once_with(runner)
                        firewall.pending_transactions.assert_called_once_with(self.root)
                        if command[0] in ("install", "configure", "--configure-only"):
                            old.inspect_host.assert_called_once_with(runner)
                        else:
                            old.inspect_host.assert_not_called()
                        for trap in traps.values():
                            trap.assert_not_called()
                        self.assertEqual(json.loads(self.path.read_text()), DESCRIPTOR)
                        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_historical_network_recovery_is_outside_descriptor_fence(self):
        # Regression evidence for the explicit limitation, not native recovery:
        # even a descriptor registry does not prevent the old dispatch reaching
        # recover_pending. Its own transaction checks are outside this fixture.
        for revision in REVISIONS:
            with self.subTest(revision=revision), historical_reader(revision, self.root) as (old, _, firewall, runner, ui):
                transaction = self.root / "transactions" / "pending"
                firewall.pending_transactions.return_value = [transaction]
                ui.message.side_effect = None
                ui.input.side_effect = None
                ui.input.return_value = "RECOVER"
                runner.output.side_effect = None
                runner.output.return_value = "saved-test-boottime"
                with self.assertRaisesRegex(AssertionError, "firewall.recover_pending"):
                    old.main(["recover-network"])
                firewall.recover_pending.assert_called_once_with(transaction, "saved-test-boottime")
                old.private_json.assert_not_called()


if __name__ == "__main__":
    unittest.main()
