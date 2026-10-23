"""One terminal entry point for managed Nextcloud/ONLYOFFICE instances."""

import argparse
import json
import os
from pathlib import Path
import re
import secrets as random_secrets
import stat
import sys

from .config import Config, OFFICE_LABELS, STATE_DIR, deployment_plan
from .deploy import Deployment
from .host import Runner, inspect_host, preflight, read_private, require_host
from .state import Registry, atomic_json, private_json
from .ui import TerminalUI
from .wizard import configure, create_secrets


def version_review(config, selected, *, policy=None):
    """Display only the already validated immutable selection, never re-resolve."""
    applications = selected.get("applications", {})
    lines = ["Selected software (before APPLY):",
             f"  Repository: FreeBSD-ports {selected.get('repository', config.repository)}",
             f"  Nextcloud: {applications.get('nextcloud', 'not recorded')}",
             f"  Office backend: {OFFICE_LABELS[config.backend]}"]
    if config.native_office:
        lines.append(f"  ONLYOFFICE: {applications.get('onlyoffice', 'not recorded')}")
    elif config.has_office:
        container = selected.get("office_runtime", {}).get("container", {})
        lines.append(f"  Pinned VM office runtime release: {container.get('release', 'not recorded')}")
    if config.has_office:
        lines.append(f"  Office connector: {selected.get('connector_app', config.backend)} "
                     f"{applications.get('connector', 'not recorded')}")
    roles, packages = selected.get("roles", {}), selected.get("packages", {})
    for role, label in (("php", "PHP"), ("database", "Database"), ("database_client", "Database client"),
                        ("web", "Web server"), ("cache", "Cache"), ("manager", "Jail manager"),
                        ("vm_manager", "VM manager"), ("vm_image_tools", "VM image tools"),
                        ("vm_firmware", "VM firmware")):
        name = roles.get(role)
        if name:
            # A package may occur in more than one jail's locked closure.
            versions = sorted({group[name]["version"] for group in packages.values() if name in group})
            lines.append(f"  {label}: {name} {', '.join(versions) or 'not recorded'}")

    def families(values):
        return ", ".join(f"{key} {value}" for key, value in sorted(values.items())) or "none (reviewed policy ranges apply)"

    def rule_summary(rule):
        if "family" in rule:
            return "family " + rule["family"] + (" >=" + rule["min"] if "min" in rule else "")
        if "exact" in rule:
            return "exact " + rule["exact"]
        if "min" in rule and "max_exclusive" in rule:
            return ">=" + rule["min"] + " <" + rule["max_exclusive"]
        return "unavailable"

    profile_id = selected.get("profile")
    profile = None
    if profile_id:
        if policy is None:
            from .versions import load_policy
            policy = load_policy()
        profile = next((item for item in policy["profiles"] if item["id"] == profile_id), None)
    if profile is None:
        lines.append("  Selected policy defaults: unavailable (selected profile not found)")
    else:
        rules = [name + " " + rule_summary(rule) for name, rule in profile["applications"].items()]
        if "connector" in profile:
            rules.append("connector " + rule_summary(profile["connector"]["version"]))
        for name, role in profile["roles"].items():
            rule = role.get("range", {})
            if "version_exact" in role:
                rule = {"exact": role["version_exact"]}
            rules.append(name + " " + rule_summary(rule))
        lines.append(f"  Selected policy defaults ({profile_id}): " + "; ".join(rules))

    lines.extend([f"  Configured families: {families(config.version_families)}",
                  f"  Effective family constraints: {families(selected.get('constraints', {}).get('version_families', {}))}",
                  "Compatibility: configured application/package checks passed; this is not native integration or security certification."])
    lines.extend("WARNING: " + warning for warning in selected.get("warnings", []))
    return "\n".join(lines)


def load_config_file(path):
    """Read an operator recipe without exposing its untrusted contents in errors."""
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate configuration key")
            value[key] = item
        return value

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024
                    or info.st_uid != os.geteuid() or info.st_mode & 0o022):
                raise ValueError("Unsafe configuration file")
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("Configuration exceeds size limit")
        # Validate duplicate keys at this boundary, leaving historical saved-config
        # interpretation and omission defaults in Config.from_json unchanged.
        text = data.decode("utf-8")
        json.loads(text, object_pairs_hook=unique_object)
        return Config.from_json(text)
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        raise ValueError("Cannot load configuration file: use a valid schema-2 JSON regular file owned by the operator, at most 1 MiB, without symlinks or group/other writes") from None


def recipe_consent(config, args, ui):
    """Invocation consent does not select features or change general UI answers."""
    if config.native_office:
        ui.message("The native ONLYOFFICE package requires Microsoft core webfonts.\n"
                   "Applicable EULA: https://corefonts.sourceforge.net/eula.htm\n"
                   "Port license: https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/webfonts/Makefile")
        if getattr(args, "accept_licenses", False):
            config.accept_microsoft_fonts = True
        if not config.accept_microsoft_fonts:
            if getattr(args, "yes", False):
                raise ValueError("Microsoft webfonts consent is missing; review the EULA and use --accept-licenses or save accept_microsoft_fonts=true")
            if not ui.confirm("Have you reviewed and accepted the Microsoft webfonts EULA?"):
                raise ValueError("Microsoft webfonts license consent declined; no configuration saved")
            config.accept_microsoft_fonts = True
    if config.tls_mode == "acme":
        ui.message("ACME account registration requires acceptance of the Let's Encrypt terms: https://letsencrypt.org/repository/")
        if not getattr(args, "accept_acme_terms", False):
            if getattr(args, "yes", False):
                raise ValueError("ACME terms consent is missing; review the terms and use --accept-acme-terms")
            if not ui.confirm("Have you reviewed and accepted the Let's Encrypt terms of service?"):
                raise ValueError("ACME terms declined; no configuration saved")
    if config.ssh_admin:
        if not ui.confirm("Grant the selected SSH key root administration in both jails through doas?" if config.native_office else
                          "Grant the selected SSH key root administration in the Nextcloud jail through doas?"):
            raise ValueError("SSH administration consent declined; no configuration saved")


def load_secrets(path, *, backend="onlyoffice"):
    if backend not in ("onlyoffice", "eurooffice", "collabora", "none"):
        raise ValueError("Unsupported private credentials backend")
    value = json.loads(read_private(path))
    keys = {"admin_password", "db_password"} | ({"jwt_secret"} if backend in ("onlyoffice", "eurooffice") else set())
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("Unexpected private credentials schema")
    if any(not isinstance(item, str) for item in value.values()):
        raise ValueError("Private credentials must be strings")
    if (len(value["admin_password"]) < 14 or len(value["admin_password"].encode("utf-8")) > 1024
            or any(ord(char) < 32 or ord(char) == 127 for char in value["admin_password"])):
        raise ValueError("Administrator password does not meet the configured minimum")
    if not all(re.fullmatch(r"[a-f0-9]{64}", value[key]) for key in keys - {"admin_password"}):
        raise ValueError("Unexpected generated credential format")
    return value


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    plain = "--plain" in argv
    argv = [value for value in argv if value != "--plain"]
    aliases = {"--plan": "plan", "--configure-only": "configure", "--verify": "verify"}
    if argv and argv[0] in aliases:
        argv[0] = aliases[argv[0]]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plain", action="store_true", help="Use numbered terminal prompts instead of bsddialog")
    commands = parser.add_subparsers(dest="command")
    install = commands.add_parser("install", help="Configure and install an additional instance")
    configuration = commands.add_parser("configure", help="Save a new configuration without provisioning")
    for command in (install, configuration):
        command.add_argument("--config", type=Path, metavar="FILE", help="Authoritative schema-2 JSON recipe (relative to caller's working directory); no wizard")
    install.add_argument("--yes", action="store_true", help="Approve prerequisite bootstrap and APPLY; generate fresh credentials; terminal and KEEP still required")
    install.add_argument("--accept-licenses", action="store_true", help="Accept the required Microsoft webfonts EULA; does not select features")
    install.add_argument("--accept-acme-terms", action="store_true", help="Accept Let's Encrypt ACME terms for this invocation")
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
    upgrade = commands.add_parser("upgrade", help="Optional live native application upgrade; initial Nextcloud 35.0.1 to 35.0.2 adapter")
    upgrade.add_argument("instance")
    upgrade.add_argument("--nextcloud", default="35.0.2", metavar="VERSION",
                         help="Target Nextcloud version (initial supported edge: 35.0.1 to 35.0.2)")
    upgrade_mode = upgrade.add_mutually_exclusive_group()
    upgrade_mode.add_argument("--plan", action="store_true", help="Inspect live state and refresh native signed pkg metadata; no upgrades")
    upgrade_mode.add_argument("--verify", action="store_true", help="Read-only live verification, including after upgrading")
    upgrade_mode.add_argument("--restore", type=Path, metavar="SNAPSHOT_REPORT", help="Explicitly restore a pre-upgrade ZFS snapshot set")
    upgrade.add_argument("--skip-packages", action="store_true", help="Omit compatible application-jail package updates")
    commands.add_parser("plan", help="Offline, read-only plan validation").add_argument("config", type=Path)
    resolution = commands.add_parser("resolve", help="Inspect version compatibility without installing or upgrading")
    resolution.add_argument("config", type=Path)
    resolution.add_argument("--metadata", type=Path, help="Use saved discovery metadata for offline assessment only")
    resolution.add_argument("--installed", type=Path, help="Compare a retained version lock; report only, never execute an upgrade")
    updates = commands.add_parser("check-updates", help="Inspect retained update reports; refresh metadata only when requested")
    updates.add_argument("instance", nargs="?")
    updates.add_argument("--all", action="store_true", help="Assess all registered non-removed instances")
    updates.add_argument("--refresh", action="store_true", help="Read current upstream/signed catalog metadata; never install")
    updates.add_argument("--save-report", action="store_true", help="Explicitly save refreshed results in private host state")
    updates.add_argument("--json", action="store_true", help="Print the structured report")
    security = commands.add_parser("check-security", help="Inspect independent security reports for retained intended versions")
    security.add_argument("instance", nargs="?")
    security.add_argument("--all", action="store_true", help="Assess all registered non-removed instances")
    security.add_argument("--refresh", action="store_true", help="Refresh core advisories and audit retained packages using existing native pkg in isolated state")
    security.add_argument("--save-report", action="store_true", help="Explicitly save refreshed security evidence privately")
    security.add_argument("--json", action="store_true", help="Print the structured report")
    maintenance = commands.add_parser("maintenance", help="Lifecycle enrollment and recovery preparation; native apply blocked")
    actions = maintenance.add_subparsers(dest="action", required=True)
    actions.add_parser("register", help="Enroll a ready original-artifact instance").add_argument("instance")
    maintenance_plan = actions.add_parser("plan", help="Assess recovery preparation or a blocked target profile")
    maintenance_plan.add_argument("--instance", required=True)
    intent = maintenance_plan.add_mutually_exclusive_group(required=True)
    intent.add_argument("--recovery-only", action="store_true")
    intent.add_argument("--target", metavar="PROFILE", help="Assessment only; no reviewed migration recipe exists")
    maintenance_plan.add_argument("--save", action="store_true", help="Save after exact interactive confirmation")
    maintenance_plan.add_argument("--json", action="store_true")
    for action, identity in (("stage", "plan_id"), ("continue", "operation")):
        staging = actions.add_parser(action, help=("Stage retained artifacts privately; never execute them" if action == "stage"
            else "Continue private staging or acceptance-gated native validation/publication"))
        staging.add_argument(identity, metavar="PLAN-ID" if action == "stage" else "OP-ID")
        staging.add_argument("--artifacts", required=action == "stage", type=Path, metavar="DIR",
                             help="Directory of retained <sha256>.pkg archives listed by maintenance plan")
        staging.add_argument("--json", action="store_true")
    target_prepare = actions.add_parser("prepare-target", help="Authenticate local target archives and inspect actual runtime before any boot fence")
    target_prepare.add_argument("operation", metavar="OP-ID")
    target_prepare.add_argument("--artifacts", required=True, type=Path, metavar="DIR",
                                help="Local source signature, target ZIP/signatures, release key and connector.archive")
    target_prepare.add_argument("--json", action="store_true")
    for action in ("cancel", "apply"):
        operation = actions.add_parser(action, help="Cancel staging or eligible pre-capture maintenance (native gate applies)"
                                       if action == "cancel" else "Always blocked: no native recipe")
        operation.add_argument("operation", metavar="OP-ID")
        operation.add_argument("--json", action="store_true")
        if action == "apply":
            operation.add_argument("--backup-dataset", metavar="POOL/DATASET",
                                   help="Existing owned recovery destination on a different pool; native acceptance still required")
    for action in ("status", "recover"):
        inspection = actions.add_parser(action, help="Inspect operation; without OP-ID use existing lifecycle " + action)
        inspection.add_argument("operation", nargs="?", metavar="OP-ID")
        inspection.add_argument("--json", action="store_true")
        if action == "recover":
            recovery_action = inspection.add_mutually_exclusive_group()
            recovery_action.add_argument("--assess", action="store_true", help="Read-only operation recovery assessment; requires OP-ID")
            recovery_action.add_argument("--restore-original", action="store_true",
                                         help="Explicit pre-publication whole-set recovery; native acceptance still required")
    for option in ("--config", "--yes", "--accept-licenses", "--accept-acme-terms"):
        if sum(value == option or value.startswith(option + "=") for value in argv) > 1:
            parser.error("Specify each recipe option at most once")
    args = parser.parse_args(argv)
    recipe = None
    if args.command == "install" and any((args.yes, args.accept_licenses, args.accept_acme_terms)) and args.config is None:
        parser.error("Install consent flags require --config FILE")
    if args.command in ("install", "configure") and args.config is not None:
        recipe = load_config_file(args.config)
        recipe.require_jail_backend("Installation/configuration")
    if args.command == "upgrade":
        if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", args.instance):
            parser.error("Invalid instance name")
    if args.command == "maintenance":
        if args.action == "plan" and not re.fullmatch(r"[a-z][a-z0-9]{0,7}", args.instance):
            parser.error("Invalid instance name")
        if args.action == "recover" and bool(args.operation) != bool(args.assess or args.restore_original):
            parser.error("Operation recovery requires OP-ID with --assess or --restore-original; omit both for enrollment recovery")
        if args.action == "recover" and args.restore_original and not args.operation.startswith("execution-"):
            parser.error("Original-set recovery requires an execution operation")
        if args.action == "continue":
            if args.operation.startswith("execution-"):
                if args.artifacts is not None:
                    parser.error("Native continuation uses retained artifacts, not --artifacts")
            elif args.artifacts is None:
                parser.error("Staging continuation requires --artifacts")
        for identity in ("operation", "plan_id"):
            value = getattr(args, identity, None)
            if value is not None and not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value):
                parser.error("Invalid maintenance identity")
    if args.command in ("check-updates", "check-security"):
        if args.instance and args.all:
            parser.error("Choose one instance or --all, not both")
        if args.instance and not re.fullmatch(r"[a-z][a-z0-9]{0,7}", args.instance):
            parser.error("Invalid instance name")
        if args.save_report and not args.refresh:
            parser.error("--save-report requires --refresh; viewing cached reports never writes")
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
    if args.command == "upgrade":
        from .upgrade_native import UpgradeRunner
        runner = UpgradeRunner()
    else:
        runner = Runner()
    require_host(runner)
    registry, ui = Registry(), TerminalUI(plain=plain)
    if args.command == "maintenance":
        return dispatch_maintenance(args, registry, runner, ui)
    from .maintenance import entry_guard
    entry_guard(args.command or "menu", registry=registry)
    if args.command in ("list", "status"):
        show_status(registry, getattr(args, "instance", None))
        return 0
    upgrade_inspection = args.command == "upgrade" and (args.plan or args.verify)
    if (args.command not in ("verify", "backup", "check-updates", "check-security") and not upgrade_inspection
            and not (sys.stdin.isatty() and sys.stdout.isatty())):
        raise ValueError("An interactive terminal is required for configuration, secrets and destructive-operation approval")
    if args.command is None:
        from .dashboard import snapshot, render
        from .updates import check_updates
        view = snapshot(registry)
        names = [row["instance"] for row in view["instances"] if not row["error"] and row["state"] != "removed"]
        reports = check_updates(registry, names) if names else None
        ui.message(render(view, host_release=runner.output("freebsd-version", "-u"), updates=reports))
        args = menu(ui, registry, view=view)
        if args.command == "upgrade":
            from .upgrade_native import UpgradeRunner
            runner = UpgradeRunner()
            entry_guard("upgrade", registry=registry)
        if args.command in ("install", "configure", "resume"):
            return launch_selected_install(args, plain=plain)
    if args.command == "maintenance":
        return dispatch_maintenance(args, registry, runner, ui)
    if args.command in ("list", "status"):
        show_status(registry, getattr(args, "instance", None))
        return 0
    if args.command == "check-updates":
        return show_updates(args, registry, runner, ui)
    if args.command == "check-security":
        return show_security(args, registry, ui)
    with registry.locked():
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
        if args.command == "upgrade":
            return dispatch_upgrade(args, registry, runner, ui)
        if args.command == "list":
            show_status(registry)
            return 0
        if args.command in ("install", "configure"):
            facts = inspect_host(runner)
            wizard_facts = {**facts, "managed_host": registry.host(),
                            "reserved_instances": [config.instance for config, _ in registry.entries(include_removed=True)]}
            existing = [config for config, _ in registry.entries()]
            config = recipe
            if recipe is not None:
                recipe_consent(config, args, ui)
                preflight(config, facts, runner, registry=registry)
                if args.command == "configure":
                    ui.message(deployment_plan(config))
            else:
                while True:
                    config = configure(wizard_facts, config, registered=existing, ui=ui)
                    config.require_jail_backend("Installation/configuration")
                    try:
                        preflight(config, facts, runner, registry=registry)
                    except (ValueError, RuntimeError, OSError) as error:
                        ui.message(f"Preflight failed: {error}")
                        if ui.confirm("Return to configuration with these values preserved?"):
                            continue
                        return 1
                    break
            if config.native_office:
                credentials = create_secrets(ui=ui, generate=True) if getattr(args, "yes", False) else create_secrets(ui=ui)
            else:
                credentials = create_secrets(ui=ui, generate=getattr(args, "yes", False), backend=config.backend)
            state = registry.save_new(config, credentials)
            ui.message(f"Configuration and generated credentials saved privately on the host: {state}")
            if args.command == "configure":
                ui.message(f"No deployment resources changed. Use: sh install.sh resume {config.instance}")
                return 0
        else:
            config = registry.load(args.instance)
            config.require_jail_backend(args.command)
            if args.command in ("backup", "restore"):
                config.require_native_backend(args.command)
            from .maintenance import require_instance_adapter
            require_instance_adapter(registry, args.instance)
            state = registry.instance_path(config.instance)
            status = registry.status(config.instance)["state"]
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
            credentials = (load_secrets(state / "secrets.json") if config.native_office else
                           load_secrets(state / "secrets.json", backend=config.backend))
            facts = inspect_host(runner) if args.command in ("resume", "remove") else {}
        deployment = Deployment(config, credentials, runner, facts.get("ssh_connection"), registry=registry, progress=ui.progress)
        if args.command in ("install", "resume"):
            if args.command == "resume":
                preflight(config, facts, runner, registry=registry, resume=True)
            ui.message("\n" + deployment_plan(config))
            selected = deployment.prepare_versions()
            ui.message(version_review(config, selected))
            ui.message("Resolved immutable version plan (no upgrades applied):\n" + json.dumps(selected, indent=2, sort_keys=True))
            ui.message(("This changes host storage/networking and creates or resumes two jails. Keep console access available.\n" if config.native_office else
                        "This changes host storage/networking and creates or resumes one Nextcloud jail and one dedicated office VM. Keep console access available.\n" if config.has_office else
                        "This changes host storage/networking and creates or resumes one Nextcloud jail. Keep console access available.\n") +
                       "Each PF transition needs a timed KEEP after checking a second SSH session. Application data is never reset on retry.")
            if getattr(args, "yes", False):
                ui.message("--yes approves APPLY for the displayed plan; timed KEEP remains mandatory.")
            elif ui.input("Type APPLY to proceed") != "APPLY":
                ui.message("Saved only; no provisioning performed.")
                return 0
            deployment.apply()
            ui.message(f"\nInstaller checks passed. Login: {config.public_url}\nAdministrator: {config.admin_username}\n"
                       f"Credentials: {state / 'secrets.json'} (host-only; not printed).")
            if config.native_office:
                ui.message("External HTTPS/proxy routing, browser editing/save and reboot acceptance still need testing.\n"
                           "SMTP delivery is disabled; schedule and test backups before production use.")
            elif config.backend=='none':
                ui.message("Nextcloud only — no integrated document server or office connector was installed.\n"
                           "You may install a compatible connector and configure your own external server manually later; the installer does not manage that integration.\n"
                            "Native login/file-transfer/reboot acceptance is not yet run. SMTP delivery is disabled; arrange and test administrator-managed backups.")
            else:
                ui.message(f"Selected office backend: {config.backend}, on its dedicated private VM.\n"
                           "External HTTPS/WebSocket/callback, browser save/reopen and host reboot acceptance remain separate.\n"
                           "Native-only maintenance/database backup is unsupported for this profile; arrange administrator-managed backups.")
            if not getattr(args, "yes", False) and ui.confirm("Create an additional non-admin Nextcloud user now?"):
                add_user(ui, deployment)
        elif args.command == "verify":
            deployment.verify()
            deployment.checkpoint()
            ui.message("Local service, mount, transport and connector checks passed. External/browser/reboot acceptance remains separate." if config.has_office else
                       "Nextcloud service, mount, transport and readiness checks passed. No integrated document server is selected; no office checks were run. External/browser/reboot acceptance remains separate.")
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


def dispatch_upgrade(args, registry, runner, ui):
    """Use current application state under the caller's host operation lock."""
    from . import upgrade
    from .operations import _database_guard
    from .upgrade_native import LiveTarget

    target = LiveTarget(registry, runner, args.instance)
    with _database_guard(target):
        if args.verify:
            report = target.verify()
        elif getattr(args, "restore", None) is not None:
            def confirm_restore(phrase):
                ui.message("This discards changes since the selected snapshot. Both jails will stop for restoration.")
                return ui.input(f"Type {phrase} to continue") == phrase
            report = upgrade.restore_snapshot(target, args.restore, confirm=confirm_restore)
        else:
            disclosure = ("Live upgrade planning may refresh signed native pkg metadata; "
                          "it does not install packages or upgrade the host OS/jail base.")
            if args.plan:
                print(disclosure, file=sys.stderr)
            else:
                ui.message(disclosure)
            selected = upgrade.plan(target, nextcloud=args.nextcloud, packages=not args.skip_packages)
            if args.plan:
                print(json.dumps(selected, indent=2, sort_keys=True))
                return 1 if selected.get("blockers") else 0
            ui.message(json.dumps(upgrade.summary(selected), indent=2, sort_keys=True))

            def confirm(phrase):
                if not (sys.stdin.isatty() and sys.stdout.isatty()):
                    raise ValueError("Native upgrade changes require an interactive terminal")
                ui.message("Save and close all editors before continuing; unsaved editor work is not covered.\n"
                           "Keep clients disconnected until the final report.\n"
                           "Expect brief downtime while services/jails stop cleanly for a local ZFS snapshot set and native upgrades. "
                           "A no-change plan does not pause services.\n"
                           "On upgrade failure, jails remain stopped and the report offers a restore command. "
                           "Nothing is rolled back unless you explicitly choose to restore the snapshot.\n"
                           "Local snapshots are not disaster-recovery backups and do not cover external storage or loss of this host/storage. "
                           "Recovery beyond that coverage remains the operator's responsibility.")
                return ui.input(f"Type {phrase} to continue") == phrase

            report = upgrade.execute(target, selected, confirm=confirm)
        public = {key: value for key, value in report.items() if key != "plan"}
        print(json.dumps(public, indent=2, sort_keys=True))
        return 1 if report.get("error") or report.get("blockers") or report.get("state") == "failed" else 0


def maintenance_report(report):
    """Expose assessment/status fields, never executor paths or bound evidence."""
    fields = ("schema_version", "instance", "status", "blockers", "warnings", "execution_authorized",
              "native_acceptance", "operation", "phase", "error", "artifacts_authenticated",
              "recovery_capture_complete", "independent_copy_verified", "writer_fencing_verified",
              "upgrade_execution_authorized", "native_execution_authorized", "publication_may_have_begun",
              "recovery_publication_may_have_begun", "restore_eligible", "saved", "pending",
              "journal_sealed", "recovery_manifest_recorded", "native_resources_verified", "state", "ready",
              "machine_drain_verified", "unsaved_editor_work_covered")
    public = {key: report[key] for key in fields if key in report}
    if "plan" in report:
        plan = report["plan"]
        public["plan"] = None if plan is None else {
            key: plan[key] for key in ("schema_version", "kind", "plan_id", "instance", "recipe",
                                      "upgrade_execution_authorized", "native_execution_authorized",
                                      "native_acceptance") if key in plan}
        if plan is not None:
            artifacts = plan["artifacts"]
            sources = [item for item in artifacts if item["kind"] == "source"]
            public["plan"].update(
                package_archives=[{"sha256": item["sha256"], "packages": item["packages"]}
                                  for item in artifacts if item["kind"] == "package"],
                source_files=len(sources), source_bytes=sum(item["size"] for item in sources))
    return public


def dispatch_maintenance(args, registry, runner, ui):
    from . import maintenance, maintenance_operations as operations
    operation = getattr(args, "operation", None)
    as_json = getattr(args, "json", False)

    def display(report):
        text = json.dumps(maintenance_report(report), indent=2, sort_keys=True)
        print(text) if as_json else ui.message(text)

    def confirmation(phrase):
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise ValueError("Maintenance changes require an interactive terminal")
        return ui.input(f"Type {phrase} to continue")

    if args.action == "register" or args.action == "recover" and operation is None:
        return maintenance.dispatch(args, registry, runner, ui)
    if args.action == "status" and operation is None:
        if not as_json:
            return maintenance.dispatch(args, registry, runner, ui)
        report = maintenance.status(registry)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if report["error"] else 0
    if args.action == "plan":
        report = operations.assess(registry, args.instance, target=args.target)
        if args.save and report["plan"] is not None and not report["blockers"]:
            if not as_json:
                display(report)
            phrase = confirmation("SAVE-MAINTENANCE " + args.instance)
            reference = operations.save_plan(registry, report["plan"], confirmation=phrase)
            report = {**report, "saved": True, "plan": {
                **report["plan"], "plan_id": Path(reference["path"]).stem}}
        display(report)
        return 1 if report["blockers"] else 0
    if args.action == "stage":
        phrase = confirmation("STAGE-MAINTENANCE " + args.plan_id)
        report = operations.stage_plan(registry, args.plan_id, args.artifacts, confirmation=phrase)
    elif args.action == "continue":
        if operation.startswith("execution-"):
            from .maintenance_execution import continue_execution
            report = continue_execution(registry, runner, operation, confirmation)
        else:
            phrase = confirmation("CONTINUE-MAINTENANCE " + operation)
            report = operations.continue_staging(registry, operation, args.artifacts, confirmation=phrase)
    elif args.action == "prepare-target":
        if not as_json:
            ui.message("This stages and authenticates local public artifacts and queries signed package metadata. "
                       "It does not install packages, stop services, arm a boot fence or authorize an upgrade.")
        phrase = confirmation("PREPARE-TARGET " + operation)
        report = operations.prepare_target(registry, operation, args.artifacts, runner, confirmation=phrase)
    elif args.action == "cancel":
        if operation.startswith("execution-"):
            from .maintenance_execution import cancel_execution
            report = cancel_execution(registry, runner, operation, confirmation)
        else:
            phrase = confirmation("CANCEL-MAINTENANCE " + operation)
            report = operations.cancel(registry, operation, confirmation=phrase)
    elif args.action == "status":
        report = operations.operation_status(registry, operation)
    elif args.action == "recover":
        if getattr(args, "restore_original", False):
            from .maintenance_execution import restore_original
            report = restore_original(registry, runner, operation, confirmation)
        else:
            report = operations.assess_recovery(registry, operation)
    elif args.action == "apply":
        report = operations.apply(registry, operation, runner=runner,
                                  backup_dataset=getattr(args, "backup_dataset", None), confirm=confirmation)
    else:
        raise ValueError("Unsupported maintenance action")
    display(report)
    return 1 if report.get("blockers") or report.get("error") else 0


def show_status(registry, instance=None):
    entries = registry.entries(include_removed=True)
    if instance:
        entries = [(c, status) for c, status in entries if c.instance == instance]
        if not entries:
            raise ValueError("Unknown instance")
    if not entries:
        print("No registered instances. Choose Install from sh install.sh.")
    for config, status in entries:
        print(f"{config.instance:8} {status['state']:11} {config.tls_mode:8} {config.public_url}")
        if not config.native_office:
            print(f"  Profile: {OFFICE_LABELS[config.backend]}")
        if instance:
            jails = f"{config.nextcloud_jail} ({config.nextcloud_host})"
            if config.native_office:
                jails += f", {config.onlyoffice_jail} ({config.onlyoffice_host})"
            print(f"  Jails: {jails}")
            if config.has_office and not config.native_office:
                print("  Office runtime: dedicated Alpine/bhyve/Docker VM; installation support unavailable")
            print(f"  State: {registry.instance_path(config.instance)}")
            journal = registry.instance_path(config.instance) / "deployment.json"
            if journal.exists():
                for phase, record in private_json(journal)["steps"].items():
                    print(f"  {record['state']:8} {phase}")
            restore = registry.instance_path(config.instance) / "restore.json"
            if restore.exists() and private_json(restore).get("state") == "pending":
                print("  Database restore pending: repeat Restore with the same trusted backup after correcting the cause.")


def launch_selected_install(args, *, plain=False):
    """Defer prerequisite consent to the current shell entrypoint, before locking.

    Python may be available without pkg. Re-entering the explicit command keeps
    the existing guarded pkg/Python bootstrap instead of duplicating it here.
    """
    entrypoint = Path(__file__).resolve().parents[1] / "install.sh"
    command = ["/bin/sh", str(entrypoint)]
    if plain:
        command.append("--plain")
    command.append(args.command)
    if args.command == "resume":
        command.append(args.instance)
    os.execv("/bin/sh", command)
    raise RuntimeError("Could not enter the selected installation command")


def show_updates(args, registry, runner, ui):
    from .dashboard import snapshot
    from .updates import check_updates
    if not args.instance:
        view = snapshot(registry)
        if view["errors"]:
            raise ValueError("Cannot enumerate registered instances safely; inspect private state")
        names = [row["instance"] for row in view["instances"] if row["state"] != "removed"]
        if not args.all:
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise ValueError("Select an instance or --all for noninteractive update checks")
            if not names:
                raise ValueError("No instances are registered for update inspection")
            selected = ui.menu("Update report scope", [("all", "All registered instances")]
                               + [("instance:" + name, name) for name in names])
            names = names if selected == "all" else [selected.split(":", 1)[1]]
    else:
        names = [args.instance]
    if not names:
        if args.json:
            print(json.dumps({"schema_version": 1, "instances": [], "inspection_failed": False,
                              "execution_authorized": False, "migration_supported": False,
                              "message": "No registered instances; host upgrades were not assessed"}, sort_keys=True))
        else:
            ui.message("No registered instances; host upgrades were not assessed.")
        return 0
    report = check_updates(registry, names, refresh=args.refresh, save_report=args.save_report, runner=runner)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        ui.message("Update assessment only — no upgrade execution or migration path is authorized.")
        for row in report["instances"]:
            ui.message(f"{row['instance']}: {row['status']} | freshness: {row.get('freshness', 'unknown')}"
                       f" | checked: {row.get('checked_at') or 'never'}")
            for label, key in (("Retained", "installed_applications"), ("Candidate", "candidate_applications")):
                apps = row.get(key)
                if isinstance(apps, dict) and apps:
                    ui.message(f"  {label}: " + ", ".join(f"{name}={value}" for name, value in sorted(apps.items())))
            for app, releases in sorted(row.get("upstream_newer", {}).items()):
                ui.message(f"  Newer upstream {app}: " + ", ".join(releases)
                           + " (availability does not establish a supported upgrade)")
            for change in row.get("changes", []):
                ui.message("  Change: " + change["component"] + ": "
                           + json.dumps(change["from"], sort_keys=True) + " -> "
                           + json.dumps(change["to"], sort_keys=True))
            for reason in row.get("stale_reasons", []):
                ui.message("  Stale evidence: " + reason)
            for label in ("blockers", "errors", "warnings"):
                for message in row.get(label, []):
                    ui.message("  " + (message["message"] if isinstance(message, dict) else message))
            if row.get("saved"):
                ui.message("  Refreshed report saved privately; installation records unchanged.")
        ui.message("Shared host summary covers retained installer prerequisites only; "
                   "host OS upgrades, security advisories and live service health are not established.")
        for package in report.get("host", {}).get("prerequisites", []):
            for kind in ("installed", "candidate"):
                entries = package[kind]
                if entries:
                    ui.message("  " + package["name"] + " " + kind + ": "
                               + ", ".join(item["instance"] + "=" + item["version"]
                                           + " (" + item["freshness"] + ")" for item in entries))
    return 1 if report.get("inspection_failed") else 0


def show_security(args, registry, ui):
    from .dashboard import snapshot
    from .security_reports import check_security
    if args.instance:
        names = [args.instance]
    else:
        view = snapshot(registry)
        if view["errors"] or any(row["error"] for row in view["instances"]):
            raise ValueError("Cannot enumerate security inspection targets safely; inspect private state")
        names = [row["instance"] for row in view["instances"] if row["state"] != "removed"]
        if not args.all:
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise ValueError("Select an instance or --all for noninteractive security checks")
            if not names:
                raise ValueError("No instances are registered for security inspection")
            choices = [("all", "All registered instances")] + [("instance:" + name, name) for name in names]
            selected = ui.menu("Security report scope", choices)
            if selected not in {key for key, _ in choices}:
                raise ValueError("Unavailable security inspection target")
            names = names if selected == "all" else [selected.split(":", 1)[1]]
    if names:
        report = check_security(registry, names, refresh=args.refresh, save_report=args.save_report)
    else:
        report = {"schema_version": 1, "instances": [], "inspection_failed": False,
                  "execution_authorized": False, "migration_supported": False,
                  "message": "No registered instances; security was not assessed"}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        ui.message("Security assessment of retained intended versions; live drift is not inspected. "
                   "Package coverage requires a fresh isolated native audit; support/EOL remains unknown. No remediation is authorized.")
        if not names:
            ui.message(report["message"])
        for row in report["instances"]:
            upstream = row["providers"]["nextcloud"]
            packages = row["providers"]["freebsd_pkg"]
            ui.message(f"{row['instance']}: Nextcloud {row['installed_version'] or 'unknown'} "
                       f"| source: {row['source']} | advisories: {upstream['status']} "
                        f"| freshness: {row['freshness']} | checked: {row['checked_at'] or 'never'}")
            ui.message(f"  Packages: {packages['status']} | coverage: {packages['coverage']} "
                       f"| freshness: {packages['freshness']}")
            for finding in upstream["findings"]:
                ui.message("  Advisory evidence: " + finding["id"] + " " + finding["url"])
            for finding in packages["findings"]:
                ui.message(f"  Package advisory: {finding['package']} {finding['version']} "
                           f"({finding['issue_count']} issues)")
            for reason in row["errors"] + row["stale_reasons"] + upstream["reasons"] + packages["reasons"]:
                ui.message("  " + reason)
            if row["saved"]:
                ui.message("  Security report and advisory evidence saved privately.")
    return 1 if report["inspection_failed"] else 0


def menu(ui, registry, *, view=None):
    from .dashboard import snapshot
    view = snapshot(registry) if view is None else view
    rows = [row for row in view["instances"] if not row["error"]]
    allowed = {
        "status": rows,
        "resume": [row for row in rows if row["state"] in ("configured", "installing", "failed")],
        "remove": [row for row in rows if row["state"] != "configured"],
        "recover-install": [row for row in rows if row["state"] in ("failed", "installing")],
    }
    for action in ("verify", "backup", "restore", "add-user", "upgrade"):
        allowed[action] = [row for row in rows if row["state"] == "ready"
                           and (not row["pending"] or action == "restore" and row["pending"] == ["database restore"])]
    choices = []
    unsafe = bool(view["errors"] or any(row["error"] for row in view["instances"]))
    blocked = unsafe or bool(view["pending_network"])
    if any(row["state"] != "removed" for row in view["instances"]):
        choices.append(("check-updates", "Check for updates (report only)"))
        choices.append(("check-security", "Check security advisories (independent report)"))
    if not blocked:
        choices.extend([("install", "Install an additional instance"), ("configure", "Configure only; install later")])
    choices.append(("list", "List registered instances"))
    if registry.lifecycle_enabled():
        choices.extend([("maintenance-status", "Inspect lifecycle state"),
                        ("maintenance-plan", "Assess recovery preparation (native apply blocked)"),
                        ("maintenance-recover", "Recover interrupted lifecycle metadata")])
    if not blocked and any(row["state"] == "ready" for row in rows):
        choices.append(("maintenance-register", "Enroll an eligible ready instance (no upgrade)"))
    labels = {"resume": "Resume interrupted/configured installation", "status": "Show retained instance status",
              "upgrade": "Upgrade applications (optional native assistant)",
              "verify": "Verify a ready instance", "backup": "Back up database and configuration",
              "restore": "Restore database and configuration", "add-user": "Create a non-admin Nextcloud user",
              "remove": "Remove an instance (data retained by default)",
              "recover-install": "Reset eligible unpublished initialization"}
    choices += [(action, labels[action]) for action in labels if allowed[action] and (not blocked or action == "status")]
    if view["pending_network"]:
        choices.append(("recover-network", "Recover interrupted network transition"))
    choice = ui.menu("Nextcloud + ONLYOFFICE instance manager", choices)
    if choice not in {key for key, _ in choices}:
        raise ValueError("Unavailable dashboard action")
    args = argparse.Namespace(command=choice)
    if choice.startswith("maintenance-"):
        args.command, args.action = "maintenance", choice.removeprefix("maintenance-")
        if args.action == "plan":
            args.instance = ui.input("Instance name for read-only recovery preparation assessment")
            if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", args.instance):
                raise ValueError("Invalid instance name")
            args.recovery_only, args.target, args.save, args.json = True, None, False, False
        if args.action == "register":
            ready = [row for row in rows if row["state"] == "ready"]
            args.instance = ui.menu("Select instance for explicit enrollment",
                                    [(row["instance"], row["instance"]) for row in ready])
            if args.instance not in {row["instance"] for row in ready}:
                raise ValueError("Unavailable enrollment instance")
        return args
    if choice in ("install", "configure", "list", "recover-network"):
        return args
    if choice in ("check-updates", "check-security"):
        args.instance, args.all, args.json = None, False, False
        label = "Security advisory discovery" if choice == "check-security" else "Update discovery"
        refresh_label = "Refresh public security advisories" if choice == "check-security" else "Refresh available-version metadata"
        args.refresh = ui.menu(label, [("cached", "Show retained results (no network)"),
                                      ("refresh", refresh_label)], "cached") == "refresh"
        args.save_report = args.refresh and ui.confirm("Save this refreshed assessment in private host state? No packages will be changed.")
        return args
    entries = allowed[choice]
    if not entries:
        raise ValueError("No instances are registered for this operation")
    args.instance = ui.menu("Select instance", [(row["instance"], f"{row['instance']} — {row['state']} — {row['public_url']}") for row in entries])
    if args.instance not in {row["instance"] for row in entries}:
        raise ValueError("Unavailable instance for this action")
    if choice == "remove":
        args.purge_data = ui.menu("Application data after removal", [("retain", "Retain datasets (default)"),
                                                                   ("purge", "Permanently destroy application data and snapshots")], "retain") == "purge"
    elif choice == "restore":
        args.backup = Path(ui.input("Absolute path to a trusted backup package directory"))
    elif choice == "upgrade":
        args.nextcloud, args.plan, args.verify = "35.0.2", False, False
        args.skip_packages = False
    return args


def add_user(ui, deployment):
    from .operations import create_user
    username = ui.input("New non-admin username")
    display = ui.input("Display name (optional)")
    email = ui.input("Email (optional; SMTP is not yet configured)")
    generated = ui.confirm("Generate a strong password and save it in this instance's private host state?")
    password = random_secrets.token_urlsafe(24) if generated else ui.secret("New user's password (at least 14 characters)")
    if not generated and ui.secret("Confirm password") != password:
        raise ValueError("Passwords did not match")
    create_user(deployment, username, password, display_name=display, email=email)
    if generated:
        # Never put a user-supplied identifier into a filename.
        path = deployment.state / ("user-" + random_secrets.token_hex(8) + ".json")
        atomic_json(path, {"username": username, "password": password, "url": deployment.config.public_url})
        ui.message(f"User created without administrator membership. Credentials saved on host: {path}")
    else:
        ui.message("User created without administrator membership; the supplied password was not stored by the installer.")


def entrypoint():
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        TerminalUI.message("\nStopped. Saved state is retained; no datasets are deleted.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as error:
        # Configuration errors never embed secret values; do not print private
        # runtime objects or tracebacks containing provisioning arguments.
        TerminalUI.message(f"Error: {error}", file=sys.stderr)
        TerminalUI.message(f"State is retained under {STATE_DIR}. Correct the reported cause, then use the matching Resume/removal/restore workflow.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    entrypoint()
