"""Optional run-local native application upgrade; no enrollment or boot fence."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import traceback
import uuid

from .state import atomic_json


TARGET = "35.0.2"
SOURCES = ("35.0.1", "35.0.2")
WEB_SERVICES = (("nc", "cron"), ("nc", "apache24"), ("nc", "php_fpm"),
                ("office", "nginx"), ("office", "supervisord"))
DATA_SERVICES = (("nc", "mysql-server"), ("nc", "redis"))


def _web_services(target):
    scanner = (("nc", "clamav_freshclam"), ("nc", "clamav_clamd")) if getattr(target.config, "antivirus", False) else ()
    return WEB_SERVICES + scanner


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _configuration(value):
    """Compare actual settings, never print or serialize their secret values."""
    system = {key: item for key, item in value["system"].items()
              if key not in ("version", "maintenance", "updater.secret")}
    office = value["apps"].get("onlyoffice", {})
    # Connection/authentication and editing selections, not upstream cached checks.
    keys = ("DocumentServerUrl", "DocumentServerInternalUrl", "StorageUrl",
            "jwt_secret", "jwt_header", "edit_formats", "def_formats", "sameTab")
    return dict(system=system, office={key: office[key] for key in keys if key in office})


def plan(target, *, nextcloud=TARGET, packages=True):
    from . import upgrade_packages
    observed = target.inspect()
    source = observed["nextcloud"]["version"]
    if source not in SOURCES or nextcloud != TARGET:
        raise ValueError("This initial native upgrade adapter supports Nextcloud 35.0.1 to 35.0.2 only; no downgrade or skipped major upgrade")
    php, database = observed["php"]["version"], observed["database"]["version"]
    if (not php.startswith("8.5.") or not database.startswith("12.3.")
            or observed["office"]["upstream"] != "9.4.0"):
        raise ValueError("The live PHP/database/Document Server combination needs a separately supported upgrade path")
    package_plan = upgrade_packages.plan(target) if packages else None
    return dict(schema_version=1, instance=target.config.instance,
                source_nextcloud=source, target_nextcloud=nextcloud,
                observed=observed, configuration_sha256=_digest(_configuration(target.private_config())),
                packages=package_plan, changes_nextcloud=source != nextcloud,
                backup="One cold ZFS snapshot set of application data and both jail roots",
                recovery="On failure, offer explicit restoration of the snapshot set; do not automatically roll back")


def summary(selected):
    packages = selected.get("packages")
    return dict(instance=selected["instance"], nextcloud=dict(
        source=selected["source_nextcloud"], target=selected["target_nextcloud"]),
        packages={group: value["actions"] for group, value in packages["jails"].items()} if packages else {},
        backup=selected["backup"], recovery=selected["recovery"])


def _private_directory(path, *, create=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Upgrade report directory must be absolute")
    for parent in reversed(path.parents):
        info = parent.lstat()
        sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not sticky)):
            raise ValueError("Unsafe upgrade report directory ancestor")
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Upgrade report directory must be owned/private")
    return path


def _run_directory(target):
    parent = Path(target.state) / "upgrades"
    if not os.path.lexists(parent):
        _private_directory(parent, create=True)
    else:
        _private_directory(parent)
    return _private_directory(parent / ("upgrade-" + uuid.uuid4().hex), create=True)


def _running(target, role, service):
    result = target.run_jail(getattr(target, role), "service", service, "onestatus", check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("Cannot determine native service state")
    return result.returncode == 0


def _stop(target, services):
    for role, service in services:
        target.run_jail(getattr(target, role), "service", service, "onestop", check=False)
        if _running(target, role, service):
            raise RuntimeError("An affected native service did not stop")


def _start(target, services, prior):
    for role, service in services:
        if prior[role + "/" + service] and not _running(target, role, service):
            target.run_jail(getattr(target, role), "service", service, "onestart")
        elif not prior[role + "/" + service] and _running(target, role, service):
            target.run_jail(getattr(target, role), "service", service, "onestop")
        if _running(target, role, service) != prior[role + "/" + service]:
            raise RuntimeError("A native service did not regain its prior state")


def _drain_php(target):
    deadline = time.monotonic() + 120
    while True:
        result = target.run_jail(target.nc, "pgrep", "-u", "www", "-x", "php", check=False)
        if result.returncode == 1:
            return
        if result.returncode != 0 or time.monotonic() >= deadline:
            raise RuntimeError("Existing PHP jobs have not finished; no migration was started")
        time.sleep(1)


def _jails(target, action):
    names = (target.office, target.nc) if action == "stop" else (target.nc, target.office)
    for jail in names:
        root = target.nc_root if jail == target.nc else target.office_root
        if target.runner.output("bastille", "config", jail, "get", "path") != str(root):
            raise RuntimeError("Configured jail identity changed")
        live = target.runner.run("jls", "-j", jail, "jid", "name", "path", check=False, hide_output=True)
        if live.returncode not in (0, 1):
            raise RuntimeError("Cannot establish jail state")
        if live.returncode == 0:
            row = live.stdout.split()
            if len(row) != 3 or not row[0].isdigit() or int(row[0]) <= 0 or row[1:] != [jail, str(root)]:
                raise RuntimeError("Live jail identity changed")
        if (action == "stop" and live.returncode == 0) or (action == "start" and live.returncode == 1):
            target.runner.run("bastille", action, jail, capture=True, hide_output=True, timeout=180)
    if action == "stop":
        # Bastille returning does not establish that kernel jail teardown ended.
        # Wait only for these identities; malformed observations still refuse.
        deadline = time.monotonic() + 120
        while True:
            rows = [line.split() for line in target.runner.output(
                "jls", "-d", "jid", "name", "path", "dying").splitlines()]
            if any(len(row) != 4 or not row[0].isdigit() or int(row[0]) <= 0
                   or not row[2].startswith("/") or row[3] not in ("true", "false") for row in rows):
                raise RuntimeError("Invalid live/dying jail observation")
            if not any(row[1] in names for row in rows):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Affected jail teardown did not complete; snapshot was not started")
            time.sleep(0.2)


def _database_ready(target):
    deadline = time.monotonic() + 120
    while True:
        result = target.run_jail(target.nc, "/usr/local/bin/mariadb", "--no-defaults",
            "--protocol=socket", "--socket=/var/run/mysql/mysql.sock", "--user=root",
            "--batch", "--skip-column-names", "--execute", "SELECT 1", check=False)
        if result.returncode == 0 and result.stdout.strip() == "1":
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Database did not become ready")
        time.sleep(1)


def execute(target, selected, *, confirm):
    """One consented operation; never resume/replay an uncertain native migration.

    Caller holds the ordinary host and database operation locks. Reports are
    informational and do not create lifecycle state or change boot permissions.
    """
    from . import upgrade_backup, upgrade_nextcloud, upgrade_packages
    if selected.get("schema_version") != 1 or selected.get("instance") != target.config.instance:
        raise ValueError("Upgrade plan does not identify this installation")
    # Compare concrete current state, not an original installer/source fingerprint.
    if (target.inspect() != selected["observed"]
            or _digest(_configuration(target.private_config())) != selected["configuration_sha256"]):
        raise ValueError("Installation changed since the upgrade plan; inspect a new plan")
    package_changes = selected["packages"] is not None and any(
        item["actions"] for item in selected["packages"]["jails"].values())
    if not selected["changes_nextcloud"] and not package_changes:
        return dict(state="complete", changed=False, instance=target.config.instance,
                    verification=target.verify(expected_nextcloud=selected["target_nextcloud"]))
    if not confirm("UPGRADE " + target.config.instance):
        return dict(state="cancelled", changed=False)
    directory = _run_directory(target)
    report = dict(schema_version=1, instance=target.config.instance, state="running",
                  source_nextcloud=selected["source_nextcloud"], target_nextcloud=selected["target_nextcloud"],
                  started=datetime.now(timezone.utc).isoformat(), steps=[], plan=selected,
                  report=str(directory / "report.json"))
    def checkpoint(step, state, details=None):
        # Adapters supply public step metadata only; never argv/stdin/config dumps.
        report["phase"] = step
        report["steps"].append(dict(step=step, state=state, details=details))
        atomic_json(directory / "report.json", report)
    prior, closed, snapshot, stopped = {}, False, None, False
    web_services = _web_services(target)
    try:
        checkpoint("prepare", "started")
        prepared = (upgrade_nextcloud.prepare(target, selected["target_nextcloud"], directory)
                    if selected["changes_nextcloud"] else None)
        if prepared is not None:
            report["artifacts"] = prepared.summary
        if selected["packages"] is not None:
            upgrade_packages.revalidate(target, selected["packages"])
        if _digest(_configuration(target.private_config())) != selected["configuration_sha256"]:
            raise ValueError("Application configuration changed during preparation")
        checkpoint("prepare", "complete")
        prior = {role + "/" + service: _running(target, role, service)
                 for role, service in (*web_services, *DATA_SERVICES)}
        report["original_services"] = prior
        checkpoint("maintenance", "started")
        closed = True
        target.occ("maintenance:mode", "--on")
        _stop(target, web_services)
        _drain_php(target)
        _stop(target, DATA_SERVICES)
        _jails(target, "stop")
        stopped = True
        checkpoint("maintenance", "complete")
        checkpoint("snapshot", "started")
        snapshot = upgrade_backup.create(target, directory / "snapshot")
        report["snapshot"] = snapshot
        checkpoint("snapshot", "complete")
        _jails(target, "start")
        stopped = False
        _stop(target, web_services)
        _drain_php(target)
        _database_ready(target)
        if package_changes:
            checkpoint("packages", "started")
            _stop(target, DATA_SERVICES)
            report["package_result"] = upgrade_packages.apply(target, selected["packages"])
            if report["package_result"].get("status") == "failed":
                raise RuntimeError("Native package upgrade failed")
            _stop(target, web_services)  # Native package scripts may restart services.
            _drain_php(target)
            _start(target, DATA_SERVICES, prior)
            _database_ready(target)
            checkpoint("packages", "complete")
        if prepared is not None:
            checkpoint("nextcloud", "started")
            report["nextcloud_result"] = upgrade_nextcloud.apply(target, prepared, checkpoint)
            checkpoint("nextcloud", "complete")
        checkpoint("configuration", "started")
        if _digest(_configuration(target.private_config())) != selected["configuration_sha256"]:
            raise ValueError("Preserved application configuration differs; inspect the private backup before reopening")
        target.run_jail(target.nc, "service", "php_fpm", "configtest")
        target.run_jail(target.nc, "service", "apache24", "configtest")
        target.run_jail(target.office, "/usr/local/sbin/nginx", "-t")
        checkpoint("configuration", "complete")
        target.occ("maintenance:mode", "--off")
        _start(target, tuple(reversed(web_services)), prior)
        checkpoint("verify", "started")
        report["verification"] = target.verify(expected_nextcloud=selected["target_nextcloud"])
        report.update(state="complete", finished=datetime.now(timezone.utc).isoformat())
        checkpoint("verify", "complete")
        return report
    except BaseException as error:
        report["failure_phase"] = report.get("phase", "preparation")
        recovery = "Upgrade did not complete; no automatic retry or rollback."
        if closed:
            try:
                if snapshot is not None:
                    _jails(target, "stop")
                    report["restore_command"] = ("sh install.sh upgrade " + target.config.instance +
                        " --restore " + str(directory / "snapshot/report.json"))
                    recovery = "Jails stopped. Snapshot retained; use restore_command only if you choose to discard changes since it."
                else:
                    _jails(target, "start")
                    _start(target, DATA_SERVICES, prior)
                    _database_ready(target)
                    target.occ("maintenance:mode", "--off")
                    _start(target, tuple(reversed(web_services)), prior)
                    recovery = "Upgrade had not started; original services restored."
            except Exception:
                try:
                    _jails(target, "stop")
                except Exception:
                    pass
                recovery = "Recovery needs operator attention; do not start affected jails or repeat the upgrade blindly."
        report.update(state="failed", error_type=type(error).__name__, recovery=recovery,
                      finished=datetime.now(timezone.utc).isoformat())
        # Containment must not depend on writable diagnostic storage. Retain the
        # original failure even if the pool is full or a report cannot be saved.
        try:
            atomic_json(directory / "failure.json", dict(error_type=type(error).__name__, message=str(error),
                frames=[dict(file=frame.filename, line=frame.lineno, function=frame.name)
                        for frame in traceback.extract_tb(error.__traceback__)]))
            report["diagnostic_file"] = str(directory / "failure.json")
        except Exception:
            report["diagnostics_incomplete"] = True
        try:
            atomic_json(directory / "report.json", report)
        except Exception:
            report["report_saved"] = False
        if not isinstance(error, Exception):
            raise
        return report


def restore_snapshot(target, path, *, confirm):
    """Explicit operator choice; never invoked automatically by execute()."""
    from . import upgrade_backup
    from .state import private_json
    path = Path(path)
    _private_directory(path.parent)
    if path.name != "report.json" or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Choose the snapshot report produced by this upgrader")
    record = private_json(path)
    if record.get("instance") != target.config.instance or record.get("state") != "captured":
        raise ValueError("Snapshot report does not identify a captured set for this instance")
    if not confirm("RESTORE " + target.config.instance):
        return dict(state="cancelled", changed=False)
    try:
        _jails(target, "stop")
        upgrade_backup.restore(target, record)
        _jails(target, "start")
        _database_ready(target)
        target.occ("maintenance:data-fingerprint")
        target.occ("maintenance:mode", "--off")
        return dict(state="restored", instance=target.config.instance, verification=target.verify())
    except BaseException as error:
        try:
            _jails(target, "stop")
        except Exception:
            recovery = "Could not confirm affected jails stopped; keep clients disconnected and inspect from the host console."
        else:
            recovery = "Affected jails are stopped. Inspect the private snapshot report."
        try:
            atomic_json(path.parent / "restore-error.json", dict(error_type=type(error).__name__,
                message=str(error), frames=[dict(file=f.filename, line=f.lineno, function=f.name)
                                           for f in traceback.extract_tb(error.__traceback__)]))
        except Exception:
            recovery += " Private error report could not be saved."
        if not isinstance(error, Exception):
            raise
        raise RuntimeError("Snapshot restore did not complete; " + recovery) from None
