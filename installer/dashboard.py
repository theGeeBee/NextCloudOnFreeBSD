"""Advisory, secret-free registry inspection. Never initialize, lock or repair.

This projection is not an ownership/adoption decision. Mutation paths must reload
the original registry and revalidate it under their existing operation lock.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from .config import Config, SCHEMA_VERSION


STATES = frozenset(("configured", "installing", "failed", "ready", "removing", "removed"))
MAX_RECORD = 16 * 1024 * 1024


def _directory(path, *, optional=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return False
        raise
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Unsafe registry directory")
    return True


def _read(path, *, optional=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if optional:
            return None
        raise
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > MAX_RECORD):
            raise ValueError("Unsafe registry record")
        raw = stream.read(MAX_RECORD + 1)
        if len(raw) > MAX_RECORD:
            raise ValueError("Registry record too large")
        def unique(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("Duplicate registry field")
                result[key] = item
            return result
        try:
            value = json.loads(raw, object_pairs_hook=unique)
        except RecursionError:
            raise ValueError("Excessively nested registry record") from None
        if not isinstance(value, dict):
            raise ValueError("Unexpected registry record")
        return value


def _time(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def instance_names(registry):
    """Enumerate only safe registered names, without creating a missing root."""
    if registry.lifecycle_enabled():
        return registry.lifecycle_names()
    root = Path(registry.root)
    if any(parent.is_symlink() for parent in (root, *root.parents)):
        raise ValueError("Symlink in registry path")
    if not _directory(root, optional=True) or not _directory(root / "instances", optional=True):
        return []
    names = []
    for path in sorted((root / "instances").iterdir()):
        if path.name.startswith(".pending-"):
            continue
        if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", path.name):
            raise ValueError("Unexpected registry entry; inspection requires review")
        # Report a broken per-instance directory in snapshot(), not as an empty host.
        names.append(path.name)
    return names


def snapshot(registry):
    """Return bounded public facts; incomplete/unsafe records remain visible."""
    view = {"instances": [], "errors": [], "pending_network": [], "host_policy": "unknown"}
    try:
        names = instance_names(registry)
        if Path(registry.root).exists():
            host = _read(Path(registry.root) / "host.json", optional=True)
            if host is not None:
                view["host_policy"] = "retained (not live-verified)"
        from .firewall import pending_transactions
        view["pending_network"] = [item.name for item in pending_transactions(registry.root)]
    except (OSError, ValueError, TypeError, KeyError):
        view["errors"].append("Registry/network inspection failed; no mutation is safe from this dashboard")
        return view
    for name in names:
        row = {"instance": name, "state": "inspection-error", "pending": [],
               "last_installation_check": None, "live_health": "not checked", "error": None}
        try:
            path = registry.instance_path(name)
            _directory(path)
            config_path = registry.evidence_path(name, "config.json")
            original = _read(config_path)
            config = registry.load(name)
            if config.instance != name:
                raise ValueError("Instance identity mismatch")
            status = registry.status(name)
            if status.get("state") not in STATES:
                raise ValueError("Unknown instance state")
            journal = _read(path / "deployment.json", optional=True)
            if journal is not None:
                if (journal.get("schema_version") != SCHEMA_VERSION
                        or journal.get("config_sha256") != registry.deployment_config_digest(name)
                        or not isinstance(journal.get("steps"), dict)):
                    raise ValueError("Deployment binding/schema mismatch")
                for record in journal["steps"].values():
                    if not isinstance(record, dict) or record.get("state") not in ("running", "failed", "complete"):
                        raise ValueError("Invalid deployment phase")
                if any(record["state"] != "complete" for record in journal["steps"].values()):
                    row["pending"].append("installation")
                check = journal["steps"].get("readiness checks", {})
                if check.get("state") == "complete":
                    row["last_installation_check"] = _time(check.get("completed"))
            for filename, label in (("restore.json", "database restore"),
                                    ("initialization.json", "initialization recovery"),
                                    ("removal.json", "removal"), ("purge.json", "data purge")):
                record = _read(path / filename, optional=True)
                if record is None:
                    continue
                if record.get("state") in ("pending", "running", "failed"):
                    row["pending"].append(label)
                steps = record.get("steps", {})
                if not isinstance(steps, dict) or any(not isinstance(step, dict) for step in steps.values()):
                    raise ValueError("Invalid maintenance journal")
                if any(step.get("state") in ("running", "failed") for step in steps.values()):
                    row["pending"].append(label)
                recoveries = record.get("recoveries", [])
                if not isinstance(recoveries, list) or any(not isinstance(item, dict) for item in recoveries):
                    raise ValueError("Invalid recovery journal")
                if recoveries and recoveries[-1].get("state") in ("running", "failed"):
                    row["pending"].append(label)
            # Detect common lock-free observation races. This is advisory; every
            # mutation still reloads state and resources while holding its lock.
            if original != _read(registry.evidence_path(name, "config.json")) or status != registry.status(name):
                raise ValueError("Registry changed during inspection")
            row.update(state=status["state"], public_url=config.public_url,
                       nextcloud_jail=config.nextcloud_jail, office_jail=config.onlyoffice_jail if config.native_office else None,
                       recorded_release=config.release, state_updated=_time(status.get("updated")))
            if not config.native_office:
                row["office_backend"] = config.backend
            row["pending"] = sorted(set(row["pending"]))
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            # Never echo private JSON, raw exceptions or journals' error payloads.
            row["error"] = "Unsafe, changed or unsupported instance records; inspect privately"
        view["instances"].append(row)
    return view


def render(view, *, host_release=None, updates=None):
    lines = ["Managed host dashboard (advisory; no repair or update discovery)"]
    if isinstance(host_release, str) and re.fullmatch(r"[0-9]+\.[0-9]+-RELEASE(?:-p[0-9]+)?", host_release):
        lines.append("Host userland: " + host_release)
    else:
        lines.append("Host userland: unknown")
    lines.append("Shared host policy: " + view["host_policy"])
    for error in view["errors"]:
        lines.append("ATTENTION: " + error)
    if view["pending_network"]:
        lines.append("ATTENTION: unresolved network transaction(s); inspect status/recover-network")
    reports = {row["instance"]: row for row in (updates or {}).get("instances", [])}
    if not view["instances"] and not view["errors"]:
        lines.append("No registered instances. Choose Install or Configure.")
    for row in view["instances"]:
        lines.append(f"{row['instance']}: {row['state']}")
        if row["error"]:
            lines.append("  " + row["error"])
            continue
        if row.get("office_backend") == "none":
            lines.append(f"  {row['public_url']} | {row['nextcloud_jail']} | Nextcloud only — no integrated document server")
        elif row.get("office_backend") in ("eurooffice", "collabora"):
            lines.append(f"  {row['public_url']} | {row['nextcloud_jail']} | {row['office_backend']} dedicated VM (support unavailable)")
        else:
            lines.append(f"  {row['public_url']} | {row['nextcloud_jail']} + dedicated {row['office_jail']}")
        lines.append("  Recorded jail release: " + row["recorded_release"])
        lines.append("  Live health: not checked. Last installation readiness check: "
                     + (row["last_installation_check"] or "unknown") + " (historical)")
        if row["pending"]:
            lines.append("  ATTENTION: " + ", ".join(row["pending"]))
        report = reports.get(row["instance"], {})
        lines.append("  Updates: " + str(report.get("status", "unknown"))
                     + " | freshness: " + str(report.get("freshness", "unknown"))
                     + " | checked: " + str(report.get("checked_at") or "never"))
    lines.append("Upgrades, post-install modification and shared DocumentServer are not implemented.")
    return "\n".join(lines)
