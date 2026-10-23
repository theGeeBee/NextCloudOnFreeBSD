"""Independent retained-intent security reports and explicit public refresh.

Only the update inspector's safe file/snapshot/lock-conflict primitives are
shared. Its discovery, version selection and update reports are never invoked.
Default inspection reads existing evidence/cache without initialization, locks,
native commands or network traffic. Registry lifecycle validation retains its
existing credential-digest checks; credentials never enter reports or requests.
Cache results are recomputed from advisory evidence, never status strings.
"""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import ssl
import time
from urllib.parse import urlsplit

from . import security_assessment as assessment
from . import package_security
from . import updates
from .state import atomic_json, timestamp


SCHEMA_VERSION = 2
MAX_BYTES = updates.MAX_BYTES
MAX_INSTANCES = 256
SOURCE = "retained-intended-version"


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _https_fetch(url, *, max_bytes, headers, deadline):
    """Public HTTPS only: no proxy/env credentials, cookies, auth or redirects."""
    assessment._allowed_url(url)
    if type(max_bytes) is not int or not 0 < max_bytes <= assessment.MAX_BYTES:
        raise assessment.AssessmentError("Invalid advisory transfer budget")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise assessment.AssessmentError("Advisory transfer deadline expired")
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection("api.github.com", timeout=min(15, remaining), context=context)
    parsed = urlsplit(url)
    try:
        # Build fixed headers rather than forwarding caller headers/credentials.
        connection.request("GET", parsed.path + "?" + parsed.query,
                           headers={"Accept": "application/vnd.github+json", "Accept-Encoding": "identity",
                                    "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "cloud-installer-security/1"})
        response = connection.getresponse()
        if (response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity"
                or response.getheader("Content-Type", "").split(";", 1)[0].strip()
                not in ("application/json", "application/vnd.github+json")):
            raise assessment.AssessmentError("Unexpected advisory HTTP response")
        length = response.getheader("Content-Length")
        if length is not None and (not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > max_bytes):
            raise assessment.AssessmentError("Invalid advisory HTTP length")
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise assessment.AssessmentError("Advisory transfer deadline expired")
            if connection.sock is not None:
                connection.sock.settimeout(min(15, remaining))
            block = response.read1(min(65536, max_bytes - len(data) + 1))
            if not block:
                break
            data.extend(block)
            if len(data) > max_bytes:
                raise assessment.AssessmentError("Advisory transfer limit exceeded")
        if length is not None and len(data) != int(length):
            raise assessment.AssessmentError("Truncated advisory HTTP response")
        links = response.headers.get_all("Link", [])
        link = ", ".join(links)
        if len(link) > 4096:
            raise assessment.AssessmentError("Invalid advisory pagination header")
        return {"status": 200, "url": url, "body": bytes(data), "link": link or None}
    finally:
        connection.close()


def _transport():
    deadline = time.monotonic() + 120
    return lambda url, **kwargs: _https_fetch(url, deadline=deadline, **kwargs)


def _empty(name):
    return {"instance": name, "source": SOURCE, "status": "unknown", "freshness": "missing",
            "checked_at": None, "installed_version": None, "bindings": {}, "provenance": {},
            "providers": {"nextcloud": assessment.assess_nextcloud(None),
                          "freebsd_pkg": assessment.assess_freebsd_packages()},
            "errors": [], "stale_reasons": [], "saved": False,
            "execution_authorized": False, "migration_supported": False}


def _base(name, version, bindings, installed_policy, packages=None):
    assessment._version(version)
    report = _empty(name)
    report.update(installed_version=version, bindings=deepcopy(bindings),
                  provenance={"installed_policy_sha256": installed_policy,
                              "original_policy_available": installed_policy == bindings["policy_sha256"],
                              "original_source_matches": bindings["source_sha256"] == bindings["inspector_source_sha256"],
                              "feed_sha256": None})
    report["providers"]["nextcloud"] = assessment.assess_nextcloud(version)
    if packages is not None:
        report["providers"]["freebsd_pkg"] = package_security.assess(packages)
        report["provenance"]["package_evidence_sha256"] = None
    return report


def _assess(report, feed, checked_at, packages=None, package_evidence=None):
    report["checked_at"] = checked_at
    report["providers"]["nextcloud"] = assessment.assess_nextcloud(report["installed_version"], feed, now=checked_at)
    report["provenance"]["feed_sha256"] = _hash(feed) if feed is not None else None
    report["freshness"] = report["providers"]["nextcloud"]["freshness"]
    if packages is not None:
        provider = package_security.assess(packages, package_evidence, now=checked_at)
        if package_evidence is None:
            provider["reasons"] = ["native-package-audit-unavailable"]
        report["providers"]["freebsd_pkg"] = provider
        report["provenance"]["package_evidence_sha256"] = _hash(package_evidence) if package_evidence is not None else None
    _summary(report)


def _summary(report):
    # No aggregate clean/security/EOL claim, even when both feeds have no hits.
    report["status"] = "affected" if any(p["status"] == "affected" for p in report["providers"].values()) else "unknown"


def _package_failure(report):
    report["errors"].append("package-refresh-failed")
    report["freshness"] = "unknown"
    report["providers"]["freebsd_pkg"].update(status="unknown", coverage="unknown", freshness="unknown",
                                              findings=[], reasons=["package-refresh-failed"])
    _summary(report)


def _failure(report, code):
    report.update(status="unknown", freshness="unknown")
    if code not in report["errors"]:
        report["errors"].append(code)
    # Never leave an apparently successful provider result beside an invalid
    # installation/cache binding or failed save.
    report["providers"]["nextcloud"] = assessment.assess_nextcloud(report["installed_version"])
    report["providers"]["nextcloud"].update(freshness="unknown", reasons=[code])
    if code == "refresh-failed":
        _summary(report)  # An independent successful pkg assessment is retained.
    else:
        report["providers"]["freebsd_pkg"].update(status="unknown", coverage="unknown", freshness="unknown",
                                                  findings=[], reasons=[code])


def _validate_cache(value, name):
    """Reconstruct the one canonical cache form; arbitrary cached text is unused."""
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] not in (1, 2):
        raise assessment.AssessmentError("Unsupported security cache schema")
    legacy = value["schema_version"] == 1
    assessment._fields(value, ("schema_version", "generated_at", "report", "feed")
                       if legacy else ("schema_version", "generated_at", "report", "feed", "packages", "package_evidence"))
    generated = assessment._date(value["generated_at"])
    report = value["report"]
    assessment._fields(report, _empty(name))
    checked = assessment._date(report["checked_at"])
    if checked > generated or generated > datetime.now(timezone.utc):
        raise assessment.AssessmentError("Invalid security cache timestamps")
    bindings = report["bindings"]
    assessment._fields(bindings, updates.BINDINGS)
    for key, digest in bindings.items():
        if digest is None and key in ("deployment_sha256", "lifecycle_sha256"):
            continue
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise assessment.AssessmentError("Invalid security cache binding")
    provenance = report["provenance"]
    provenance_fields = ("installed_policy_sha256", "original_policy_available", "original_source_matches", "feed_sha256")
    assessment._fields(provenance, provenance_fields if legacy else (*provenance_fields, "package_evidence_sha256"))
    policy_hash = provenance["installed_policy_sha256"]
    if not isinstance(policy_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", policy_hash):
        raise assessment.AssessmentError("Invalid retained security policy provenance")
    feed = value["feed"]
    if feed is not None:
        assessment._validate_feed(feed)
        if assessment._date(feed["fetched_at"]) > checked:
            raise assessment.AssessmentError("Invalid advisory fetch timestamp")
    packages, package_evidence = (None, None) if legacy else (value["packages"], value["package_evidence"])
    if not legacy:
        package_security.packages_hash(packages)
        if package_evidence is not None:
            package_security.validate_evidence(package_evidence, packages)
            if assessment._date(package_evidence["fetched_at"]) > checked:
                raise assessment.AssessmentError("Invalid package fetch timestamp")
    expected = _base(name, report["installed_version"], bindings, policy_hash, packages)
    _assess(expected, feed, report["checked_at"], packages, package_evidence)
    errors = report["errors"]
    allowed = ([], ["refresh-failed"], ["instance-not-ready"])
    if not legacy:
        allowed += (["package-refresh-failed"], ["refresh-failed", "package-refresh-failed"])
    if errors not in allowed:
        raise assessment.AssessmentError("Invalid cached security failure")
    if "refresh-failed" in errors or "instance-not-ready" in errors:
        if feed is not None or ("instance-not-ready" in errors and package_evidence is not None):
            raise assessment.AssessmentError("Invalid cached security failure")
        _failure(expected, errors[0])
        if legacy:
            # Schema 1 never had native coverage; preserve its exact original
            # unknown provider rather than retrofitting a guessed assessment.
            expected["providers"]["freebsd_pkg"] = assessment.assess_freebsd_packages()
    elif feed is None:
        raise assessment.AssessmentError("Missing cached advisory evidence")
    if "package-refresh-failed" in errors:
        if package_evidence is not None:
            raise assessment.AssessmentError("Failed package refresh has unexpected evidence")
        _package_failure(expected)
    if report != expected:
        raise assessment.AssessmentError("Security cache does not match its evidence")
    return expected, feed, packages, package_evidence


def _cached(root, name, bindings, packages):
    directory = root / "security-reports"
    try:
        updates._directory(directory)
    except FileNotFoundError:
        if directory.is_symlink():
            raise assessment.AssessmentError("Unsafe security cache directory") from None
        return None
    data = updates._optional(directory / (name + ".json"))
    if data is None:
        return None
    report, feed, cached_packages, package_evidence = _validate_cache(updates._json(data), name)
    reasons = [key for key in sorted(updates.BINDINGS) if bindings[key] != report["bindings"][key]]
    if cached_packages is not None and cached_packages != packages:
        reasons.append("package-arguments-changed")
    now = datetime.now(timezone.utc)
    if (now - assessment._date(report["checked_at"])).total_seconds() > assessment.MAX_AGE_SECONDS:
        reasons.append("older-than-24-hours")
    if feed is not None:
        assessed = assessment.assess_nextcloud(report["installed_version"], feed, now=now.isoformat())
        report["providers"]["nextcloud"] = assessed
        if assessed["freshness"] == "stale" and "older-than-24-hours" not in reasons:
            reasons.append("older-than-24-hours")
    if package_evidence is not None:
        provider = package_security.assess(cached_packages, package_evidence, now=now.isoformat())
        report["providers"]["freebsd_pkg"] = provider
        if provider["freshness"] == "stale" and "older-than-24-hours" not in reasons:
            reasons.append("older-than-24-hours")
    if reasons:
        report.update(freshness="stale", stale_reasons=reasons, status="unknown")
        for provider in report["providers"].values():
            provider.update(status="unknown", coverage="unknown", freshness="stale")
            provider["reasons"] = sorted(set(provider["reasons"] + ["stale-report-evidence"]))
    return report


def _snapshot(registry, name):
    _, policy_hash, source_hash = updates._context(registry, name)
    return updates._snapshot(registry, name, policy_hash, source_hash)


def _save(registry, reports, snapshots, feed, packages, package_evidence):
    if any(not row["checked_at"] or not row["bindings"] or "inspection-failed" in row["errors"] for row in reports):
        raise assessment.AssessmentError("Cannot save invalid security inspection evidence")
    updates._save_conflicts(registry)
    with registry.locked():
        updates._save_conflicts(registry)
        for row in reports:
            if _snapshot(registry, row["instance"])[3] != snapshots[row["instance"]]:
                raise assessment.AssessmentError("Security report bindings changed before save")
        directory = Path(registry.root).absolute() / "security-reports"
        if not directory.exists() and not directory.is_symlink():
            directory.mkdir(mode=0o700)
        updates._directory(directory)
        values = []
        for row in reports:
            path = directory / (row["instance"] + ".json")
            previous = updates._optional(path)
            if previous is not None:
                _validate_cache(updates._json(previous), row["instance"])
            value = {"schema_version": SCHEMA_VERSION, "generated_at": timestamp(),
                     "report": row, "feed": None if any(code in row["errors"] for code in ("refresh-failed", "instance-not-ready")) else feed,
                     "packages": packages[row["instance"]], "package_evidence": package_evidence.get(row["instance"])}
            _validate_cache(value, row["instance"])
            if len(json.dumps(value, indent=2, sort_keys=True).encode()) + 1 > MAX_BYTES:
                raise assessment.AssessmentError("Security report exceeds cache size limit")
            values.append((path, value))
        for path, value in values:
            atomic_json(path, value)
            value["report"]["saved"] = True


def check_security(registry, names, *, refresh=False, save_report=False, fetcher=None, runner=None):
    """Return independent reports for explicit distinct IDs; no live-version claim.

    fetcher is the core refresh transport contract, injected only for an explicit
    refresh. runner optionally supplies the native package adapter; otherwise
    it is available only on FreeBSD with an existing reviewed pkg. One bounded
    upstream Nextcloud feed is shared across the selection. Saving
    requires refresh and a short global lock with exact evidence revalidation.
    Failed refreshes can be saved as unknown; invalid instance evidence cannot.
    """
    if (not isinstance(names, list) or not 1 <= len(names) <= MAX_INSTANCES
            or any(not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", name) for name in names)
            or len(names) != len(set(names))):
        raise ValueError("Security inspection requires distinct explicit instance IDs")
    if save_report and not refresh:
        raise ValueError("Saving a security report requires explicit refresh")
    reports, snapshots, feed, attempted = [], {}, None, False
    packages, package_evidence = {}, {}
    for name in names:
        report = _empty(name)
        reports.append(report)
        try:
            _, status, installed, bindings = _snapshot(registry, name)
            snapshots[name] = bindings
            packages[name] = package_security.retained_packages(installed)
            report.update(_base(name, installed["applications"]["nextcloud"], bindings, installed["policy_sha256"], packages[name]))
            if not refresh:
                cached = _cached(Path(registry.root).absolute(), name, bindings, packages[name])
                if cached is not None:
                    report.update(cached)
                continue
            if status["state"] != "ready":
                report["checked_at"] = timestamp()
                _failure(report, "instance-not-ready")
                continue
            if not attempted:
                attempted = True
                try:
                    feed = assessment.refresh_nextcloud(fetcher if fetcher is not None else _transport(),
                                                        fetched_at=timestamp())
                except (ValueError, RuntimeError, OSError, TypeError, KeyError):
                    feed = None  # No remote exceptions or previous-success fallback.
            package_failed = False
            try:
                package_evidence[name] = package_security.refresh(packages[name], runner=runner)
            except package_security.NativeAuditUnavailable:
                pass
            except (ValueError, RuntimeError, OSError, TypeError, KeyError):
                package_failed = True
            _assess(report, feed, timestamp(), packages[name], package_evidence.get(name))
            if feed is None:
                _failure(report, "refresh-failed")
            if package_failed:
                _package_failure(report)
        except (ValueError, RuntimeError, OSError, TypeError, KeyError, UnicodeError):
            _failure(report, "inspection-failed")
    for report in reports:
        name = report["instance"]
        if name not in snapshots or "inspection-failed" in report["errors"]:
            continue
        try:
            if _snapshot(registry, name)[3] != snapshots[name]:
                raise assessment.AssessmentError("Security inspection evidence changed")
        except (ValueError, RuntimeError, OSError, TypeError, KeyError):
            _failure(report, "inspection-failed")
    if save_report:
        try:
            _save(registry, reports, snapshots, feed, packages, package_evidence)
        except (ValueError, RuntimeError, OSError, TypeError, KeyError):
            for report in reports:
                _failure(report, "save-failed")
    return {"schema_version": SCHEMA_VERSION, "generated_at": timestamp(), "instances": reports,
            "inspection_failed": any(row["errors"] for row in reports),
            "execution_authorized": False, "migration_supported": False}
