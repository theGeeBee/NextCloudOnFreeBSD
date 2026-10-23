"""Optional, installed-state FreeBSD ports upgrades; no enrollment or host writes.

The caller holds its operation/database locks, checks jail identities in run_jail,
and stops application writers/services before apply. Run this BEFORE replacing NC
code: both the live NC release and every supplied nextcloud_path step are checked.
Failures require inspection, never automatic replay or package downgrade rollback.

Reviewed 2026-10-18: freebsd/pkg tag 2.8.4, docs/pkg-{upgrade,query,rquery}.8,
src/{upgrade,utils,repositories,config}.c and libpkg/{pkg_jobs,pkgdb}.c. In particular -U
disables refresh, exact installed name selectors constrain upgrade, -F fetches the
same upgrade job, and a single stdin answer refuses a second conflict-solver job.
Repository display is src/utils.c:print_repository, NOT a generic UCL parser.
"""

from copy import deepcopy
import re

from .compatibility import VERSION, profile_roots
from .discovery import package_catalog
from .versions import (NAME, ORIGIN, constraints, in_range, load_policy,
                       release_base, stable_version, target as policy_target)


REPO = "FreeBSD-ports"
LIMIT = 16 * 1024 * 1024
SOURCES = [
    "https://github.com/freebsd/pkg/tree/2.8.4",
    "https://github.com/freebsd/freebsd-src/blob/releng/15.1/share/keys/pkg/trusted/pkg.freebsd.org.2013102301",
    "https://github.com/nextcloud/server/blob/v35.0.2/lib/versioncheck.php",
    "https://github.com/nextcloud/server/blob/v35.0.2/apps/settings/lib/SetupChecks/SupportedDatabase.php",
]
FINGERPRINT = "b0170035af3acc5f3f3ae1859dc717101b4e6c1d0a794ad554928ca0cbb2f438"
KEYS = ('for f in /usr/share/keys/pkg/trusted/*; do '
        '[ -f "$f" ] || exit 1; /bin/cat "$f" || exit; printf "\\n"; done')
ENV = ("/usr/bin/env", "-i", "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C")
# Per-command options; never rewrite the operator's pkg.conf or repository files.
PKG = ENV + ("/usr/local/sbin/pkg",) + tuple(
    token for setting in ("PKG_ENABLE_PLUGINS=no", "REPO_AUTOUPDATE=no",
                          "ASSUME_ALWAYS_YES=no", "DEFAULT_ALWAYS_YES=no",
                          "AUTOREMOVE=no", "AUTOCLEAN=no", "HANDLE_RC_SCRIPTS=no",
                          "IGNORE_OSVERSION=no", "IGNORE_OSMAJOR=no", "PERMISSIVE=no",
                          "CASE_SENSITIVE_MATCH=yes")
    for token in ("-o", setting))
SECTIONS = {"New packages to be INSTALLED:": "installed", **{
    "Installed packages to be " + word.upper() + ":": word
    for word in ("upgraded", "reinstalled", "removed", "downgraded")}}


class PackageUpgradeError(ValueError):
    """Public, sanitized blocker; raw command output must not be attached."""


def _require(condition, message):
    if not condition:
        raise PackageUpgradeError(message)


def _output(target, jail, *argv, input="", timeout=120):
    try:
        result = target.run_jail(jail, *argv, input=input, timeout=timeout, check=False)
    except Exception:
        raise PackageUpgradeError("Native package command failed; inspect the jail before retrying") from None
    _require(result.returncode == 0, "Native package command failed; inspect the jail before retrying")
    _require(isinstance(result.stdout, str) and len(result.stdout.encode()) <= LIMIT,
             "Invalid or oversized native package output")
    return result.stdout


def parse_summary(output):
    """Parse the complete pkg 2.8.4 C-locale upgrade summary, including totals."""
    _require(isinstance(output, str) and len(output.encode()) <= LIMIT, "Invalid pkg summary")
    lines = [line for line in output.splitlines() if line.strip()]
    # src/event.c and pkg_jobs.c: cached archives allow pre-solve integrity
    # checking even for -n. A nonzero conflict count needs separate review.
    for prefix in ("Updating database digests format: . done", "Checking integrity... done (0 conflicting)"):
        if lines and lines[0] == prefix:
            lines.pop(0)
    if lines == ["Your packages are up to date."]:
        return [], []
    header = re.fullmatch(r"The following ([1-9][0-9]*) package\(s\) will be affected \(of [0-9]+ checked\):", lines[0]) if lines else None
    _require(header is not None, "Unrecognized pkg upgrade summary (including empty output)")
    actions, counts, totals, notes = [], {}, {}, []
    section = None
    for line in lines[1:]:
        if line in SECTIONS:
            section = SECTIONS[line]
            _require(section not in counts and not totals, "Repeated or misplaced pkg section")
            counts[section] = 0
        elif line.startswith("\t"):
            _require(section is not None and not totals, "Unexpected pkg action")
            # Reasons and vulnerability labels are bounded informational strings.
            row = re.sub(r" \([^()\x00-\x1f]{1,256}\)$", "", line)
            row = re.sub(r" \([^()\x00-\x1f]{1,256}\)$", "", row)
            row = re.sub(r" \[FreeBSD-ports\]$", "", row)
            if section == "reinstalled":
                match = re.fullmatch(r"\t(" + NAME + r")-(" + VERSION + r")", row)
                _require(match is not None, "Unrecognized pkg reinstall row")
                name, new = match.groups()
                old = new
            else:
                match = re.fullmatch(r"\t(" + NAME + r"): (" + VERSION + r")(?: -> (" + VERSION + r"))?", row)
                _require(match is not None, "Unrecognized pkg action row or repository")
                name, first, second = match.groups()
                _require(bool(second) == (section in ("upgraded", "downgraded")), "Incomplete pkg action")
                old = first if section != "installed" else None
                new = second if second else (None if section == "removed" else first)
            _require(name not in {item["name"] for item in actions}, "Duplicate pkg action")
            actions.append(dict(action=section, name=name, old_version=old, new_version=new))
            counts[section] += 1
        else:
            total = re.fullmatch(r"Number of packages to be (installed|upgraded|reinstalled|removed|downgraded): ([1-9][0-9]*)", line)
            if total:
                _require(total[1] not in totals and not notes, "Repeated or misplaced pkg total")
                totals[total[1]] = int(total[2])
            else:
                size = r"[0-9]{1,12}(?:\.[0-9]{1,2})? (?:B|KiB|MiB|GiB|TiB|PiB|EiB)"
                _require(bool(totals) and len(notes) < 4 and re.fullmatch(
                    r"(?:The process will require " + size + r" more space\.|The operation will free " + size
                    + r"\.|" + size + r" to be downloaded\.|WARNING: [1-9][0-9]* package\(s\) have known vulnerabilities)", line),
                    "Unrecognized pkg action or informational output")
                notes.append(line)
    _require(counts == totals and all(counts.values()) and len(actions) == int(header[1]), "Incomplete pkg action totals")
    return sorted(actions, key=lambda item: item["name"]), notes


def parse_repository(output, abi, branch):
    """Allowlist the effective native repository display; never return raw config."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    _require(lines and lines[0] == REPO + ": {" and lines[-1] == "}", "Missing or ambiguous FreeBSD-ports configuration")
    fields = {}
    for line in lines[1:-1]:
        match = re.fullmatch(r'([a-z_]+)\s*:\s*("[^"\x00-\x1f]*"|yes|no|-?[0-9]+)(?: \(overridden by pkg\))?,?', line)
        _require(match is not None and match[1] not in fields, "Unsupported native repository configuration")
        fields[match[1]] = match[2].strip('"')
    expected = {"url": "pkg+https://pkg.FreeBSD.org/" + abi + "/" + branch,
                "enabled": "yes", "mirror_type": "SRV", "signature_type": "FINGERPRINTS",
                "fingerprints": "/usr/share/keys/pkg"}
    _require(set(fields) <= set(expected) | {"priority", "ip_version"}, "Unsupported repository authentication or transport override")
    normalized = dict(fields)
    normalized["url"] = normalized.get("url", "").replace("pkg.freebsd.org/", "pkg.FreeBSD.org/")
    _require(all(normalized.get(key) == value for key, value in expected.items()),
             "FreeBSD-ports must use the official HTTPS repository and native FreeBSD fingerprints")
    return fields


def _repository(target, jail, environment):
    _require(_output(target, jail, *PKG, "-v").strip() == "2.8.4", "Only reviewed pkg 2.8.4 output/commands are supported; update pkg separately")
    settings = {"ABI": environment["abi"], "PKG_DBDIR": "/var/db/pkg", "RUN_SCRIPTS": "yes",
                "SAT_SOLVER": "", "CUDF_SOLVER": "", "PKG_ENV": ""}
    for key, expected in settings.items():
        _require(_output(target, jail, *PKG, "config", key).strip() == expected,
                 "Unsupported effective pkg configuration: " + key)
    # Harmless aliases may remain; never allow an alias for a command we invoke.
    aliases = _output(target, jail, *PKG, "config", "ALIAS")
    _require(not re.search(r"(?m)^(?:config|query|rquery|repositories|update|upgrade):", aliases), "pkg command aliases require manual review")
    _require(release_base(_output(target, jail, "/bin/freebsd-version", "-u").strip()) == environment["release"], "Jail userland release differs from reviewed policy")
    repository = parse_repository(_output(target, jail, *PKG, "repositories", REPO), environment["abi"], target.config.repository)
    keys = _output(target, jail, "/bin/sh", "-c", KEYS)
    key_pattern = r'\s*function:\s*"sha256"\s+fingerprint:\s*"' + FINGERPRINT + r'"\s*'
    _require(bool(keys.strip()) and re.fullmatch("(?:" + key_pattern + ")+", keys), "Unreviewed FreeBSD ports trust key; review native key rotation/custom trust first")
    repository["trusted_fingerprint"] = FINGERPRINT
    return repository


def _installed(target, jail):
    records = _output(target, jail, *PKG, "query", "-a", "%n|%v|%o|%q|%#d")
    dependencies = _output(target, jail, *PKG, "query", "-a", "%n|%dn|%dv|%do")
    packages, counts = {}, {}
    for line in records.splitlines():
        fields = line.split("|")
        _require(len(fields) == 5, "Malformed installed package inventory")
        name, version, origin, abi, count = fields
        _require(re.fullmatch(NAME, name) and re.fullmatch(VERSION, version) and re.fullmatch(ORIGIN, origin)
                 and re.fullmatch(r"FreeBSD:[0-9]+:(?:[A-Za-z0-9_]+|\*)", abi)
                 and re.fullmatch(r"[0-9]{1,5}", count) and name not in packages, "Ambiguous installed package inventory")
        packages[name] = dict(name=name, version=version, origin=origin, abi=abi, dependencies={})
        counts[name] = int(count)
    _require(bool(packages), "Empty installed package inventory")
    for line in dependencies.splitlines():
        fields = line.split("|")
        _require(len(fields) == 4 and fields[0] in packages, "Malformed installed dependency inventory")
        name, dependency, version, origin = fields
        if not any(fields[1:]):
            continue
        _require(re.fullmatch(NAME, dependency) and re.fullmatch(VERSION, version) and re.fullmatch(ORIGIN, origin)
                 and dependency not in packages[name]["dependencies"], "Ambiguous installed dependency inventory")
        packages[name]["dependencies"][dependency] = dict(version=version, origin=origin)
    _require(all(len(packages[name]["dependencies"]) == count for name, count in counts.items()), "Incomplete installed dependency inventory")
    return packages


def _roots(config, profile, group, installed):
    names = profile_roots(config, profile)[group]
    management = {name for feature in ("zsh", "ssh_admin")
                  for name in profile["optional_roots"][feature].get(group, [])}
    names = [name for name in names if name not in management]
    if group == "onlyoffice":
        names += ["www/nginx", "sysutils/py-supervisor"]
    result = []
    for name in names:
        matches = [key for key, record in installed.items() if (record["origin"] == name if "/" in name else key == name)]
        _require(len(matches) == 1, "Required installed upgrade root missing or ambiguous: " + name)
        result.extend(matches)
    return sorted(set(result))


def _closure(packages, roots, abi):
    seen, pending = set(), list(roots)
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        _require(name in packages, "Native dependency graph is incomplete: " + name)
        item = packages[name]
        _require(not name.startswith("FreeBSD-") and not item["origin"].startswith("base/")
                 and name not in ("pkg", "pkg-devel", "bastille"), "Host/pkgbase/package-manager change is outside application upgrades")
        _require(all(a in (b, "*") for a, b in zip(item["abi"].split(":"), abi.split(":"))), "Wrong ABI in application dependency graph")
        _require(not (re.match(r"php[0-9]", name) and name != "php85" and not name.startswith("php85-"))
                 and not (name.startswith(("mariadb", "mysql", "postgresql")) and not name.startswith("mariadb123-")),
                 "Automatic PHP/database family changes are unsupported")
        seen.add(name)
        for dependency, required in item["dependencies"].items():
            _require(dependency in packages and packages[dependency]["origin"] == required["origin"], "Missing or changed dependency origin")
            pending.append(dependency)
    return seen


def _compatible(packages, profile, group):
    # Fresh-install families are not upgrade authority. This native adapter was
    # reviewed only for Docs 9.4.0 (including native revisions/epochs), regardless
    # of later install-policy widening. Connector archives and host Bastille are
    # not upgraded here; host/package-manager dependencies remain forbidden.
    if group == "onlyoffice":
        item = packages.get("onlyoffice-documentserver")
        _require(item is not None and item["origin"] == "www/onlyoffice-documentserver"
                 and in_range(item["version"], {"exact": "9.4.0"}),
                 "ONLYOFFICE upgrade adapter supports Docs 9.4.0 only")
    for rule in profile["roles"].values():
        if group in rule["groups"]:
            item = packages.get(rule["package"])
            _require(item is not None and item["origin"] == rule["origin"]
                     and ("range" not in rule or in_range(item["version"], rule["range"])),
                     "Installed/selected runtime is outside reviewed compatibility: " + rule["package"])
    if group == "nextcloud":
        for pattern in profile["php_extensions"]:
            name = pattern.replace("{suffix}", profile["php_suffix"])
            if "-pecl-" not in name:
                _require(name in packages and in_range(packages[name]["version"], profile["roles"]["php"]["range"]),
                         "PHP extension family change is unsupported: " + name)
        for pattern, bounds in profile["extension_ranges"].items():
            name = pattern.replace("{suffix}", profile["php_suffix"])
            _require(name in packages and in_range(packages[name]["version"], bounds), "PHP extension outside reviewed compatibility: " + name)


def _jail_plan(target, group, profile, environment, refresh):
    jail = target.nc if group == "nextcloud" else target.office
    repository = _repository(target, jail, environment)
    installed = _installed(target, jail)
    roots = _roots(target.config, profile, group, installed)
    _compatible(installed, profile, group)
    _closure(installed, roots, environment["abi"])
    if refresh:
        # -f authenticates a fresh catalog even if an old local catalog was unsigned.
        _output(target, jail, *PKG, "update", "-f", "-r", REPO, timeout=600)
    actions, notes = parse_summary(_output(target, jail, *PKG, "upgrade", "-n", "-U", "-r", REPO, *roots, timeout=600))
    _require(all(item["action"] not in ("removed", "downgraded") for item in actions), "Package removal/downgrade requires a separately reviewed native procedure")
    selected = {}
    if actions:
        names = [item["name"] for item in actions]
        _require(len(names) <= 512, "Package transaction is too large for bounded native review")
        records = _output(target, jail, *PKG, "rquery", "-U", "-r", REPO, "%n|%v|%o|%q|%#d|%u%d%{%|%}", *names)
        deps = _output(target, jail, *PKG, "rquery", "-U", "-r", REPO, "%n|%dn|%dv|%do", *names)
        try:
            selected = package_catalog(records, deps)
        except ValueError:
            raise PackageUpgradeError("Invalid selected signed package metadata") from None
        _require(set(selected) == set(names), "Selected repository packages are incomplete or ambiguous")
    expected = deepcopy(installed)
    for action in actions:
        name = action["name"]
        old, new = installed.get(name), selected[name]
        _require((old["version"] if old else None) == action["old_version"] and new["version"] == action["new_version"], "Native solver version differs from installed/repository metadata")
        _require(old is None or (old["origin"], old["abi"]) == (new["origin"], new["abi"]), "Package origin/ABI transitions require manual review")
        action.update(old=deepcopy(old), new=deepcopy(new))
        expected[name] = {key: value for key, value in new.items() if key != "checksum"}
    allowed = _closure(expected, roots, environment["abi"])
    _require(all(item["name"] in allowed for item in actions), "Native solver affects packages outside reviewed roots/dependencies")
    _compatible(expected, profile, group)
    return dict(jail=jail, root=str(target.nc_root if group == "nextcloud" else target.office_root),
                repository=repository, roots=roots, installed=installed, expected=expected,
                actions=actions, notes=notes)


def _plan(target, nextcloud_path, refresh):
    policy = load_policy()
    _require(target.config.repository in ("latest", "quarterly"), "Unsupported FreeBSD ports repository branch")
    effective = constraints(target.config, policy)
    environment = policy_target(policy, effective["freebsd_release"], effective["architecture"])
    source = _output(target, target.nc, "/bin/cat", "/usr/local/www/nextcloud/version.php")
    versions = re.findall(r"(?m)^\$OC_VersionString\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+)'\s*;", source)
    _require(len(versions) == 1, "Cannot establish the live Nextcloud code version")
    path = [versions[0], *nextcloud_path]
    _require(all(isinstance(version, str) and version in ("35.0.1", "35.0.2") for version in path), "Only reviewed NC35 patch paths are supported")
    _require(all(stable_version(a) <= stable_version(b) for a, b in zip(path, path[1:])), "Nextcloud downgrade paths are unsupported")
    profiles = [p for p in policy["profiles"] if p.get("office_backend", "onlyoffice") == "onlyoffice"
                and environment["release"] + "/" + environment["architecture"] in p["targets"]
                and all(in_range(v, p["applications"]["nextcloud"]) or
                        (v == "35.0.2" and p["id"] == "nc35-oo94-php85-mariadb123") for v in path)]
    # The explicit 35.0.2 extension is tagged source evidence above, not a widening
    # of the installer's central policy or a guessed future patch/major capability.
    _require(len(profiles) == 1, "No reviewed compatibility profile covers every Nextcloud step")
    jails = {group: _jail_plan(target, group, profiles[0], environment, refresh)
             for group in ("nextcloud", "onlyoffice")}
    return dict(schema_version=1, nextcloud_path=path, profile=profiles[0]["id"], jails=jails,
                status="changes-available" if any(j["actions"] for j in jails.values()) else "no-compatible-package-changes",
                catalog_refresh="Planning refreshes and authenticates jail pkg catalogs; installed packages are unchanged.",
                sources=SOURCES.copy())


def plan(target, *, nextcloud_path=("35.0.2",)):
    """Refresh signed catalogs and solve against each actual installed database."""
    return _plan(target, nextcloud_path, True)


def _same(actual, approved):
    # Download-size notes change when packages enter the native cache; identities,
    # archive checksums, installed inventory, dependency graph and actions may not.
    left, right = deepcopy(actual), deepcopy(approved)
    for value in (left, right):
        for jail in value["jails"].values():
            jail.pop("notes", None)
    return left == right


def revalidate(target, approved):
    """Repeat the complete installed-state solve WITHOUT catalog refresh."""
    _require(isinstance(approved, dict) and approved.get("schema_version") == 1
             and isinstance(approved.get("nextcloud_path"), list) and approved["nextcloud_path"], "Invalid approved package plan")
    current = _plan(target, approved["nextcloud_path"][1:], False)
    _require(_same(current, approved), "Package plan changed; obtain a new reviewed plan and consent")
    return current


def _verify_inventory(actual, expected):
    """Keep exact package identities; allow native reverse-dependency bookkeeping.

    pkgdb.c:DEPS_UPDATE can rewrite an unchanged dependent's requirement version
    when its provider is registered. Accept only the declared version or that
    exact installed provider version, never arbitrary changed edges/versions.
    """
    if actual.keys() != expected.keys():
        return False
    normalized = deepcopy(actual)
    for name, item in normalized.items():
        required = expected[name]["dependencies"]
        if item["dependencies"].keys() != required.keys():
            return False
        for dependency, edge in item["dependencies"].items():
            versions = {required[dependency]["version"]}
            if dependency in expected:
                versions.add(expected[dependency]["version"])
            if edge["version"] not in versions or edge["origin"] != required[dependency]["origin"]:
                return False
            edge["version"] = required[dependency]["version"]
    return normalized == expected


def apply(target, approved):
    """Fetch, revalidate, apply once; return a sanitized partial/failure report.

    Maintenance/service shutdown and application-native post-upgrade migrations
    belong to the caller. A successful pkg transaction is not application readiness.
    """
    completed, phase, active = [], "revalidate", None
    try:
        current = revalidate(target, approved)
        for group, jail in current["jails"].items():
            if jail["actions"]:
                phase, active = "fetch", group
                _output(target, jail["jail"], *PKG, "upgrade", "-F", "-U", "-r", REPO, *jail["roots"], input="y\n", timeout=1800)
        phase = "revalidate-after-fetch"
        current = revalidate(target, approved)
        for group, jail in current["jails"].items():
            if not jail["actions"]:
                continue
            phase, active = "execute", group
            # No -y: pkg may discover a new conflict job after fetching. One answer
            # authorizes only the first job; EOF refuses any subsequent solver job.
            _output(target, jail["jail"], *PKG, "upgrade", "-U", "-r", REPO, *jail["roots"], input="y\n", timeout=1800)
            phase = "verify-inventory"
            _require(_verify_inventory(_installed(target, jail["jail"]), jail["expected"]), "Installed package result differs from the approved transaction")
            completed.append(group)
        return dict(status="applied" if completed else "no-compatible-package-changes", completed=completed,
                    application_verification_required=bool(completed))
    except Exception as error:
        return dict(status="failed", completed=completed, phase=phase, jail=active,
                    error=str(error) if isinstance(error, PackageUpgradeError) else "Native package operation could not complete",
                    installed_state_uncertain=phase in ("execute", "verify-inventory"),
                    recovery="Inspect installed packages and application state; no automatic replay or rollback was attempted.")
