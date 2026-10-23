"""Availability only: upstream stable archives and signed FreeBSD pkg catalogs.

No compatibility decisions, package installs, ports builds or application writes
belong here. The native adapter uses an isolated, disposable catalog database.
"""

from contextlib import contextmanager
from html.parser import HTMLParser
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit, urlencode
import urllib.error
import urllib.request


NEXTCLOUD_RELEASES = "https://download.nextcloud.com/server/releases/"
ONLYOFFICE_RELEASES = "https://api.github.com/repos/ONLYOFFICE/DocumentServer/releases?per_page=100"
CONNECTORS = "https://apps.nextcloud.com/api/v1/platform/{version}/apps.json"
LIMIT = 16 * 1024 * 1024
NAME = r"[A-Za-z0-9][A-Za-z0-9_+.-]*"
VERSION = r"[A-Za-z0-9._+][A-Za-z0-9_+.,~:-]*"
ORIGIN = r"[A-Za-z0-9_+.-]+/[A-Za-z0-9_+.-]+"
CHECKSUM = r"(?=.{1,256}\Z)(?:[0-9]+\$[A-Za-z0-9]+|[A-Fa-f0-9]{64})"


class DiscoveryError(ValueError):
    """Availability could not be established; do not substitute a default."""


class _HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        if urlsplit(url).scheme != "https" or urlsplit(url).netloc != urlsplit(request.full_url).netloc:
            raise DiscoveryError("Release metadata redirected outside its authoritative HTTPS origin")
        return super().redirect_request(request, fp, code, message, headers, url)


def fetch_releases(url=NEXTCLOUD_RELEASES):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _HTTPSOnly())
    try:
        with opener.open(url, timeout=30) as response:
            data = response.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise DiscoveryError("Release metadata exceeds its size limit")
        return data.decode("utf-8")
    except (OSError, UnicodeError, urllib.error.URLError) as error:
        raise DiscoveryError("Authoritative release metadata is unavailable; check HTTPS/DNS and retry (no fallback selected)") from error


def onlyoffice_versions(text):
    try:
        releases = json.loads(text)
        if not isinstance(releases, list) or len(releases) > 100:
            raise ValueError
        result = set()
        for item in releases:
            if not isinstance(item, dict):
                raise ValueError
            tag = item.get("tag_name", "")
            if (item.get("prerelease") is False and item.get("draft") is False
                    and isinstance(tag, str) and re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+", tag)):
                result.add(tag.removeprefix("v"))
        if not result:
            raise ValueError
        return sorted(result, key=lambda value: tuple(map(int, value.split("."))), reverse=True)
    except (TypeError, ValueError):
        raise DiscoveryError("No valid stable ONLYOFFICE upstream releases were advertised (bounded to the latest 100 releases)") from None


def connector_releases(text, app_id="onlyoffice"):
    if app_id not in ("onlyoffice", "eurooffice", "richdocuments"):
        raise DiscoveryError("Unsupported integrated office connector ID")
    try:
        apps = json.loads(text)
        if not isinstance(apps, list) or any(not isinstance(item, dict) for item in apps):
            raise ValueError
        matches = [item for item in apps if item.get("id") == app_id]
        if not matches:
            return []  # This platform legitimately has no advertised connector.
        if (len(matches) != 1 or not isinstance(matches[0].get("certificate"), str)
                or not matches[0]["certificate"].strip() or not isinstance(matches[0].get("releases"), list)):
            raise ValueError
        result = []
        keys = ("version", "phpVersionSpec", "platformVersionSpec", "isNightly", "signatureDigest", "download", "signature")
        for item in matches[0]["releases"]:
            if (not isinstance(item, dict) or type(item.get("isNightly")) is not bool
                    or not isinstance(item.get("version"), str) or not item["version"].strip()):
                raise ValueError
            if item["isNightly"]:
                continue
            if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", item["version"]):
                continue
            record = {key: item[key] for key in keys}
            if any(not isinstance(record[key], str) or not record[key].strip() for key in keys if key != "isNightly"):
                raise ValueError
            record["certificate"] = matches[0]["certificate"]
            result.append(record)
        return result
    except (KeyError, TypeError, ValueError, AttributeError):
        label = "ONLYOFFICE" if app_id == "onlyoffice" else app_id
        raise DiscoveryError(f"Signed stable {label} connector metadata is missing or malformed") from None


def _vm_metadata(url, *, headers=None, method="GET"):
    """Bounded metadata only; registry bearer tokens never leave their origin."""
    if urlsplit(url).scheme != "https":
        raise DiscoveryError("VM metadata requires authoritative HTTPS")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _HTTPSOnly())
    try:
        request = urllib.request.Request(url, headers=headers or {}, method=method)
        with opener.open(request, timeout=30) as response:
            if response.status != 200:
                raise ValueError
            body = b"" if method == "HEAD" else response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise ValueError
            return body, dict(response.headers)
    except (OSError, ValueError, urllib.error.URLError):
        raise DiscoveryError("Pinned VM artifact metadata unavailable; check HTTPS/DNS/registry access (no fallback)") from None


def probe_vm_artifacts(runtime, *, request=None):
    """Verify pinned OCI index/platform-manifest hashes and guest checksum.

    Only official GHCR/Docker Hub pull protocols are supported. No layers/images
    are downloaded and no hypervisor is probed. Blob/CDN redirects are unnecessary:
    the pinned index binds linux/amd64 to the exact selected platform manifest.
    """
    from .versions import validate_office_runtime
    runtime = validate_office_runtime(runtime)
    request = _vm_metadata if request is None else request
    image, container = runtime["guest_image"], runtime["container"]
    try:
        checksum, _ = request(image["url"] + ".sha512")
        fields = checksum.decode('ascii').split()
        if (len(fields) not in (1, 2) or not re.fullmatch(r"[a-fA-F0-9]{128}", fields[0])
                or fields[0].lower() != image["sha512"]
                or (len(fields) == 2 and fields[1].lstrip('*') != image["url"].rsplit('/', 1)[-1])):
            raise ValueError
        _, head = request(image["url"], method="HEAD")
        size = next((v for k, v in head.items() if k.lower() == 'content-length'), None)
        if size is not None and (not str(size).isdigit() or not 0 < int(size) <= 2 * 1024**3):
            raise ValueError
        registry, repository = container["reference"].split('/', 1)
        repository, digest = repository.split('@', 1)
        if registry == 'ghcr.io':
            server, token_url, service = 'ghcr.io', 'https://ghcr.io/token', 'ghcr.io'
        elif registry == 'docker.io':
            server, token_url, service = 'registry-1.docker.io', 'https://auth.docker.io/token', 'registry.docker.io'
        else:
            raise ValueError
        token_body, _ = request(token_url + '?' + urlencode(dict(service=service, scope='repository:' + repository + ':pull')))
        token_record = json.loads(token_body)
        token = token_record.get('token', token_record.get('access_token'))
        if (not isinstance(token, str) or not token or len(token) > 65536
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError
        headers = {'Authorization': 'Bearer ' + token,
                   'Accept': 'application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'}
        base = 'https://' + server + '/v2/' + repository + '/manifests/'
        index_body, _ = request(base + container['index_digest'], headers=headers)
        if 'sha256:' + hashlib.sha256(index_body).hexdigest() != container['index_digest']:
            raise ValueError
        index = json.loads(index_body)
        if type(index.get('schemaVersion')) is not int or index['schemaVersion'] != 2:
            raise ValueError
        choices = [item for item in index['manifests']
                   if item.get('platform', {}).get('architecture') == container['architecture']
                   and item.get('platform', {}).get('os') == 'linux' and item.get('digest') == digest]
        if len(choices) != 1:
            raise ValueError
        manifest_body, _ = request(base + digest, headers=headers)
        if 'sha256:' + hashlib.sha256(manifest_body).hexdigest() != digest:
            raise ValueError
        manifest = json.loads(manifest_body)
        if (type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2
                or not isinstance(manifest.get('layers'), list) or not manifest['layers']
                or not re.fullmatch(r'sha256:[a-f0-9]{64}', manifest.get('config', {}).get('digest', ''))):
            raise ValueError
        return {'guest_image': {'url': image['url'], 'sha512': image['sha512'], 'available': True},
                'container': {key: container[key] for key in ('reference','index_digest','architecture')} | {'os': 'linux', 'available': True}}
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        raise DiscoveryError('Pinned guest checksum or OCI index/platform identity is unavailable or mismatched') from None


def nextcloud_versions(text):
    """Only explicit numeric, signed release archives, never latest/RC/beta links."""
    if not isinstance(text, str) or len(text.encode()) > LIMIT:
        raise DiscoveryError("Invalid or oversized Nextcloud release metadata")

    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.names = set()

        def handle_starttag(self, tag, attrs):
            if tag == "a":
                for key, value in attrs:
                    if key == "href" and value and re.fullmatch(r"nextcloud-[0-9]+\.[0-9]+\.[0-9]+\.tar\.bz2(?:\.asc)?", value):
                        self.names.add(value)

    parser = Links()
    parser.feed(text)
    versions = {name[len("nextcloud-"):-len(".tar.bz2")] for name in parser.names
                if name.endswith(".tar.bz2") and name + ".asc" in parser.names}
    if not versions:
        raise DiscoveryError("No explicit stable Nextcloud archives with detached signatures were advertised")
    return sorted(versions, key=lambda value: tuple(map(int, value.split("."))), reverse=True)


def package_catalog(records, dependencies):
    """Parse pkg rquery output without interpreting executable repository data."""
    if any(not isinstance(text, str) or len(text.encode()) > LIMIT for text in (records, dependencies)):
        raise DiscoveryError("Invalid or oversized package metadata")
    result, counts, ambiguous, unversioned = {}, {}, set(), set()
    for line in records.splitlines():
        values = line.split("|")
        if len(values) != 6:
            raise DiscoveryError("Package catalog fields are missing")
        name, version, origin, abi, count, checksum = values
        if (not re.fullmatch(NAME, name) or not re.fullmatch(VERSION, version)
                or not re.fullmatch(ORIGIN, origin) or not re.fullmatch(r"FreeBSD:[0-9]+:(?:[A-Za-z0-9_]+|\*)", abi)
                or not re.fullmatch(r"[0-9]{1,5}", count) or not re.fullmatch(CHECKSUM, checksum)):
            raise DiscoveryError("Unsafe package catalog entry")
        if name in result:
            ambiguous.add(name)
        result[name] = dict(name=name, version=version, origin=origin, abi=abi, checksum=checksum, dependencies={})
        counts[name] = int(count)
    # A duplicate outside the selected closure must not invalidate unrelated
    # packages. Remove every ambiguous name, never select a last-wins record.
    for name in ambiguous:
        result.pop(name)
    if not result:
        raise DiscoveryError("The selected package repository returned an empty catalog")
    for line in dependencies.splitlines():
        values = line.split("|")
        if len(values) != 4:
            raise DiscoveryError("Package dependency metadata fields are missing")
        name, dependency, version, origin = values
        if name in ambiguous:
            continue
        if name not in result:
            raise DiscoveryError("Dependency metadata names an unknown package")
        if (dependency, version, origin) == ("", "", ""):
            continue
        if (not re.fullmatch(NAME, dependency) or (version and not re.fullmatch(VERSION, version))
                or not re.fullmatch(ORIGIN, origin) or dependency in result[name]["dependencies"]):
            raise DiscoveryError("Unsafe or ambiguous package dependency metadata")
        if not version:
            # Signed catalogs may retain references to unavailable/restricted
            # ports without a dependency version. Never guess a lock for them.
            unversioned.add(name)
        result[name]["dependencies"][dependency] = {"version": version, "origin": origin}
    if any(len(item["dependencies"]) != counts[name] for name, item in result.items()):
        raise DiscoveryError("Incomplete package dependency metadata; declared counts do not match")
    # As with ambiguous names, unrelated unusable packages must not invalidate
    # the entire repository. Keep references from other packages: closure()
    # will still reject any selected root that needs an omitted package.
    for name in unversioned:
        result.pop(name)
    if not result:
        raise DiscoveryError("The selected package repository returned no fully versioned packages")
    return result


@contextmanager
def _catalog(config, runner, *, directory=None, policy=None):
    """Read the selected native repository, never the host's configured catalogs.

    pkg authenticates metadata using FreeBSD base fingerprints. Temporary repo,
    database and cache directories are private; no installed package database is
    changed. This adapter only queries the actual, matching FreeBSD environment.
    """
    from .versions import constraints, load_policy, target, release_base, selected_profiles
    policy = load_policy() if policy is None else policy
    selected_profiles(config, policy)
    selected = constraints(config, policy)
    environment = target(policy, selected["freebsd_release"], selected["architecture"])
    if (runner.output("uname", "-s") != "FreeBSD"
            or release_base(runner.output("freebsd-version", "-u")) != environment["release"]
            or release_base(runner.output("freebsd-version", "-r")) != environment["release"]
            or runner.output("uname", "-m") != environment["architecture"]):
        raise DiscoveryError("Native package discovery requires the selected FreeBSD release/kernel and architecture; use mocked metadata for offline assessment")
    if runner.run("/usr/sbin/pkg", "-N", check=False).returncode != 0:
        raise DiscoveryError("Native discovery needs an already bootstrapped pkg; resolve never bootstraps or installs host dependencies")
    # pkg guesses the .0 OSVERSION when ABI is supplied alone. Preserve the
    # already-validated native userland's minor release, never ignore OS checks.
    osversion = runner.output("uname", "-U")
    if not re.fullmatch(r"[1-9][0-9]{6,8}", osversion):
        raise DiscoveryError("Native userland OSVERSION is invalid; cannot safely query the selected repository")
    with tempfile.TemporaryDirectory(prefix="version-catalog-", dir=directory) as temporary:
        root = Path(temporary)
        for name in ("repos", "db", "cache"):
            (root / name).mkdir(mode=0o700)
        (root / "repos/FreeBSD.conf").write_text('''FreeBSD-ports: {
  url: "pkg+https://pkg.FreeBSD.org/''' + environment["abi"] + "/" + config.repository + '''",
  mirror_type: "srv", signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg", enabled: yes
}
''')
        command = ("/usr/bin/env", "-i", "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
                   "LC_ALL=C", "pkg", "-C", "/dev/null", "-o", f"REPOS_DIR={root / 'repos'}", "-o", f"PKG_DBDIR={root / 'db'}",
                   "-o", f"PKG_CACHEDIR={root / 'cache'}", "-o", f"ABI={environment['abi']}",
                   "-o", f"OSVERSION={osversion}")
        try:
            # Captured output must never hide a pkg question while it reads the
            # operator's terminal (for example an OS-version mismatch prompt).
            runner.run(*command, "update", "-r", "FreeBSD-ports", input="")
            # pkg 2.8.4: %{ selects pkg_printf; %u preserves catalog sum
            # (archive checksum), whereas %X recomputes an internal digest.
            # Explicitly empty dependency item/separator formats emit nothing.
            records = runner.output(*command, "rquery", "-U", "-r", "FreeBSD-ports", "-a", "%n|%v|%o|%q|%#d|%u%d%{%|%}")
            dependencies = runner.output(*command, "rquery", "-U", "-r", "FreeBSD-ports", "-a", "%n|%dn|%dv|%do")
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            raise DiscoveryError("Signed FreeBSD package metadata is unavailable for the selected ABI/branch; check repository reachability, base trust keys and pkg's extended checksum-query support (review/update pkg separately)") from error
        packages = package_catalog(records, dependencies)
        yield environment, packages, command


def discover(config, runner, *, directory=None, fetch=fetch_releases, policy=None):
    """Discover stable upstream archives and packages, without selecting any."""
    from .compatibility import profile_roots
    from .versions import (constraints, in_range, load_policy, office_backend,
                           satisfies, selected_profiles, stable_version, validate_policy)
    policy = load_policy() if policy is None else policy
    validate_policy(policy)
    backend = office_backend(config)
    limits = constraints(config, policy)
    profiles = selected_profiles(config, policy)
    # Native discovery retains the complete catalog. Its package roots are
    # checked only by compatibility.validate, after matching a candidate's
    # target/backend, NC/OO versions and constraints. An eager union here would
    # let an irrelevant future profile's feature requirements block discovery.
    releases = nextcloud_versions(fetch(NEXTCLOUD_RELEASES))
    if backend != "onlyoffice":
        candidates = [version for version in releases if satisfies(version, "nextcloud", limits)]
        profiles = [profile for profile in profiles
                    if any(in_range(version, profile["applications"]["nextcloud"]) for version in candidates)]
        if backend != 'none':
            candidates = [version for version in candidates if any(in_range(version, profile['applications']['nextcloud']) for profile in profiles)]
            if len(candidates) > 32 or len(profiles) > 8:
                raise DiscoveryError('Narrow Nextcloud constraints to bound VM/connector metadata queries')
        requirements, errors = set(), []
        for profile in profiles:
            try:
                roots = profile_roots(config, profile)
            except ValueError as error:
                # A profile without a selected feature must not poison another
                # candidate. Resolution will explain that candidate's refusal.
                errors.append(str(error))
                continue
            requirements.update(name for names in roots.values() for name in names)
        if not requirements:
            raise DiscoveryError("No reviewed Nextcloud package profile matches discovery constraints"
                                 + (": " + "; ".join(dict.fromkeys(errors)) if errors else ""))
        with _catalog(config, runner, directory=directory, policy=policy) as (environment, packages, _):
            # Retain available records, including ambiguous origins and broken
            # dependency edges. Exact closure validation belongs to each resolver
            # candidate: an unavailable newer root must allow an older fallback.
            pending = {name for name, record in packages.items()
                       if name in requirements or record["origin"] in requirements}
            selected = {}
            while pending:
                name = pending.pop()
                if name in selected or name not in packages:
                    continue
                selected[name] = packages[name]
                pending.update(packages[name]["dependencies"])
            selected = {name: selected[name] for name in sorted(selected)}
        result = {"schema_version": 2, "office_backend": backend, "target": environment,
                "repository": config.repository, "nextcloud": releases, "packages": selected,
                "sources": [NEXTCLOUD_RELEASES, f"https://pkg.FreeBSD.org/{environment['abi']}/{config.repository}/"]}
        if backend != 'none':
            from .versions import CONNECTOR_APPS
            app_id = CONNECTOR_APPS[backend]
            result.update(schema_version=3, connector_app=app_id,
                          connectors={version: connector_releases(fetch(CONNECTORS.format(version=version)), app_id) for version in candidates},
                          artifacts={})
            for profile in profiles:
                try:
                    result['artifacts'][profile['id']] = probe_vm_artifacts(profile['office_runtime'])
                except DiscoveryError:
                    result['artifacts'][profile['id']] = {'unavailable': True}
            result['sources'].extend(CONNECTORS.format(version=version) for version in candidates)
            result['sources'].extend(profile['office_runtime']['guest_image']['url'] + '.sha512' for profile in profiles)
        return result
    office = onlyoffice_versions(fetch(ONLYOFFICE_RELEASES))
    # Discovery may apply user constraints but must not equate them to support.
    candidates = [version for version in releases if satisfies(version, "nextcloud", limits)
                  and any(in_range(version, profile["applications"]["nextcloud"]) for profile in profiles)]
    if len(candidates) > 32:
        raise DiscoveryError("More than 32 releases meet the discovery constraints; raise the minimum or set an exact pin to bound metadata requests")
    connectors = {version: connector_releases(fetch(CONNECTORS.format(version=version))) for version in candidates}
    with _catalog(config, runner, directory=directory, policy=policy) as (environment, packages, _):
        pass
    return {"schema_version": 1, "target": environment, "repository": config.repository,
            "nextcloud": releases, "onlyoffice": office, "connectors": connectors, "packages": packages,
            "sources": [NEXTCLOUD_RELEASES, ONLYOFFICE_RELEASES,
                        f"https://pkg.FreeBSD.org/{environment['abi']}/{config.repository}/",
                        *(CONNECTORS.format(version=version) for version in candidates)]}


def check_solver_plan(output, packages):
    """Fail closed on pkg 2.8.4's C-locale, empty-DB install dry-run summary.

    Exit zero means solvable, not that pkg selected only the requested lock:
    shared-library providers can be added independently of declared edges.
    This reviewed text interface is not a generic/stable pkg JSON interface.
    """
    if not isinstance(output, str) or len(output.encode()) > LIMIT:
        raise DiscoveryError("Invalid or oversized native solver summary")
    lines = [line for line in output.splitlines() if line.strip()]
    if lines and lines[0] == "Updating database digests format: . done":
        lines.pop(0)
    header = re.fullmatch(r"The following ([1-9][0-9]*) package\(s\) will be affected \(of [0-9]+ checked\):", lines[0]) if lines else None
    if not header or len(lines) < 4 or lines[1] != "New packages to be INSTALLED:":
        raise DiscoveryError("Unrecognized native solver summary; provisioning refused")
    planned = {}
    index = 2
    while index < len(lines) and lines[index].startswith("\t"):
        row = re.fullmatch(r"\t(" + NAME + r"): (" + VERSION + r")(?: \[FreeBSD-ports\])?(?: \(vulnerable!\))?", lines[index])
        if not row or row[1] in planned:
            raise DiscoveryError("Malformed or duplicate native solver package")
        planned[row[1]] = row[2]
        index += 1
    total = re.fullmatch(r"Number of packages to be installed: ([1-9][0-9]*)", lines[index]) if index < len(lines) else None
    if not total or int(total[1]) != len(planned) or int(header[1]) != len(planned):
        raise DiscoveryError("Incomplete or unexpected native solver actions; provisioning refused")
    # Only reviewed informational trailers may follow; never skip another job
    # section, changed package, or a second summary.
    trailers = [r"The process will require [0-9]+(?:\.[0-9]+)? (?:B|KiB|MiB|GiB|TiB) more space\.",
                r"[0-9]+(?:\.[0-9]+)? (?:B|KiB|MiB|GiB|TiB) to be downloaded\.",
                r"The most recent versions of packages are already installed"]
    remaining = lines[index + 1:]
    for pattern in trailers:
        if remaining and re.fullmatch(pattern, remaining[0]):
            remaining.pop(0)
    if remaining:
        raise DiscoveryError("Unrecognized native solver actions or output; provisioning refused")
    expected = {name: item["version"] for name, item in packages.items()}
    if planned != expected:
        raise DiscoveryError("Native solver package set differs from the immutable lock; review shared-library providers and dependencies before provisioning")


def probe_packages(config, plan, runner, *, directory=None):
    """Native solver dry-runs in an empty private DB, before provisioning.

    This is an execution-boundary check, not version selection. Repositories may
    have changed since discovery; drift or solver conflicts never rewrite a lock.
    """
    from .resolution import _plan_inventory
    from .versions import office_backend
    backend = office_backend(config)
    if backend != plan.get("office_backend", "onlyoffice"):
        raise DiscoveryError("Package probe backend does not match the retained plan")
    if backend != "onlyoffice":
        _plan_inventory(plan)
    with _catalog(config, runner, directory=directory) as (_, available, command):
        for group, packages in plan["packages"].items():
            for name, package in packages.items():
                if available.get(name) != package:
                    raise DiscoveryError(f"Locked {group} package {name} changed or is unavailable; preserve the lock and use the original repository snapshot")
            args = [name + "-" + value["version"] for name, value in sorted(packages.items())]
            if not args:
                raise DiscoveryError("A resolved package group is empty")
            try:
                # pkg 2.8.4 reports a successful -n plan as declined unless -y
                # is also set. -n remains mandatory; this DB has no installs.
                result = runner.run(*command, "install", "-n", "-y", "-U", "-r", "FreeBSD-ports", *args, input="")
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                raise DiscoveryError(f"The native package solver rejected the locked {group} dependency set; inspect conflicts/OS requirements before installing") from error
            check_solver_plan(result.stdout, packages)
