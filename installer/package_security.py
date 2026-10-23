"""Explicit pkg 2.8.4 audit of retained package arguments, never the live DB.

Source evidence reviewed 2026-10-15 (native acceptance NOT RUN):
https://github.com/freebsd/pkg/blob/2.8.4/src/audit.c
https://github.com/freebsd/pkg/blob/2.8.4/libpkg/pkg_audit.c
https://github.com/freebsd/pkg/blob/2.8.4/libpkg/pkg_config.c
https://github.com/freebsd/pkg/blob/2.8.4/external/libucl/src/ucl_util.c

audit.c's explicit arguments avoid pkgdb_open; --raw=json reports affected
packages, not the number checked. Exit 1 with valid affected JSON is expected.
The NULL insertion in libucl omits "packages" when pkg_count is zero. No other
empty-result shape is inferred. Version comparison belongs to native pkg.

pkg_audit_fetch bounds download/extraction (64/256 MiB), stages then renames
its database, and does not verify an advisory signature. Our per-file limit is
64 MiB, output limit 4 MiB, and subprocess deadlines also bound this workflow.
The source is the fixed native HTTPS endpoint; native libfetch redirect policy
applies. This is not a signed feed or proof of exhaustive vulnerability coverage.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from xml.parsers import expat

from . import compatibility, resolution, security_assessment as core, versions
from .state import timestamp


SCHEMA_VERSION = 1
PKG_VERSION = "2.8.4"
PKG = "/usr/local/sbin/pkg"
SOURCE_URL = "https://vuxml.freebsd.org/freebsd/vuln.xml.xz"
SOURCE = "retained-intended-version"
MAX_PACKAGES = 4096
MAX_ARGUMENT_BYTES = 128 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_VUXML = 64 * 1024 * 1024
MAX_ISSUES = 10000
UUID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
NAMESPACE = "http://www.vuxml.org/apps/vuxml-1"
PATH = "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"


class PackageSecurityError(ValueError):
    """Fixed, non-sensitive diagnostic; subprocess output is never included."""


class NativeAuditUnavailable(PackageSecurityError):
    """No default native adapter on this platform; no bootstrap is attempted."""


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def packages_hash(packages):
    _packages(packages)
    return _hash(json.dumps(packages, sort_keys=True, separators=(",", ":")).encode())


def _packages(packages):
    if not isinstance(packages, dict) or not 1 <= len(packages) <= MAX_PACKAGES:
        raise PackageSecurityError("Missing or excessive retained package arguments")
    size = 0
    for name, version in packages.items():
        if (not isinstance(name, str) or not re.fullmatch(versions.NAME, name)
                or not isinstance(version, str) or len(version) > 512
                or not re.fullmatch(compatibility.VERSION, version)):
            raise PackageSecurityError("Unsupported explicit package argument")
        size += len(name) + len(version) + 2
    if size > MAX_ARGUMENT_BYTES:
        raise PackageSecurityError("Retained package arguments exceed limit")


def _arguments(packages):
    _packages(packages)
    # audit.c splits at the LAST dash. A dash inside an opaque version would
    # silently change the requested package name/version pair.
    if any("-" in version for version in packages.values()):
        raise PackageSecurityError("Unsupported dash in explicit package version")
    return tuple(name + "-" + version for name, version in sorted(packages.items()))


def retained_packages(plan):
    """All host/NC/OO locked closures, deduplicated by exact retained identity."""
    try:
        resolution._plan_inventory(plan)
        merged = {}
        for group in versions.GROUPS:
            for name, item in plan["packages"][group].items():
                if name in merged and merged[name] != item:
                    raise ValueError
                merged[name] = item
        packages = {name: merged[name]["version"] for name in sorted(merged)}
        _packages(packages)
        return packages
    except (ValueError, TypeError, KeyError):
        raise PackageSecurityError("Invalid or unsupported retained package closure") from None


def _text(value, limit):
    if (not isinstance(value, str) or not value or len(value) > limit
            or any((ord(char) < 32 and char not in "\t\r\n") or ord(char) == 127
                   or 0xd800 <= ord(char) <= 0xdfff for char in value)):
        raise PackageSecurityError("Invalid audit text")


def parse_audit(output, returncode, packages):
    """Validate the entire reviewed JSON/exit contract against exact arguments.

    Descriptions/range strings are validated but never returned. A zero result
    is meaningful only with nonempty validated explicit arguments and exit 0.
    """
    _arguments(packages)
    if (not isinstance(output, str) or len(output) > MAX_OUTPUT
            or type(returncode) is not int or returncode not in (0, 1)):
        raise PackageSecurityError("Invalid package audit output or exit status")
    try:
        data = output.encode("utf-8")
        if not data or len(data) > MAX_OUTPUT:
            raise ValueError
        # Reuse the bounded duplicate-key/constant/depth/node JSON parser. The
        # wrapper preserves a strict single object and rejects trailing output.
        parsed = core._json(b"[" + data + b"]")
        if len(parsed) != 1 or not isinstance(parsed[0], dict):
            raise ValueError
        value = parsed[0]
    except (ValueError, UnicodeError):
        raise PackageSecurityError("Malformed package audit JSON") from None
    count = value.get("pkg_count")
    if type(count) is not int or not 0 <= count <= len(packages):
        raise PackageSecurityError("Invalid affected-package count")
    if count == 0:
        if value != {"pkg_count": 0} or returncode != 0:
            raise PackageSecurityError("Unsupported empty audit result")
        return []
    if (set(value) != {"pkg_count", "packages"} or returncode != 1
            or not isinstance(value["packages"], dict) or len(value["packages"]) != count):
        raise PackageSecurityError("Incomplete affected-package result")
    findings, total = [], 0
    for name, package in sorted(value["packages"].items()):
        if (name not in packages or not isinstance(package, dict)
                or set(package) != {"version", "issue_count", "issues", "reverse dependencies"}
                or package["version"] != packages[name] or package["reverse dependencies"] != []):
            raise PackageSecurityError("Audit result does not match explicit package arguments")
        count, issues = package["issue_count"], package["issues"]
        if type(count) is not int or not isinstance(issues, list) or not 1 <= count == len(issues) <= MAX_ISSUES:
            raise PackageSecurityError("Invalid audit issue count")
        total += count
        if total > MAX_ISSUES:
            raise PackageSecurityError("Excessive audit issues")
        advisories = []
        for issue in issues:
            if (not isinstance(issue, dict) or not {"Affected versions", "description"} <= set(issue)
                    or set(issue) - {"Affected versions", "description", "cve", "url"}):
                raise PackageSecurityError("Unsupported audit issue schema")
            _text(issue["description"], 16384)
            ranges = issue["Affected versions"]
            if not isinstance(ranges, list) or not 1 <= len(ranges) <= 128:
                raise PackageSecurityError("Invalid audit affected ranges")
            for interval in ranges:
                _text(interval, 2048)
                if not re.fullmatch(r"(?:<=|>=|<|>|=) " + compatibility.VERSION
                                    + r"(?: : (?:<=|>=|<|>|=) " + compatibility.VERSION + r")?", interval):
                    raise PackageSecurityError("Unsupported native affected range")
            cves = issue.get("cve", [])
            if (not isinstance(cves, list) or len(cves) > 128 or ("cve" in issue and not cves)
                    or any(not isinstance(cve, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,12}", cve) for cve in cves)
                    or len(cves) != len(set(cves))):
                raise PackageSecurityError("Invalid native advisory identifiers")
            url = issue.get("url")
            if "url" in issue:
                if (not isinstance(url, str) or not re.fullmatch(
                        r"https://vuxml\.(?:FreeBSD|freebsd)\.org/freebsd/" + UUID + r"\.html", url)):
                    raise PackageSecurityError("Unsupported native advisory URL")
                url = url.replace("vuxml.FreeBSD.org", "vuxml.freebsd.org")
            advisories.append({"cve": sorted(cves), "url": url})
        findings.append({"package": name, "version": packages[name], "issue_count": count,
                         "advisories": sorted(advisories, key=lambda item: (item["url"] or "", item["cve"]))})
    return findings


def _validate_xml(data):
    """Reject non-VuXML/empty feeds and entities before accepting native output.

    Expat does no network access. External DTD declarations in official VuXML
    are allowed without loading them; internal subsets/entities are refused.
    Native pkg remains the only package-range matcher.
    """
    if not data or len(data) > MAX_VUXML:
        raise PackageSecurityError("Missing or oversized VuXML evidence")
    parser = expat.ParserCreate(namespace_separator="}")
    parser.namespace_prefixes = True
    depth, nodes, vulnerabilities = 0, 0, 0
    stack, current, package, interval = [], {}, {}, {}
    def tag(name):
        return NAMESPACE + "}" + name
    def start(name, attributes):
        nonlocal depth, nodes, vulnerabilities
        depth += 1
        nodes += 1
        stack.append(name)
        if depth > 32 or nodes > 2000000:
            raise PackageSecurityError("VuXML complexity limit exceeded")
        if depth == 1 and name != tag("vuxml"):
            raise PackageSecurityError("Unexpected VuXML root")
        if depth == 2:
            if name != tag("vuln") or not re.fullmatch(UUID, attributes.get("vid", "")):
                raise PackageSecurityError("Invalid VuXML advisory identity")
            vulnerabilities += 1
            current.clear()
            current.update(packages=0, topic="")
        if stack[2:] == [tag("affects"), tag("package")]:
            package.clear()
            package.update(names=0, ranges=0, text="")
        if stack[2:] == [tag("affects"), tag("package"), tag("name")]:
            package["text"] = ""
        if stack[2:] == [tag("affects"), tag("package"), tag("range")]:
            interval.clear()
            interval.update(bounds=0, text="")
        if stack[2:5] == [tag("affects"), tag("package"), tag("range")] and depth == 6:
            if name not in {tag(op) for op in ("lt", "le", "eq", "gt", "ge")}:
                raise PackageSecurityError("Unsupported VuXML range operator")
            interval["text"] = ""
    def text(data):
        if stack[2:] == [tag("topic")]:
            current["topic"] += data
            if len(current["topic"]) > 16384:
                raise PackageSecurityError("Excessive VuXML topic")
        elif stack[2:] == [tag("affects"), tag("package"), tag("name")]:
            package["text"] += data
            if len(package["text"]) > 512:
                raise PackageSecurityError("Excessive VuXML package name")
        elif stack[2:5] == [tag("affects"), tag("package"), tag("range")] and depth == 6:
            interval["text"] += data
            if len(interval["text"]) > 512:
                raise PackageSecurityError("Excessive VuXML version bound")
    def end(name):
        nonlocal depth
        if stack[2:] == [tag("affects"), tag("package"), tag("name")]:
            if not package["text"].strip():
                raise PackageSecurityError("Empty VuXML package name")
            package["names"] += 1
        if stack[2:5] == [tag("affects"), tag("package"), tag("range")] and depth == 6:
            if not interval["text"].strip():
                raise PackageSecurityError("Empty VuXML range bound")
            interval["bounds"] += 1
        if stack[2:] == [tag("affects"), tag("package"), tag("range")]:
            if not 1 <= interval["bounds"] <= 2:
                raise PackageSecurityError("Invalid VuXML range bounds")
            package["ranges"] += 1
        if stack[2:] == [tag("affects"), tag("package")]:
            if not 1 <= package["names"] <= 128 or not 1 <= package["ranges"] <= 128:
                raise PackageSecurityError("Incomplete VuXML package range")
            current["packages"] += 1
        if depth == 2 and (not current["packages"] or not current["topic"].strip()):
            raise PackageSecurityError("Incomplete VuXML advisory")
        stack.pop()
        depth -= 1
    def doctype(name, system, public, internal):
        if name != "vuxml" or internal:
            raise PackageSecurityError("Unsupported VuXML document type")
    def entity(*args):
        raise PackageSecurityError("VuXML entity declarations are unsupported")
    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = entity
    parser.ExternalEntityRefHandler = entity
    try:
        parser.Parse(data, True)
    except expat.ExpatError:
        raise PackageSecurityError("Malformed VuXML evidence") from None
    if depth != 0 or vulnerabilities == 0:
        raise PackageSecurityError("Empty VuXML advisory collection")


def _read(path, limit, *, xml=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        # pkg writes VuXML 0444 inside our private directory. Protect that file
        # via the already checked descriptor before any evidence is retained.
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_size > limit or info.st_mode & (0o022 if xml else 0o077)):
            raise PackageSecurityError("Unsafe native audit evidence file")
        if xml:
            os.fchmod(stream.fileno(), 0o600)
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise PackageSecurityError("Oversized native audit evidence")
        return data


def _run_file(runner, environment, command, output, limit, timeout):
    # POSIX sh ulimit -f uses 512-byte blocks. Bound output during execution,
    # not just after Runner has captured an arbitrarily large native JSON blob.
    script = 'umask 077; ulimit -f "$1" || exit 70; shift; out=$1; shift; exec "$@" >"$out" 2>/dev/null'
    result = runner.run(*environment, "/bin/sh", "-c", script, "pkg-security", str(limit // 512),
                        str(output), *command, input="", hide_output=True, check=False, timeout=timeout)
    if type(result.returncode) is not int or result.returncode not in (0, 1):
        raise PackageSecurityError("Native package audit command failed")
    return result.returncode


def refresh(packages, *, runner=None, directory=None):
    """Explicit native refresh; return evidence or a fixed PackageSecurityError.

    Injected runners permit offline tests; otherwise require FreeBSD root and
    an existing /usr/local/sbin/pkg. No shim, bootstrap, package install, host
    catalog update or installed-DB lookup is performed. directory is only a
    parent for a NEW private TemporaryDirectory (never an existing audit DB).
    """
    arguments = _arguments(packages)
    if runner is None:
        if not sys.platform.startswith("freebsd"):
            raise NativeAuditUnavailable("Native package audit unavailable")
        if os.geteuid() != 0 or not Path(PKG).is_file():
            raise NativeAuditUnavailable("Native package audit unavailable")
        from .host import Runner
        runner = Runner()
    try:
        with tempfile.TemporaryDirectory(prefix="security-pkg-", dir=directory or "/var/tmp") as temporary:
            root = Path(temporary)
            for name in ("repos", "db", "cache", "tmp", "home"):
                (root / name).mkdir(mode=0o700)
            environment = ("/usr/bin/env", "-i", PATH, "LC_ALL=C", "HOME=" + str(root / "home"),
                           "NETRC=/dev/null", "TMPDIR=" + str(root / "tmp"))
            command = (PKG, "-C", "/dev/null", "-o", "REPOS_DIR=" + str(root / "repos"),
                       "-o", "PKG_DBDIR=" + str(root / "db"), "-o", "PKG_CACHEDIR=" + str(root / "cache"),
                       "-o", "VULNXML_SITE=" + SOURCE_URL, "-o", "PKG_ENABLE_PLUGINS=false",
                       "-o", "FETCH_RETRY=1", "-o", "FETCH_TIMEOUT=30")
            version_file = root / "pkg-version"
            code = _run_file(runner, environment, (*command, "-v"), version_file, 4096, 10)
            if code != 0 or _read(version_file, 4096) not in (PKG_VERSION.encode(), (PKG_VERSION + "\n").encode()):
                raise PackageSecurityError("Native pkg version is not reviewed")
            database = root / "vuln.xml"
            if database.exists() or database.is_symlink():
                raise PackageSecurityError("Native refresh requires a new audit database")
            _run_file(runner, environment, (*command, "audit", "-F", "-f", str(database), "--", *arguments),
                      "/dev/null", MAX_VUXML, 90)
            xml = _read(database, MAX_VUXML, xml=True)
            _validate_xml(xml)
            xml_hash = _hash(xml)
            fetched = timestamp()
            output_file = root / "audit.json"
            code = _run_file(runner, environment,
                             (*command, "audit", "--raw=json", "-f", str(database), "--", *arguments),
                             output_file, MAX_OUTPUT, 60)
            output = _read(output_file, MAX_OUTPUT).decode("utf-8")
            parse_audit(output, code, packages)
            if _hash(_read(database, MAX_VUXML)) != xml_hash:
                raise PackageSecurityError("VuXML evidence changed during audit")
            return {"schema_version": SCHEMA_VERSION, "provider": core.PKG_PROVIDER,
                    "pkg_version": PKG_VERSION, "source_url": SOURCE_URL, "fetched_at": fetched,
                    "packages": dict(packages), "packages_sha256": packages_hash(packages),
                    "vuxml_sha256": xml_hash, "vuxml_bytes": len(xml),
                    "audit_output": output, "audit_sha256": _hash(output.encode()), "exit_status": code}
    except PackageSecurityError:
        raise
    except Exception:
        raise PackageSecurityError("Native package advisory refresh failed") from None


def validate_evidence(evidence, packages):
    core._fields(evidence, ("schema_version", "provider", "pkg_version", "source_url", "fetched_at",
                            "packages", "packages_sha256", "vuxml_sha256", "vuxml_bytes",
                            "audit_output", "audit_sha256", "exit_status"))
    if (type(evidence["schema_version"]) is not int or evidence["schema_version"] != SCHEMA_VERSION
            or evidence["provider"] != core.PKG_PROVIDER or evidence["pkg_version"] != PKG_VERSION
            or evidence["source_url"] != SOURCE_URL or evidence["packages"] != packages
            or evidence["packages_sha256"] != packages_hash(packages)
            or type(evidence["vuxml_bytes"]) is not int or not 0 < evidence["vuxml_bytes"] <= MAX_VUXML):
        raise PackageSecurityError("Invalid native advisory evidence binding")
    for key in ("vuxml_sha256", "audit_sha256"):
        if not isinstance(evidence[key], str) or not re.fullmatch(r"[a-f0-9]{64}", evidence[key]):
            raise PackageSecurityError("Invalid native advisory evidence digest")
    core._date(evidence["fetched_at"])
    findings = parse_audit(evidence["audit_output"], evidence["exit_status"], packages)
    if _hash(evidence["audit_output"].encode()) != evidence["audit_sha256"]:
        raise PackageSecurityError("Native audit output digest mismatch")
    return findings


def assess(packages, evidence=None, *, now=None):
    """Pure assessment; only fresh exact native evidence can report no known hits."""
    report = core._empty(core.PKG_PROVIDER)
    report.update(source=SOURCE, package_count=0, packages_sha256=None)
    try:
        report.update(package_count=len(packages), packages_sha256=packages_hash(packages))
    except (ValueError, TypeError):
        report["reasons"] = ["invalid-retained-package-arguments"]
        return report
    if evidence is None:
        report["reasons"] = ["missing-package-audit"]
        return report
    try:
        findings = validate_evidence(evidence, packages)
        checked = datetime.now(timezone.utc) if now is None else core._date(now)
        age = (checked - core._date(evidence["fetched_at"])).total_seconds()
        if age < 0:
            raise ValueError
    except (ValueError, TypeError, KeyError, UnicodeError):
        report.update(freshness="unknown", reasons=["invalid-package-audit"])
        return report
    report["findings"] = findings
    report["provenance"] = {key: evidence[key] for key in ("source_url", "fetched_at", "pkg_version",
                              "packages_sha256", "vuxml_sha256", "vuxml_bytes", "audit_sha256")}
    report["provenance"]["authentication"] = "native-pkg-https-source-not-signed-feed"
    report["freshness"] = "fresh" if age <= core.MAX_AGE_SECONDS else "stale"
    if report["freshness"] == "fresh":
        report.update(status="affected" if findings else "no-known-advisories", coverage="complete")
    else:
        report["reasons"] = ["stale-package-audit"]
    return report
