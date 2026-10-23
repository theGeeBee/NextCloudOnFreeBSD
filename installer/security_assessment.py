"""Read-only advisory evidence, independent of release/compatibility policy.

Source reviewed 2026-10-15:
https://docs.github.com/en/rest/security-advisories/repository-advisories
https://api.github.com/repos/nextcloud/security-advisories/security-advisories
The nextcloud/server endpoint returned []; the separate upstream advisory
repository publishes package.ecosystem="nextcloud", package.name="Server".
This covers that package identity only, not third-party apps or Enterprise.

GitHub's live multi-branch strings (e.g. ">= 32.0.0, >= 33.0.0") do not
document unambiguous interval semantics. These remain unsupported, never clean.
Only numeric final versions and explicit single intervals are understood.
HTTPS provenance is not a signed-feed or exhaustive-disclosure guarantee.

All filesystem/cache, installed-identity binding and native execution belong to
the caller. refresh_nextcloud requires an injected bounded HTTPS transport;
there is no default transport, subprocess, remediation or import-time I/O.
"""

from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit

from . import versions


SCHEMA_VERSION = 1
UPSTREAM_PROVIDER = "nextcloud-upstream"
PKG_PROVIDER = "freebsd-pkg"
SOURCE_URL = "https://api.github.com/repos/nextcloud/security-advisories/security-advisories"
ADVISORY_URL = "https://github.com/nextcloud/security-advisories/security/advisories/"
REFRESH_URL = SOURCE_URL + "?per_page=100&state=published"
MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 5000
MAX_PAGES = 32
MAX_DEPTH = 20
MAX_NODES = 250000
MAX_AGE_SECONDS = 24 * 60 * 60
GHSA = r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
VERSION = versions.NUMBER + r"(?:\." + versions.NUMBER + r"){2,3}"


class AssessmentError(ValueError):
    """Fixed diagnostics only; never include untrusted feed/transport text."""


def _version(value):
    if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(VERSION, value):
        raise AssessmentError("Unsupported final application version")
    return versions.stable_version(value)


def _date(value):
    if (not isinstance(value, str) or len(value) > 40
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                                r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value)):
        raise AssessmentError("Invalid advisory timestamp")
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise AssessmentError("Invalid advisory timestamp") from None


def _fields(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise AssessmentError("Invalid normalized advisory schema")


def _id(value):
    if not isinstance(value, str) or not re.fullmatch(GHSA, value):
        raise AssessmentError("Invalid advisory identifier")
    return value


def _json(data):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise AssessmentError("Invalid or oversized advisory payload")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AssessmentError("Duplicate advisory JSON field")
            result[key] = value
        return result
    def invalid(value):
        raise AssessmentError("Non-JSON advisory numeric constant")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise AssessmentError("Malformed advisory JSON") from None
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise AssessmentError("Advisory JSON complexity limit exceeded")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    if not isinstance(value, list) or len(value) > MAX_RECORDS:
        raise AssessmentError("Invalid advisory record collection")
    return value


def _interval(value, patched):
    """Normalize >= introduced, < fixed, <= last_affected, or exact versions.

    A single patched version may close a lower-only interval on the same major
    branch. Multiple lower bounds/fixes, wildcards, prereleases, disjunctions,
    missing ranges and contradictory boundaries fail closed as unsupported.
    """
    if not isinstance(value, str) or not value or len(value) > 256:
        raise AssessmentError("Unsupported advisory range")
    result = {"introduced": None, "fixed": None, "last_affected": None}
    for clause in value.split(","):
        match = re.fullmatch(r"\s*(>=|<=|<|=)?\s*(" + VERSION + r")\s*", clause)
        if not match:
            raise AssessmentError("Unsupported advisory range")
        operator, number = match.groups()
        _version(number)
        if operator in (None, "="):
            if any(result.values()) or len(value.split(",")) != 1:
                raise AssessmentError("Unsupported advisory range")
            result.update(introduced=number, last_affected=number)
        else:
            key = {">=": "introduced", "<": "fixed", "<=": "last_affected"}[operator]
            if result[key] is not None:
                raise AssessmentError("Ambiguous advisory range")
            result[key] = number
    if patched is not None:
        if not isinstance(patched, str):
            raise AssessmentError("Unsupported patched version")
        patched = patched.strip()
        _version(patched)
        if result["fixed"] is not None:
            if _version(result["fixed"]) != _version(patched):
                raise AssessmentError("Conflicting patched version")
        elif result["last_affected"] is not None:
            if _version(patched) <= _version(result["last_affected"]):
                raise AssessmentError("Conflicting patched version")
        else:
            lower = result["introduced"]
            if lower is None or _version(lower)[0] != _version(patched)[0]:
                raise AssessmentError("Ambiguous patched version branch")
            result["fixed"] = patched
    _validate_interval(result)
    return result


def _validate_interval(value):
    _fields(value, ("introduced", "fixed", "last_affected"))
    for number in value.values():
        if number is not None:
            _version(number)
    lower, fixed, last = (value[key] for key in ("introduced", "fixed", "last_affected"))
    if (not any(value.values()) or (fixed is not None and last is not None)
            or (lower is not None and fixed is not None and _version(lower) >= _version(fixed))
            or (lower is not None and last is not None and _version(lower) > _version(last))):
        raise AssessmentError("Invalid advisory interval")


def matches(version, interval):
    """Pure numeric introduced-inclusive/fixed-exclusive interval matcher."""
    key = _version(version)
    _validate_interval(interval)
    return ((interval["introduced"] is None or key >= _version(interval["introduced"]))
            and (interval["fixed"] is None or key < _version(interval["fixed"]))
            and (interval["last_affected"] is None or key <= _version(interval["last_affected"])))


def normalize_nextcloud(pages, *, fetched_at, complete=False):
    """Adapt bounded raw GitHub repository-advisory pages into schema 1.

    complete=True means the caller observed the end of API pagination, not that
    upstream disclosed every vulnerability. Partial evidence can report hits.
    A truncated/malformed page invalidates the feed; unsupported relevant ranges
    retain explicit unknown coverage alongside any understood intervals.
    """
    fetched_at = _date(fetched_at).isoformat()
    if not isinstance(pages, list) or not 1 <= len(pages) <= MAX_PAGES or type(complete) is not bool:
        raise AssessmentError("Invalid advisory pages")
    records, unsupported, seen = [], set(), set()
    total, digest = 0, hashlib.sha256()
    for page in pages:
        if not isinstance(page, bytes):
            raise AssessmentError("Invalid advisory page")
        total += len(page)
        if total > MAX_BYTES:
            raise AssessmentError("Advisory payload limit exceeded")
        digest.update(len(page).to_bytes(8, "big"))
        digest.update(page)
        for item in _json(page):
            if not isinstance(item, dict):
                raise AssessmentError("Invalid advisory record")
            identity = _id(item.get("ghsa_id"))
            if identity in seen or len(seen) >= MAX_RECORDS:
                raise AssessmentError("Duplicate or excessive advisory records")
            seen.add(identity)
            if item.get("html_url") != ADVISORY_URL + identity:
                raise AssessmentError("Unexpected advisory provenance")
            if "withdrawn_at" not in item:
                raise AssessmentError("Missing advisory withdrawal state")
            if item["withdrawn_at"] is not None:
                _date(item["withdrawn_at"])
                continue
            if item.get("state") == "withdrawn":
                continue
            if item.get("state") != "published":
                raise AssessmentError("Unpublished advisory in public feed")
            vulnerabilities = item.get("vulnerabilities")
            if not isinstance(vulnerabilities, list) or not 1 <= len(vulnerabilities) <= 100:
                raise AssessmentError("Missing or excessive advisory vulnerabilities")
            ranges = []
            for entry in vulnerabilities:
                if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
                    raise AssessmentError("Invalid advisory package")
                package = entry["package"]
                if any(not isinstance(package.get(key), str) or not package[key]
                       or len(package[key]) > 128 for key in ("ecosystem", "name")):
                    raise AssessmentError("Missing advisory package identity")
                if package != {"ecosystem": "nextcloud", "name": "Server"}:
                    # Unknown fields on an otherwise relevant identity cannot
                    # silently turn into a skipped package.
                    if package.get("ecosystem") == "nextcloud" and package.get("name") == "Server":
                        unsupported.add(identity)
                    continue
                try:
                    if "patched_versions" not in entry:
                        raise AssessmentError("Missing patched version field")
                    ranges.append(_interval(entry.get("vulnerable_version_range"), entry["patched_versions"]))
                except AssessmentError:
                    unsupported.add(identity)
            if ranges:
                records.append({"id": identity, "url": ADVISORY_URL + identity, "ranges": ranges})
    return {"schema_version": SCHEMA_VERSION, "provider": UPSTREAM_PROVIDER,
            "source_url": SOURCE_URL, "fetched_at": fetched_at,
            "content_sha256": digest.hexdigest(), "complete": complete,
            "records": sorted(records, key=lambda item: item["id"]),
            "unsupported_ids": sorted(unsupported)}


def _validate_feed(feed):
    _fields(feed, ("schema_version", "provider", "source_url", "fetched_at", "content_sha256",
                   "complete", "records", "unsupported_ids"))
    if (type(feed["schema_version"]) is not int or feed["schema_version"] != SCHEMA_VERSION
            or feed["provider"] != UPSTREAM_PROVIDER or feed["source_url"] != SOURCE_URL
            or type(feed["complete"]) is not bool
            or not isinstance(feed["content_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", feed["content_sha256"])):
        raise AssessmentError("Invalid advisory feed provenance")
    _date(feed["fetched_at"])
    for field in ("records", "unsupported_ids"):
        if not isinstance(feed[field], list) or len(feed[field]) > MAX_RECORDS:
            raise AssessmentError("Invalid normalized advisory collection")
    seen = set()
    for item in feed["records"]:
        _fields(item, ("id", "url", "ranges"))
        identity = _id(item["id"])
        if identity in seen or item["url"] != ADVISORY_URL + identity:
            raise AssessmentError("Invalid normalized advisory identity")
        seen.add(identity)
        if not isinstance(item["ranges"], list) or not 1 <= len(item["ranges"]) <= 100:
            raise AssessmentError("Invalid normalized advisory ranges")
        for interval in item["ranges"]:
            _validate_interval(interval)
    unknown = [_id(value) for value in feed["unsupported_ids"]]
    if len(set(unknown)) != len(unknown):
        raise AssessmentError("Duplicate unsupported advisory identity")


def _empty(provider):
    return {"provider": provider, "status": "unknown", "coverage": "unknown",
            "freshness": "missing", "installed_version": None, "findings": [],
            "unsupported_ids": [], "provenance": None, "reasons": [],
            "eol": {"status": "unknown", "reason": "no-reviewed-authoritative-eol-policy"},
            "execution_authorized": False}


def assess_nextcloud(installed_version, feed=None, *, now=None):
    """Assess upstreamarchive Server only; invalid evidence never means clean.

    A stale/partial feed may retain known affected findings, but its coverage is
    unknown. no-known-advisories requires fresh, complete, understood evidence.
    EOL is deliberately independent of compatibility/minimum-version policy.
    """
    report = _empty(UPSTREAM_PROVIDER)
    try:
        _version(installed_version)
    except AssessmentError:
        report["reasons"] = ["invalid-installed-version"]
        return report
    report["installed_version"] = installed_version
    if feed is None:
        report["reasons"] = ["missing-feed"]
        return report
    try:
        _validate_feed(feed)
        checked = datetime.now(timezone.utc) if now is None else _date(now)
        age = (checked - _date(feed["fetched_at"])).total_seconds()
        if age < 0:
            raise AssessmentError("Future advisory timestamp")
    except (AssessmentError, TypeError, OverflowError):
        report.update(freshness="unknown", reasons=["invalid-feed"])
        return report
    report["freshness"] = "fresh" if age <= MAX_AGE_SECONDS else "stale"
    report["provenance"] = {key: feed[key] for key in ("source_url", "fetched_at", "content_sha256")}
    report["provenance"]["authentication"] = "https-source-not-signed-feed"
    report["unsupported_ids"] = sorted(feed["unsupported_ids"])
    if report["freshness"] == "stale":
        report["reasons"].append("stale-feed")
    if not feed["complete"]:
        report["reasons"].append("incomplete-feed")
    if feed["unsupported_ids"]:
        report["reasons"].append("unsupported-ranges")
    for item in sorted(feed["records"], key=lambda item: item["id"]):
        if any(matches(installed_version, interval) for interval in item["ranges"]):
            report["findings"].append({"id": item["id"], "url": item["url"],
                                       "affected_version": installed_version})
    if not report["reasons"]:
        report["coverage"] = "complete"
        report["status"] = "no-known-advisories"
    if report["findings"]:
        report["status"] = "affected"
    return report


def assess_freebsd_packages():
    """Separate provider placeholder: no native audit format/backend is approved.

    pkg audit cannot cover an upstreamarchive Nextcloud installation. Neither
    a blank stdout nor a fabricated JSON interpretation is accepted as evidence.
    """
    report = _empty(PKG_PROVIDER)
    report["reasons"] = ["native-audit-not-implemented"]
    return report


def _allowed_url(url):
    if not isinstance(url, str) or len(url) > 1024 or not re.fullmatch(r"[\x21-\x7e]+", url):
        raise AssessmentError("Invalid advisory transport URL")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "api.github.com" or parsed.fragment
            or parsed.path not in ("/repos/nextcloud/security-advisories/security-advisories",
                                   "/repositories/63675426/security-advisories")):
        raise AssessmentError("Unapproved advisory transport URL")
    query = parse_qsl(parsed.query, keep_blank_values=True)
    fields = dict(query)
    if (len(fields) != len(query) or set(fields) - {"per_page", "state", "after", "before"}
            or fields.get("per_page") != "100" or fields.get("state") != "published"
            or ("before" in fields and "after" in fields)):
        raise AssessmentError("Unapproved advisory transport query")
    for key in ("after", "before"):
        if key in fields and not re.fullmatch(r"[A-Za-z0-9+/=_-]{1,512}", fields[key]):
            raise AssessmentError("Invalid advisory pagination cursor")


def _next_url(link):
    if link is None or link == "":
        return None
    if not isinstance(link, str) or len(link) > 4096:
        raise AssessmentError("Invalid advisory pagination")
    links = {}
    for part in link.split(","):
        match = re.fullmatch(r'\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*', part)
        if not match or match[2] in links:
            raise AssessmentError("Invalid advisory pagination")
        _allowed_url(match[1])
        links[match[2]] = match[1]
    return links.get("next")


def refresh_nextcloud(fetcher, *, fetched_at):
    """Explicit refresh through fetcher(url, max_bytes=..., headers=...).

    The transport MUST bound reads/timeouts, verify TLS and refuse redirects;
    return {status: int, url: requested URL, body: bytes, link: str|None}.
    Link must be the complete HTTP Link header, not a guessed completion bit.
    Only the reviewed repository API/name and its observed numeric ID are
    allowlisted. The supplied completion timestamp is checked by assessment.
    Failures raise fixed AssessmentError diagnostics; no stale fallback/write.
    """
    _date(fetched_at)
    pages, seen, total, url = [], set(), 0, REFRESH_URL
    try:
        while url is not None:
            _allowed_url(url)
            if url in seen or len(pages) >= MAX_PAGES:
                raise AssessmentError("Advisory pagination limit exceeded")
            seen.add(url)
            response = fetcher(url, max_bytes=MAX_BYTES - total,
                               headers={"Accept": "application/vnd.github+json",
                                        "X-GitHub-Api-Version": "2026-03-10"})
            _fields(response, ("status", "url", "body", "link"))
            if type(response["status"]) is not int or response["status"] != 200 or response["url"] != url:
                raise AssessmentError("Advisory HTTP request failed or redirected")
            body = response["body"]
            if not isinstance(body, bytes) or len(body) > MAX_BYTES - total:
                raise AssessmentError("Advisory payload limit exceeded")
            total += len(body)
            pages.append(body)
            url = _next_url(response["link"])
        return normalize_nextcloud(pages, fetched_at=fetched_at, complete=True)
    except AssessmentError:
        raise
    except Exception:
        # Transport exceptions may contain tokens, response bodies or URL data.
        raise AssessmentError("Advisory refresh failed") from None
