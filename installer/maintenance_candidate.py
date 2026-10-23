"""Pre-intent destination capture for the trusted, internal acceptance harness.

The caller holds both operation locks and supplies SourceAdmission, never JSON
eligibility. Only private evidence, isolated catalogs and public artifact staging
are written. No NativeState.begin, boot fence, service/config change, package
transaction, or downloaded script execution belongs here. Native acceptance is
NOT RUN and the production entrypoint remains disabled.

An optional local connector archive is authenticated against the original signed
record and the first-readiness-bound installed tree. Missing archive bytes remain
an explicit blocker; tree/metadata digests never stand in for archive SHA256.
"""

from dataclasses import asdict, dataclass
from copy import deepcopy
import base64
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET
import zipfile

from . import bounded_process, compatibility, discovery, maintenance_preflight as preflight
from . import maintenance_admission as admission, maintenance_operations as operations
from . import maintenance_staging as staging, nextcloud_update as update
from .generations import MAX_FILE_BYTES, _encode, _json, _fields, _reference
from .versions import GROUPS
from .runtime_inventory import collect_php
from .version_runtime import connector_text


DENIED = "Pre-intent maintenance candidate capture refused"
CONNECTOR_BLOCKER = "authenticated-retained-connector-archive-unavailable"
MAX_XML = 128 * 1024
MAX_CONNECTOR = 256 * 1024 * 1024
CONNECTOR_FILES = 20000
SQL = ("SELECT VERSION(), @@transaction_isolation; "
       "SELECT DISTINCT ENGINE FROM information_schema.TABLES "
       "WHERE TABLE_SCHEMA = 'nextcloud' AND TABLE_TYPE = 'BASE TABLE' ORDER BY ENGINE")
DB = ("/usr/local/bin/mariadb", "--no-defaults", "--protocol=socket",
      "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch",
      "--skip-column-names", "--execute", SQL)
OCC = ("/usr/bin/mdo", "-u", "www", "/usr/local/bin/php", "-d", "display_errors=0",
       "-d", "log_errors=0", "-d", "zend.exception_ignore_args=1", update.APP + "/occ")

# Reviewed 2026-10-15: nextcloud/server v35.0.1
# core/Command/Integrity/{CheckApp.php,../Base.php}, lib/private/IntegrityCheck/Checker.php,
# lib/private/Memcache/{Factory,NullCache}.php and lib/public/ICacheFactory.php.
# CheckApp's exact positive output is "No errors found\n"; skipped signatures
# emit an additional warning. Its Checker also ALWAYS calls storeResults, which
# writes app-config/cache. Use that same public checker with nullable config /
# appConfig and a native NullCache instead. No container replacement/reflection,
# custom CA engine, installed helper rewrite, or persistent result writes.
# The native checker validates CA/CN and signed files; initial installer receipt
# supplies the original app-store (including its CRL) provenance. This does NOT
# claim that Checker independently refreshes CRL evidence.
# App-store 35.0.1 metadata inspected 2026-10-15 advertises 10.2.1 as
# https://github.com/ONLYOFFICE/onlyoffice-nextcloud/releases/download/v10.2.1/onlyoffice.tar.gz
# Runtime trust still comes exclusively from the retained record, never this URL.
_CONNECTOR_INTEGRITY = r'''
define('OC_CONSOLE', 1);
require '/usr/local/www/nextcloud/lib/base.php';
$path = '/usr/local/www/nextcloud/custom_apps/onlyoffice';
if (!is_file($path . '/appinfo/signature.json')) { exit(1); }
$factory = new class extends \OC\Memcache\Factory {
    public function __construct() {}
    public function createDistributed(string $prefix = ''): \OCP\ICache {
        return new \OC\Memcache\NullCache();
    }
};
$checker = new \OC\IntegrityCheck\Checker(
    \OCP\Server::get(\OCP\ServerVersion::class),
    new \OC\IntegrityCheck\Helpers\EnvironmentHelper(),
    new \OC\IntegrityCheck\Helpers\FileAccessHelper(), null, null, $factory,
    \OCP\Server::get(\OCP\App\IAppManager::class),
    \OCP\Server::get(\OCP\Files\IMimeTypeDetector::class));
if ($checker->verifyAppSignature('onlyoffice', $path, true) !== []) { exit(1); }
echo "No errors found\n";
'''
_CONNECTOR_SIGNATURE = r'''
$archive = file_get_contents($argv[1]);
$record = json_decode(file_get_contents($argv[2]), true, 32, JSON_THROW_ON_ERROR);
$signature = base64_decode(str_replace(["\r", "\n"], '', $record['signature']), true);
if (!is_string($archive) || !is_string($signature) ||
    openssl_verify($archive, $signature, $record['certificate'], OPENSSL_ALGO_SHA512) !== 1) { exit(1); }
echo "Connector archive verified\n";
'''


def _connector_commands(context):
    return (OCC[:-1] + ("-r", _CONNECTOR_INTEGRITY),
            ("/usr/local/bin/php", "-d", f"memory_limit={context.memory_mib}M", "-d", "display_errors=0",
             "-d", "log_errors=0", "-d", "zend.exception_ignore_args=1", "-r", _CONNECTOR_SIGNATURE,
             "--", context.stage + "/onlyoffice-10.2.1.tar.gz", context.stage + "/connector-record.json"))


class CandidateError(ValueError):
    def __init__(self, blocker):
        self.blocker = blocker
        super().__init__(DENIED + ": " + blocker)


def _require(value, blocker="source-or-preparation-drift"):
    if not value:
        raise CandidateError(blocker)


@dataclass(frozen=True)
class CapturedCandidate:
    """Private receipt reference, not a deserializable execution permission."""

    operation: str
    reference: dict
    bundle: update.StagedUpdate


@dataclass(frozen=True)
class RevalidatedCandidate:
    """Same-call result of trusted revalidation, not an input permission object.

    The native caller invokes revalidation itself under both live locks and
    consumes its freshly generated admission immediately; no JSON proof is read.
    """
    reference: dict
    admission: dict


def _bindings(deployment, retained, store):
    return dict(config_sha256=preflight.digest(json.loads(deployment.config.to_json())),
                 versions_sha256=preflight.digest(deployment.versions),
                 graph_sha256=preflight.digest(_json(store._bound(retained["graph"]))),
                 generation_sha256=preflight.digest(_json(store._bound(retained["generation"]))),
                network_sha256=preflight.digest(retained["network"]),
                executor_sha256=retained["executor"]["executor_sha256"])


class ArtifactsOnlyAuthority(update.Authority):
    """Exact ready/enrolled source and preparation owner, before native intent.

    Construction invokes the trusted admission adapter itself. No supplied proof
    dictionary/boolean, native view, arbitrary runner, or execution phase can be
    used to broaden this authority. Tests replace the bounded transport only.
    """

    def __init__(self, deployment, operation, source_admission):
        _require(type(source_admission) is admission.SourceAdmission,
                 "trusted-source-admission-required")
        _require(type(operation) is str and re.fullmatch(r"maint-[a-f0-9]{32}", operation),
                 "preparation-owner-required")
        self.d, self.c, self.operation = deployment, deployment.config, operation
        self.admission = source_admission
        self.store = source_admission.native.store
        self.context, self.bundle, self.connector = None, None, None
        self.directory = "maintenance/operations/" + operation
        self._locks()
        # Authenticate original executable/config trees before ANY installed PHP.
        self.admitted = source_admission.admit_source(deployment)
        self.original = source_admission._original(deployment)
        self.expected = self.original[4]
        self.parent, self.plan, journal = operations.load_operation(deployment.registry, operation)
        _require(self.parent["instance"] == self.c.instance and journal.read()["phase"] == "staged")
        retained, config, versions = operations.bindings(deployment.registry, self.c.instance)
        _require(retained == self.plan["bindings"] and config == self.c and versions == deployment.versions)
        self.bindings = _bindings(deployment, retained, self.store)
        self.preparation = self.store.reference(self.directory + "/operation.json")
        self.admission_record = _json(self.store._bound(self.admitted["evidence"]))
        _require(self.admission_record["recipe"] == preflight.recipe()
                 and self.admission_record["graph"] == retained["graph"]
                 and self.admission_record["generation"] == retained["generation"])
        self._cache()
        self.pair = self._pair()
        uid = self.jail(self.c.nextcloud_jail, "/usr/bin/id", "-u", "www").stdout.strip()
        gid = self.jail(self.c.nextcloud_jail, "/usr/bin/id", "-g", "www").stdout.strip()
        _require(uid.isdigit() and gid.isdigit(), "www-identity-unavailable")
        self.context = update.NativeContext(operation, self.pair[self.c.nextcloud_jail],
            self.c.nextcloud_jail, deployment.jail_root(self.c.nextcloud_jail), int(uid), int(gid),
            self.c.php_memory_mb, self, self._artifact_run)
        self.validate(self.context, update.Phase.ARTIFACTS)

    def _locks(self):
        from .enrollment_start import _held
        self.d.registry._require_lock()
        admission.fence._root_required()
        _require(self.d.registry is self.admission.native.registry
                 and self.store.pending() is None, "pre-intent-only")
        _held(self.store, "operation.lock")
        _held(self.store, f"instances/{self.c.instance}/database-operation.lock")

    def _cache(self):
        parent, plan, journal = operations.load_operation(self.d.registry, self.operation)
        record = journal.read()
        _require(parent == self.parent and plan == self.plan and record["phase"] == "staged")
        return staging.verify_stage(self.store.root, self.operation, plan["artifacts"],
            record["evidence"]["artifacts"], **operations._artifact_bindings(self.d.registry, parent, plan))

    def _pair(self):
        result = {jail: self.d.require_running_jail(jail)
                  for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail)}
        _require(all(type(jid) is int and jid > 0 for jid in result.values())
                 and len(set(result.values())) == 2, "numeric-pair-identity-required")
        return result

    def _guard(self):
        self._locks()
        _require(self.store.reference(self.directory + "/operation.json") == self.preparation
                 and self.store._active() == self.plan["bindings"]["graph"])
        _require(self._pair() == self.pair, "pair-identity-changed")

    def validate(self, context, phase):
        _require(context is self.context and phase is update.Phase.ARTIFACTS,
                 "artifacts-only-authority")
        self._guard()

    def source(self, context, reference):
        self.validate(context, update.Phase.ARTIFACTS)
        self.d.require_original_artifact()
        _require(reference == update.SourceReference(
            update._digest_file(context.host(update.RETAINED), update.MAX_ARCHIVE)[0],
            update._hash(update._read(context.host(update.SHA_PROOF), 128))))
        # stage_artifacts must independently authenticate the retained tarball
        # with pinned PGP; capture then compares its entire code inventory.

    def artifacts(self, context, bundle):
        self.validate(context, update.Phase.ARTIFACTS)
        _require(bundle is self.bundle, "artifact-bundle-changed")

    def checkpoint(self, context, event, state, binding):
        self.validate(context, update.Phase.ARTIFACTS)
        _require(event in ("stage-artifacts", "import-release-key", "stage-connector")
                 and state in ("before", "after") and type(binding) is str
                 and re.fullmatch(r"[a-f0-9]{64}", binding), "unexpected-artifact-effect")
        path = self.directory + "/candidate-" + event + "-" + state + ".json"
        before = None
        if state == "after":
            before = self.store.reference(self.directory + "/candidate-" + event + "-before.json")
            previous = _json(self.store._bound(before))
            _require(previous["operation"] == self.operation and previous["event"] == event
                     and (event in ("stage-artifacts", "stage-connector") or previous["binding"] == binding))
        self.store._write_once(path, _encode(dict(schema_version=1, operation=self.operation,
            preparation=self.preparation, admission=self.admitted["evidence"], event=event,
            state=state, binding=binding, before=before)), recover=False)

    def _run(self, argv, *, stdin=b"", timeout=60, output_limit=discovery.LIMIT):
        self._guard()
        try:
            result = bounded_process.run(tuple(argv), stdin=stdin, env=bounded_process.ENV,
                                         timeout=timeout, output_limit=output_limit)
            _require(isinstance(result, update.NativeResult) and type(result.returncode) is int
                     and isinstance(result.stdout, bytes) and len(result.stdout) <= output_limit,
                     "invalid-native-observation")
            return result
        finally:
            self._guard()

    def _artifact_run(self, argv, **kwargs):
        self.validate(self.context, update.Phase.ARTIFACTS)
        _require(tuple(argv[:2]) == ("/usr/sbin/jexec", str(self.context.jid)))
        args = tuple(argv[2:])
        stage = self.context.stage
        gpg = ("/usr/local/bin/gpg", "--no-options", "--homedir", stage + "/gnupg",
               "--batch", "--no-tty", "--no-auto-key-retrieve", "--auto-key-locate", "clear")
        allowed = {
            *_connector_commands(self.context),
            (*gpg, "--import", stage + "/nextcloud.asc"),
            (*gpg, "--status-fd", "1", "--verify", stage + "/nextcloud-35.0.1.tar.bz2.asc", update.RETAINED),
            (*gpg, "--status-fd", "1", "--verify", stage + "/nextcloud-35.0.2.zip.asc", stage + "/nextcloud-35.0.2.zip"),
            ("/usr/local/bin/php", "-d", f"memory_limit={self.context.memory_mib}M", "-d", "display_errors=0",
             "-d", "log_errors=0", "-r", update._VERIFY_SIGNATURE.decode().removeprefix("<?php\n"),
             "--", stage + "/nextcloud-35.0.2.zip", stage + "/nextcloud-35.0.2.zip.sig", stage + "/source-core.crt"),
        }
        _require(args in allowed and kwargs.get("env") == bounded_process.ENV
                 and kwargs.get("stdin") == b"", "unreviewed-artifact-command")
        return self._run(argv, stdin=b"", timeout=kwargs["timeout"], output_limit=kwargs["output_limit"])

    @property
    def config(self):
        return self.c

    def jail_root(self, jail):
        return self.d.jail_root(jail)

    def jail(self, jail, *args, **kwargs):
        from .runtime_inventory import HELPER
        probes = {("/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C",
                   "/usr/local/bin/php", HELPER, name) for name in ("cli", "main", "callback")}
        allowed = {("/usr/bin/id", "-u", "www"), ("/usr/bin/id", "-g", "www"),
                   ("/usr/local/sbin/pkg", "query", "%n %v %o"), DB,
                   *(OCC + (command, "--output=json") for command in ("status", "app:list")),
                   OCC + ("config:list", "--private", "--output=json"), *probes}
        _require(jail in self.pair and tuple(args) in allowed, "unreviewed-observation-command")
        _require(jail == self.c.nextcloud_jail or tuple(args) == ("/usr/local/sbin/pkg", "query", "%n %v %o"))
        result = self._run(("/usr/sbin/jexec", str(self.pair[jail]), *args),
                           timeout=kwargs.get("timeout", 60))
        _require(result.returncode == 0, "native-observation-failed")
        return SimpleNamespace(returncode=0, stdout=result.stdout.decode("utf-8"), stderr="")

    def output(self, *args):
        allowed = {("/usr/local/sbin/pkg", "query", "%n %v %o"),
                   ("/sbin/sysctl", "-n", "hw.pagesize"),
                   ("/sbin/sysctl", "-n", "vm.stats.vm.v_free_count")}
        _require(tuple(args) in allowed, "unreviewed-host-command")
        result = self._run(args)
        _require(result.returncode == 0, "native-observation-failed")
        return result.stdout.decode("utf-8").strip()

    def capacity(self, size):
        memory = self.context.memory_mib * 1024 * 1024
        _require(memory >= 3 * size + 256 * 1024 * 1024
                 and self.context.memory_mib <= self.c.php_budget_mb, "artifact-memory-budget")
        page = int(self.output("/sbin/sysctl", "-n", "hw.pagesize"))
        free = int(self.output("/sbin/sysctl", "-n", "vm.stats.vm.v_free_count"))
        _require(page >= 4096 and free >= 0 and page * free >=
                 memory + self.c.host_reserved_mb * 1024 * 1024, "actual-free-memory-insufficient")
        for path in (update.APP, "/var/nc-data", "/var/db"):
            available = os.statvfs(self.context.host(path))
            _require(available.f_frsize > 0 and available.f_bavail * available.f_frsize >=
                     2 * update.MAX_EXPANDED + size, "actual-update-space-insufficient")

    def _recheck_source_bindings(self):
        self._guard()
        _require(self.admission._original(self.d) == self.original)
        retained, config, versions = operations.bindings(self.d.registry, self.c.instance)
        _require(retained == self.plan["bindings"] and config == self.c and versions == self.d.versions)
        self._cache()

    def recheck_source(self):
        self._guard()
        _require(self.admission._original(self.d) == self.original)
        admission._trees(self.d, self.expected["trees"])
        retained, config, versions = operations.bindings(self.d.registry, self.c.instance)
        _require(retained == self.plan["bindings"] and config == self.c and versions == self.d.versions)
        self._cache()


class _CatalogRunner:
    """Only the native discovery adapter's isolated update/rquery grammar."""

    def __init__(self, authority):
        self.authority = authority

    def run(self, *args, **kwargs):
        fixed = {("uname", "-s"): ("/usr/bin/uname", "-s"),
                 ("uname", "-m"): ("/usr/bin/uname", "-m"),
                 ("uname", "-U"): ("/usr/bin/uname", "-U"),
                 ("freebsd-version", "-u"): ("/bin/freebsd-version", "-u"),
                 ("freebsd-version", "-r"): ("/bin/freebsd-version", "-r"),
                 ("/usr/sbin/pkg", "-N"): ("/usr/sbin/pkg", "-N")}
        command = fixed.get(tuple(args))
        if command is None:
            prefix = ("/usr/bin/env", "-i", "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
                      "LC_ALL=C", "pkg", "-C", "/dev/null")
            _require(tuple(args[:7]) == prefix and len(args) in (20, 23), "unreviewed-catalog-command")
            _require(all(args[index] == "-o" for index in (7, 9, 11, 13, 15)))
            options = [args[index] for index in (8, 10, 12, 14, 16)]
            roots = []
            for value, key, leaf in zip(options[:3], ("REPOS_DIR", "PKG_DBDIR", "PKG_CACHEDIR"),
                                        ("repos", "db", "cache")):
                _require(value.startswith(key + "="))
                path = Path(value[len(key) + 1:])
                _require(path.name == leaf and path.parent.parent == self.authority.store.root / self.authority.directory
                         and re.fullmatch(r"version-catalog-[A-Za-z0-9_-]+", path.parent.name))
                roots.append(path.parent)
            _require(len(set(roots)) == 1 and options[3] == "ABI=" + self.authority.d.versions["target"]["abi"]
                     and re.fullmatch(r"OSVERSION=[1-9][0-9]{6,8}", options[4]))
            tails = {("update", "-r", "FreeBSD-ports"),
                     ("rquery", "-U", "-r", "FreeBSD-ports", "-a", "%n|%v|%o|%q|%#d|%u%d%{%|%}"),
                     ("rquery", "-U", "-r", "FreeBSD-ports", "-a", "%n|%dn|%dv|%do")}
            _require(tuple(args[17:]) in tails and kwargs.get("input", "") == "", "unreviewed-catalog-command")
            command = args
        result = self.authority._run(command, timeout=300)
        _require(result.returncode == 0 or kwargs.get("check") is False, "signed-catalog-unavailable")
        return SimpleNamespace(returncode=result.returncode, stdout=result.stdout.decode("utf-8"), stderr="")

    def output(self, *args):
        return self.run(*args).stdout.strip()


def _app_list(value):
    _require(type(value) is dict and set(value) == {"enabled", "disabled"}, "app-inventory-unavailable")
    result = {}
    for kind in ("enabled", "disabled"):
        rows = value[kind]
        if type(rows) is list and not rows:
            rows = {}
        _require(type(rows) is dict, "app-inventory-unavailable")
        for name, version in rows.items():
            _require(type(name) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name)
                     and preflight.source_app_label(name, version)
                     and name not in result, "app-inventory-unavailable")
            result[name] = dict(version=version, enabled=kind == "enabled",
                                provenance="appstore" if name == "onlyoffice" else "shipped")
    _require(result and result.get("onlyoffice", {}).get("enabled") is True, "app-inventory-unavailable")
    return result


def _canonical_base64(value, limit):
    _require(type(value) is str and 0 < len(value) <= limit
             and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", value), "connector-signature-shape")
    encoded = value.replace("\r", "").replace("\n", "").encode("ascii")
    decoded = base64.b64decode(encoded, validate=True)
    _require(decoded and base64.b64encode(decoded) == encoded, "connector-signature-shape")
    return decoded


def _certificate(value):
    _require(type(value) is str and len(value) <= 65536, "connector-certificate-missing")
    match = re.fullmatch(r"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)"
                         r"-----END CERTIFICATE-----", value.strip())
    _require(match is not None, "connector-certificate-shape")
    # Canonical DER identity only; trust is established by the native checker.
    return _canonical_base64(match[1], 65536)


def _connector_record(authority):
    record = compatibility.connector_record(authority.d.versions["connector"])
    _require(record["version"] == "10.2.1" and record["phpVersionSpec"] == ">=8.2.0 <8.6.0"
             and record["platformVersionSpec"] == ">=33.0.0 <36.0.0", "connector-record-drift")
    _canonical_base64(record["signature"], 16384)
    certificate = _certificate(record["certificate"])
    raw = connector_text(authority.d.versions).encode()
    _require(len(raw) <= 65536, "connector-record-size")
    return raw, certificate


def _source_config(authority):
    config = _json(authority.jail(authority.c.nextcloud_jail, *OCC,
                                 "config:list", "--private", "--output=json").stdout)
    _require(type(config.get("system")) is dict and type(config.get("apps")) is dict,
             "integration-inventory-unavailable")
    baseline = dict(system=config["system"], onlyoffice=config["apps"].get("onlyoffice"))
    _require(preflight.digest(baseline) == authority.expected["config:list"], "original-integration-config-drift")
    return config


def _connector_live(authority, record, certificate):
    from .maintenance_update import _custom
    context = authority.context
    tree = _custom(context)  # Complete no-follow traversal BEFORE native checker.
    raw = update._read(context.host(update.APP + "/custom_apps/onlyoffice/appinfo/signature.json"),
                       1024 * 1024, (context.www_uid,))
    signed = _json(raw)
    _require(type(signed.get("hashes")) is dict and "appinfo/info.xml" in signed["hashes"]
             and _certificate(signed.get("certificate")) == certificate, "connector-certificate-mismatch")
    _canonical_base64(signed.get("signature"), 16384)
    manifest_sha = update._hash(raw)
    _require(tree["files"]["onlyoffice/appinfo/signature.json"]["sha256"] == manifest_sha,
             "connector-manifest-raced")
    receipt = _source_config(authority)["system"].get("cloud_installer_connector_auth")
    _require(receipt == dict(record_sha256=update._hash(record), manifest_sha256=manifest_sha),
             "original-connector-receipt-mismatch")
    result = update._native(context, update.Phase.ARTIFACTS, _connector_commands(context)[0], output_limit=4096)
    _require(result == b"No errors found\n", "connector-native-integrity-unproven")
    _require(_custom(context) == tree and _source_config(authority)["system"].get(
        "cloud_installer_connector_auth") == receipt, "connector-tree-raced")
    return tree, receipt


class _ConnectorTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        archive._candidate_count = getattr(archive, "_candidate_count", 0) + 1
        _require(archive._candidate_count <= CONNECTOR_FILES
                 and self.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                 and 0 <= self.size <= update.MAX_FILE, "unsafe-connector-archive")
        # Reject PAX/GNU extension payloads before tarfile reads them.
        return super()._proc_member(archive)


def _connector_inventory(path, tree):
    files, seen, total, manifest = {}, {}, 0, None
    with update._file(path, MAX_CONNECTOR) as stream:
        with tarfile.open(fileobj=stream, mode="r|gz", tarinfo=_ConnectorTarInfo) as archive:
            for member in archive:
                _require(member.name == "onlyoffice" or member.name.startswith("onlyoffice/"),
                         "connector-archive-root")
                _require(not member.mode & 0o7000 and not member.pax_headers, "unsafe-connector-archive")
                relative = update._member("nextcloud" + member.name[len("onlyoffice"):], member.isdir(), seen)
                if member.isdir():
                    _require(member.size == 0, "unsafe-connector-archive")
                    continue
                total += member.size
                _require(total <= 1024 * 1024 * 1024, "oversized-connector-archive")
                with archive.extractfile(member) as raw:
                    if relative == "appinfo/info.xml":
                        manifest = raw.read(MAX_XML + 1)
                        _require(len(manifest) <= MAX_XML and len(manifest) == member.size,
                                 "connector-manifest-size")
                        digest, size = update._hash(manifest), len(manifest)
                    else:
                        digest, size = update._digest(raw, member.size)
                _require(size == member.size, "connector-archive-size")
                files["onlyoffice/" + relative] = dict(sha256=digest, size=size)
    expected = {name: {key: value[key] for key in ("sha256", "size")} for name, value in tree["files"].items()}
    directories = {"", "onlyoffice"} | {"onlyoffice/" + name for name, directory, _ in seen.values() if name and directory}
    _require(files == expected and directories == set(tree["directories"]), "connector-archive-tree-mismatch")
    _require(manifest is not None, "connector-manifest-missing")
    # Unlike shipped core apps, the connector may NOT inherit optional defaults.
    root = ET.fromstring(manifest)
    for name in ("php", "nextcloud"):
        nodes = root.findall("dependencies/" + name)
        _require(len(nodes) == 1 and set(nodes[0].attrib) == {"min-version", "max-version"},
                 "connector-manifest-bounds-missing")
    app = _manifest(manifest, "onlyoffice")
    _require(app == dict(version="10.2.1", phpVersionSpec=">=8.2.0 <8.6.0",
                         platformVersionSpec=">=33.0.0 <36.0.0"), "connector-manifest-incompatible")
    return app


def _connector_verify(authority, records):
    context = authority.context
    directory = context.host(context.stage)
    metadata, certificate = _connector_record(authority)
    _require(len(records) == 2 and [item["path"] for item in records] ==
             ["onlyoffice-10.2.1.tar.gz", "connector-record.json"], "connector-artifact-records")
    def bound():
        with update._directory(directory) as fd:
            _require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, "connector-stage-not-private")
        for item in records:
            _require(set(item) == {"path", "size", "sha256", "executable"}
                     and item["executable"] is False
                     and update._digest_file(directory / item["path"], MAX_CONNECTOR) ==
                     (item["sha256"], item["size"]), "connector-artifact-drift")
            with update._file(directory / item["path"], MAX_CONNECTOR) as stream:
                _require(stat.S_IMODE(os.fstat(stream.fileno()).st_mode) == 0o600,
                         "connector-artifact-not-private")
        _require(update._read(directory / "connector-record.json", 65536) == metadata,
                 "connector-record-drift")
    bound()
    authority.capacity(records[0]["size"])
    tree, original = _connector_live(authority, metadata, certificate)
    result = update._native(context, update.Phase.ARTIFACTS, _connector_commands(context)[1], output_limit=4096)
    _require(result == b"Connector archive verified\n", "connector-archive-signature-unproven")
    bound()
    app = _connector_inventory(directory / records[0]["path"], tree)
    from .maintenance_update import _custom
    _require(_custom(context) == tree, "connector-tree-raced")
    bound()
    digest = records[0]["sha256"]
    return dict(schema_version=1, operation=authority.operation, preparation=authority.preparation,
        metadata_sha256=update._hash(metadata), original=original, artifacts=records,
        tree_sha256=preflight.digest(tree), manifest=dict(**app, source_version="10.2.1",
            delivery="retained", artifact_sha256=digest),
        artifact=dict(version="10.2.1", sha256=digest, available_sha256=digest,
                      provenance="appstore-sha512-signature"))


def _stage_connector(authority, archive):
    context = authority.context
    directory = context.host(context.stage)
    metadata, _ = _connector_record(authority)
    authority.capacity(update._digest_file(Path(archive), MAX_CONNECTOR)[1])
    authority.checkpoint(context, "stage-connector", "before", update._hash(metadata))
    records = [asdict(update._create(directory, "onlyoffice-10.2.1.tar.gz", source=Path(archive), limit=MAX_CONNECTOR)),
               asdict(update._create(directory, "connector-record.json", data=metadata, limit=65536))]
    result = _connector_verify(authority, records)
    receipt = update._create(directory, "connector-receipt.json", data=_encode(result), limit=1024 * 1024)
    authority.checkpoint(context, "stage-connector", "after", receipt.sha256)
    authority.connector = result
    return receipt.sha256


def _revalidate_connector(authority, receipt_sha):
    path = authority.context.host(authority.context.stage) / "connector-receipt.json"
    raw = update._read(path, 1024 * 1024)
    with update._file(path, 1024 * 1024) as stream:
        _require(stat.S_IMODE(os.fstat(stream.fileno()).st_mode) == 0o600, "connector-receipt-not-private")
    _require(update._hash(raw) == receipt_sha, "connector-receipt-drift")
    saved = _json(raw)
    after = _json(authority.store._read(authority.directory + "/candidate-stage-connector-after.json"))
    before_ref = authority.store.reference(authority.directory + "/candidate-stage-connector-before.json")
    before = _json(authority.store._bound(before_ref))
    _require(after["binding"] == receipt_sha and after["before"] == before_ref
             and before["binding"] == saved["metadata_sha256"]
             and before["state"] == "before" and after["state"] == "after" and before["before"] is None
             and all(item["operation"] == authority.operation and item["preparation"] == authority.preparation
                     and item["event"] == "stage-connector" for item in (before, after)))
    current = _connector_verify(authority, saved["artifacts"])
    _require(current == saved and update._read(path, 1024 * 1024) == raw, "connector-receipt-drift")
    authority.connector = current


def _observations(authority, captured_at):
    packages = {}
    for group, jail in (("host", None), ("nextcloud", authority.c.nextcloud_jail),
                        ("onlyoffice", authority.c.onlyoffice_jail)):
        args = ("/usr/local/sbin/pkg", "query", "%n %v %o")
        output = authority.output(*args) if jail is None else authority.jail(jail, *args).stdout
        rows = [line.split() for line in output.splitlines() if line.strip()]
        _require(rows and all(len(row) == 3 for row in rows), "complete-package-inventory-required")
        packages[group] = [dict(zip(("name", "version", "origin"), row)) for row in sorted(rows)]
    php = collect_php(authority)
    rows = authority.jail(authority.c.nextcloud_jail, *DB).stdout.strip().splitlines()
    _require(len(rows) >= 2 and len(rows[0].split("\t")) == 2, "database-observation-unavailable")
    version, isolation = rows[0].split("\t")
    match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)-MariaDB(?:-[A-Za-z0-9._+-]+)?", version)
    _require(match is not None and rows[1:] == sorted(set(rows[1:])), "database-observation-unavailable")
    database = dict(vendor="MariaDB", version=match[1], isolation=isolation, engines=rows[1:])
    def occ(*args):
        return _json(authority.jail(authority.c.nextcloud_jail, *OCC, *args).stdout)
    status = occ("status", "--output=json")
    apps = _app_list(occ("app:list", "--output=json"))
    if authority.connector is not None:
        apps["onlyoffice"]["artifact_sha256"] = authority.connector["artifact"]["sha256"]
    config = _source_config(authority)
    system, settings = config["system"], config["apps"]
    # Exact initial source/config identity plus the original admission's shipped
    # tree inventory is required before asserting absence of integrations.
    external = any(apps.get(name, {}).get("enabled") is True
                   for name in ("files_external", "user_ldap", "user_external"))
    external |= any(bool(system.get(key)) for key in ("objectstore", "objectstore_multibucket"))
    unmanaged = bool(set(settings) - (set(apps) | {"core", "backgroundjob"}))
    background = settings.get("backgroundjob", {})
    unmanaged |= type(background) is not dict or bool(set(background) - {"lastjob"})
    unmanaged |= system.get("mail_smtpmode") not in (None, "", "null")
    unmanaged |= any(bool(system.get(key)) for key in ("user_backends", "ldapProviderFactory",
        "mail_smtphost", "mail_smtpport", "mail_smtpname", "mail_smtppassword"))
    for name in ("files_external", "user_ldap", "user_external"):
        values = settings.get(name, {})
        unmanaged |= type(values) is not dict or bool(set(values) - {"enabled", "installed_version", "types"})
    nc = {key: status[key] for key in ("installed", "maintenance", "needsDbUpgrade", "version", "versionstring")}
    return dict(schema_version=1, captured_at=captured_at, bindings=authority.bindings,
                packages=packages, php=php, database=database, nextcloud=dict(**nc, apps=apps),
                integrations=dict(external_storage=external, unmanaged_integrations=unmanaged))


def _manifest(data, name, *, source=False):
    _require(len(data) <= MAX_XML and b"<!DOCTYPE" not in data.upper()
             and b"<!ENTITY" not in data.upper(), "app-manifest-unavailable")
    root = ET.fromstring(data)
    _require(root.tag == "info" and len(root.findall("id")) == len(root.findall("version")) == 1
             and root.findtext("id") == name, "app-manifest-identity")
    version = root.findtext("version")
    _require(type(source) is bool and type(version) is str
             and (preflight.source_app_label(name, version) if source else
                  re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)), "app-manifest-version")
    _require(len(root.findall("dependencies")) <= 1, "app-manifest-dependencies")
    def bounds(kind, fallback):
        nodes = root.findall("dependencies/" + kind)
        _require(len(nodes) <= 1, "app-manifest-dependencies")
        if not nodes:
            return fallback
        node = nodes[0]
        _require(set(node.attrib) <= {"min-version", "max-version"} and not list(node),
                 "app-manifest-dependencies")
        limits = fallback.split()
        for index, key in enumerate(("min-version", "max-version")):
            if key not in node.attrib:
                continue
            value = node.attrib[key]
            _require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", value), "app-manifest-dependencies")
            numbers = list(map(int, value.split(".")))
            if index:
                numbers[-1] += 1
            numbers += [0] * (3 - len(numbers))
            limits[index] = ("<" if index else ">=") + ".".join(map(str, numbers))
        return " ".join(limits)
    # Shipped inventories are authenticated as the exact vendor NC 35 pair.
    # The connector caller separately requires both explicit bounds.
    # Absent optional app bounds inherit the reviewed core35 platform contract;
    # this does not change installation/package policy or cover custom apps.
    return dict(version=version, phpVersionSpec=bounds("php", ">=8.3.0 <8.6.0"),
                platformVersionSpec=bounds("nextcloud", ">=35.0.0 <36.0.0"))


def _manifests(context, bundle):
    def wanted(inventory):
        return {item.path: item for item in inventory.files
                if re.fullmatch(r"apps/[a-z][a-z0-9_]{0,63}/appinfo/info.xml", item.path)}
    source_files, target_files = wanted(bundle.source_inventory), wanted(bundle.target_inventory)
    source, target = {}, {}
    with update._file(context.host(update.RETAINED), update.MAX_ARCHIVE) as stream:
        with tarfile.open(fileobj=stream, mode="r|bz2", tarinfo=update._BoundedTarInfo) as archive:
            for member in archive:
                path = member.name.removeprefix("nextcloud/")
                if path in source_files:
                    _require(member.isfile() and member.size <= MAX_XML, "app-manifest-unavailable")
                    with archive.extractfile(member) as raw:
                        data = raw.read(MAX_XML + 1)
                    _require(update._hash(data) == source_files[path].sha256, "app-manifest-byte-drift")
                    source[path.split("/")[1]] = _manifest(data, path.split("/")[1], source=True)
    with update._file(context.host(context.stage) / "nextcloud-35.0.2.zip", update.MAX_ARCHIVE) as stream:
        with zipfile.ZipFile(stream) as archive:
            for path, item in target_files.items():
                _require(item.size <= MAX_XML, "app-manifest-unavailable")
                with archive.open("nextcloud/" + path) as raw:
                    data = raw.read(MAX_XML + 1)
                _require(update._hash(data) == item.sha256, "app-manifest-byte-drift")
                target[path.split("/")[1]] = _manifest(data, path.split("/")[1])
    _require(source and len(source) == len(source_files) and source.keys() == target.keys(),
             "app-manifest-inventory-changed")
    digest = next(item.sha256 for item in bundle.artifacts if item.path == "nextcloud-35.0.2.zip")
    return {name: dict(**manifest, source_version=source[name]["version"], delivery="shipped",
                       artifact_sha256=digest) for name, manifest in target.items()}


def _repository(authority, bundle, captured_at):
    cache = authority._cache()
    available = {}
    for item in cache["artifacts"]:
        if item["kind"] == "package":
            for name in item["packages"]:
                available[name] = item["sha256"]
    with discovery._catalog(authority.c, _CatalogRunner(authority),
                             directory=authority.store.root / authority.directory) as (target, packages, _):
         catalog = preflight.digest(dict(target=target, repository=authority.c.repository, packages=packages))
    # This fixed edge changes no packages. Bind the entire signed catalogue by
    # digest, retaining every dependency of all three locked root sets, not tens
    # of thousands of unrelated ports in a private 16-MiB state document.
    selected = {}
    for group in GROUPS:
        selected.update(compatibility.closure(packages, authority.d.versions["roots"][group]))
    packages = selected
    _require(not available, "unexpected-staged-package-archives")
    available = {name: item["checksum"] for name, item in packages.items()}
    checksum = next(item.sha256 for item in bundle.artifacts if item.path == "nextcloud-35.0.2.zip")
    artifacts = dict(nextcloud=dict(version=update.TARGET[0], internal_version=update.TARGET[1],
        sha256=checksum, available_sha256=checksum, provenance="authenticated-release"))
    apps = _manifests(authority.context, bundle)
    if authority.connector is not None:
        artifacts["connector"] = authority.connector["artifact"]
        apps["onlyoffice"] = authority.connector["manifest"]
    return dict(schema_version=1, captured_at=captured_at, bindings=authority.bindings,
        target=target, repository=authority.c.repository, catalog_sha256=catalog,
        trust="native-pkg-signed-catalog", packages=packages, available_packages=available,
        artifacts=artifacts, apps=apps,
        package_transaction=[], solver_receipt=None)


def _report(authority, observations, repository, blockers, now):
    report = preflight.assess(authority.c, authority.d.versions, observations, repository,
                             bindings=authority.bindings, now=now)
    blockers = set(report["blockers"]) | set(blockers)
    connector = getattr(authority, "connector", None)
    if connector is None:
        blockers.update((CONNECTOR_BLOCKER, "application-compatibility-unknown"))
    elif (repository.get("artifacts", {}).get("connector") != connector["artifact"]
          or repository.get("apps", {}).get("onlyoffice") != connector["manifest"]):
        blockers.add("connector-capture-binding-mismatch")
    # Missing connector archive evidence must not suppress useful evaluation of
    # the independently authenticated shipped apps. The pure whole-repository
    # gate intentionally cannot enter _apps until ALL artifacts are available.
    try:
        apps = observations["nextcloud"]["apps"]
        manifests = {name: value for name, value in repository["apps"].items() if name != "onlyoffice"}
        php = observations["php"]["cli"]["version"]
        _require(set(apps) - {"onlyoffice"} == set(manifests) and "serverinfo" in manifests)
        for name, manifest in manifests.items():
            _require(apps[name]["version"] == manifest["source_version"]
                     and apps[name]["provenance"] == "shipped" and manifest["delivery"] == "shipped"
                     and manifest["artifact_sha256"] == repository["artifacts"]["nextcloud"]["sha256"]
                     and compatibility.in_range(php, compatibility.version_spec(manifest["phpVersionSpec"]))
                     and compatibility.in_range(update.TARGET[0],
                                                compatibility.version_spec(manifest["platformVersionSpec"])))
        _require(manifests["serverinfo"]["source_version"] == manifests["serverinfo"]["version"] == "7.0.0")
    except (ValueError, KeyError, TypeError):
        blockers.add("shipped-application-incompatible-or-unknown")
    if blockers:
        report.update(status="blocked", eligible=False, candidate=None, blockers=sorted(blockers))
    return report


def collect(deployment, preparation, *, source_admission, target_zip, target_asc,
            target_sig, source_asc, public_key, connector_archive=None):
    """Capture actual inputs and seal a non-executable receipt before begin.

    Incompatibility is recorded, not converted to execution authority. Call
    revalidate before any proposed native begin; it rechecks live source/runtime,
    exact archive bytes, catalogs and observation age and refuses blocked results.
    Neither function accepts operator JSON as an eligible candidate.
    connector_archive supplies local bytes, never trust; omission stays unknown.
    """
    try:
        authority = ArtifactsOnlyAuthority(deployment, preparation, source_admission)
        context = authority.context
        authority.capacity(update._digest_file(Path(target_zip), update.MAX_ARCHIVE)[1])
        parent = context.host(update.STAGING)
        if not os.path.lexists(parent):
            update._mkdir(parent)
        with update._directory(parent) as fd:
            info = os.fstat(fd)
            _require(info.st_uid == update._ROOT_UID and stat.S_IMODE(info.st_mode) == 0o700,
                     "private-artifact-parent-required")
        bundle = update.stage_artifacts(context, target_zip=target_zip, target_asc=target_asc,
            target_sig=target_sig, source_asc=source_asc, public_key=public_key)
        authority.bundle = bundle
        from .maintenance_update import _code, _hardened
        _hardened(context, _code(context, bundle.source_inventory))
        started = int(time.time())
        connector_receipt = None if connector_archive is None else _stage_connector(authority, connector_archive)
        observations, repository, blockers = {}, {}, []
        for label, capture in (("runtime-observation-unavailable", lambda: _observations(authority, started)),
                               ("repository-or-manifest-unavailable", lambda: _repository(authority, bundle, started))):
            try:
                value = capture()
                if label == "runtime-observation-unavailable":
                    observations = deepcopy(value)
                else:
                    repository = value
            except Exception:
                blockers.append(label)
        authority.recheck_source()
        update._bound(context, bundle, update.Phase.ARTIFACTS)
        update._source_bound(context, bundle.source)
        # Initial collection can spend minutes authenticating static trees and
        # repository inputs. Obtain genuinely new runtime evidence at the end,
        # never merely retimestamp the earlier values or a saved candidate.
        if observations:
            try:
                final_observations = deepcopy(_observations(authority, int(time.time())))
            except Exception:
                blockers.append("runtime-observation-unavailable")
            else:
                _require({k: v for k, v in final_observations.items() if k != "captured_at"} ==
                         {k: v for k, v in observations.items() if k != "captured_at"}, "candidate-inputs-changed")
                observations = final_observations
        report = _report(authority, observations, repository, blockers, int(time.time()))
        value = dict(schema_version=1, kind="captured-maintenance-candidate", operation=preparation,
            preparation=authority.preparation, plan=authority.parent["plan"], recipe=preflight.recipe(),
            admission=authority.admitted["evidence"], bindings=authority.bindings,
            observations=observations, repository=repository, report=report,
            observations_sha256=preflight.digest(observations), repository_sha256=preflight.digest(repository),
            bundle=update.bundle_record(bundle), connector_receipt_sha256=connector_receipt,
            execution_authorized=False, native_acceptance="not-run")
        encoded = _encode(value)
        _require(len(encoded) <= MAX_FILE_BYTES, "candidate-record-too-large")
        reference = authority.store._write_once(authority.directory + "/candidate.json", encoded, recover=False)
        return CapturedCandidate(preparation, reference, bundle)
    except CandidateError:
        raise
    except Exception:
        raise CandidateError("capture-incomplete") from None


def load(store, operation):
    """Decode the retained receipt without probes, writes or execution authority.

    This is not resume or admission. The caller must still revalidate the live
    source, authenticated artifacts and catalogs under both locks before begin.
    Old receipts with noncanonical bindings are deliberately not repaired here.
    """
    try:
        _require(type(operation) is str and re.fullmatch(r"maint-[a-f0-9]{32}", operation),
                 "preparation-owner-required")
        directory = "maintenance/operations/" + operation
        reference = store.reference(directory + "/candidate.json")
        record = _json(store._bound(reference))
        _fields(record, "schema_version kind operation preparation plan recipe admission bindings "
                "observations repository report observations_sha256 repository_sha256 bundle "
                "connector_receipt_sha256 execution_authorized native_acceptance")
        _require(type(record["schema_version"]) is int and record["schema_version"] == 1
                 and record["kind"] == "captured-maintenance-candidate"
                 and record["operation"] == operation and record["recipe"] == preflight.recipe()
                 and record["execution_authorized"] is False and record["native_acceptance"] == "not-run")
        _reference(record["preparation"], directory + "/operation.json")
        for key in ("preparation", "plan", "admission"):
            _reference(record[key])
            store._bound(record[key])
        _fields(record["bindings"], "config_sha256 versions_sha256 graph_sha256 generation_sha256 "
                "network_sha256 executor_sha256")
        _require(all(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value)
                     for value in record["bindings"].values()))
        for key in ("observations", "repository"):
            _require(type(record[key]) is dict and record[key + "_sha256"] == preflight.digest(record[key]))
        connector = record["connector_receipt_sha256"]
        _require(connector is None or (type(connector) is str and re.fullmatch(r"[a-f0-9]{64}", connector)))
        bundle = update.decode_bundle(record["bundle"])
        _require(bundle.operation == operation)
        return CapturedCandidate(operation, reference, bundle)
    except CandidateError:
        raise
    except Exception:
        raise CandidateError("retained-candidate-invalid") from None


def revalidate(captured, deployment, *, source_admission):
    """Public inspection result retains the original reference-only contract."""
    return revalidate_for_execution(captured, deployment, source_admission=source_admission).reference


def require_execution_freshness(store, checked, *, now=None):
    """Recheck original protected timestamps at the actual intent boundary."""
    _require(type(checked) is RevalidatedCandidate, "revalidated-candidate-required")
    record = _json(store._bound(checked.reference))
    now = int(time.time()) if now is None else now
    try:
        preflight._fresh(record["observations"]["captured_at"], now, preflight.MAX_OBSERVATION_AGE)
        preflight._fresh(record["repository"]["captured_at"], now, preflight.MAX_CATALOG_AGE)
    except (ValueError, TypeError, KeyError):
        raise CandidateError("candidate-ineligible-or-stale") from None


def revalidate_for_execution(captured, deployment, *, source_admission):
    """Required pre-begin refusal gate; no native intent or boot-fence effects."""
    try:
        _require(type(captured) is CapturedCandidate, "captured-receipt-required")
        _require(load(source_admission.native.store, captured.operation) == captured,
                 "retained-candidate-changed")
        authority = ArtifactsOnlyAuthority(deployment, captured.operation, source_admission)
        _require(captured.reference == authority.store.reference(authority.directory + "/candidate.json"))
        record = _json(authority.store._bound(captured.reference))
        _require(record["preparation"] == authority.preparation and record["plan"] == authority.parent["plan"]
                 and record["recipe"] == preflight.recipe() and record["bindings"] == authority.bindings
                 and record["bundle"] == json.loads(_encode(update.bundle_record(captured.bundle))))
        authority.bundle = captured.bundle
        update._bound(authority.context, captured.bundle, update.Phase.ARTIFACTS)
        update._source_bound(authority.context, captured.bundle.source)
        # Construction just performed both admission tree scans under these same
        # locks. Recheck all bindings here; retain the final full tree scan after
        # candidate queries. This is not reusable/caller-supplied admission.
        authority._recheck_source_bindings()
        from .maintenance_update import _code, _hardened
        _hardened(authority.context, _code(authority.context, captured.bundle.source_inventory))
        if record.get("connector_receipt_sha256") is not None:
            _revalidate_connector(authority, record["connector_receipt_sha256"])
        now = int(time.time())
        observations = _observations(authority, now)
        repository = _repository(authority, captured.bundle, now)
        update._bound(authority.context, captured.bundle, update.Phase.ARTIFACTS)
        update._source_bound(authority.context, captured.bundle.source)
        for key, fresh in (("observations", observations), ("repository", repository)):
            saved = record[key]
            _require(record[key + "_sha256"] == preflight.digest(saved)
                     and {k: v for k, v in fresh.items() if k != "captured_at"} ==
                         {k: v for k, v in saved.items() if k != "captured_at"}, "candidate-inputs-changed")
        authority.recheck_source()
        # Use the actual assessment time AFTER expensive queries/binding checks,
        # not the earlier timestamp at which the fresh query pass began.
        assessed_at = int(time.time())
        old = _report(authority, record["observations"], record["repository"], [], assessed_at)
        fresh = _report(authority, observations, repository, [], assessed_at)
        _require(old["eligible"] and fresh["eligible"] and record["report"] == old,
                 "candidate-ineligible-or-stale")
        return RevalidatedCandidate(captured.reference, authority.admitted)
    except CandidateError:
        raise
    except Exception:
        raise CandidateError("candidate-revalidation-failed") from None
