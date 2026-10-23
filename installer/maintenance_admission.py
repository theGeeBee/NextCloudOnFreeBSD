"""First-edge, same-artifact admission for the trusted native acceptance harness.

No operator document, observed replacement baseline, or enrollment confirmation
grants admission. This is not the production recipe catalog or a compatibility /
security assessment. Those independent gates and native acceptance remain required.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from . import enrollment, maintenance_fence as fence
from .generations import _encode, _json
from .maintenance_native import AcceptanceHarness, NativeBackend
from .maintenance_state import NativeState
from .paths import PROJECT_ROOT
from .state import Journal, config_digest


DENIED = "Original-generation maintenance admission refused"
# This is the same fixed projection used to create the first-readiness baseline.
# Never derive allowed symlink destinations or executable roots from caller JSON.
STATIC_ROOTS = enrollment.STATIC_ROOTS


def _require(value):
    if not value:
        raise ValueError(DENIED)


def descriptor():
    """Exact compiled successor recipe; implementation is executor-hash bound."""
    from .maintenance_preflight import recipe
    return recipe()


def _trees(deployment, expected):
    """Authenticate ALL executable/config trees before the first installed PHP.

    _observe compares only after its occ calls; calling it alone would already
    execute changed code. The original baseline supplies hashes, never paths.
    """
    c = deployment.config
    _require(type(expected) is dict and set(expected) == {c.nextcloud_jail, c.onlyoffice_jail})
    for jail, application in ((c.nextcloud_jail, "nextcloud"),
                              (c.onlyoffice_jail, "onlyoffice/documentserver")):
        root = deployment.jail_root(jail)
        _require(root == Path(c.bastille_root) / "jails" / jail / "root")
        names = (*STATIC_ROOTS, "usr/local/www/" + application)
        unbound = root / "etc/unbound"
        if unbound.is_symlink() and os.readlink(unbound) == "../var/unbound":
            names += ("var/unbound",)
        _require(type(expected[jail]) is dict and set(expected[jail]) == set(names))
        roots = tuple(root / name for name in names)
        for name in names:
            _require(enrollment._tree_identity(root / name, jail_root=root,
                     observed_roots=roots) == expected[jail][name])


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _at_inventory(root):
    """Inspect the two fixed native at containers, never execute an at command.

    Reviewed 2026-10-15, FreeBSD releng/15.1:
    https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/etc/mtree/BSD.var.dist
    https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/usr.bin/at/Makefile.inc
    https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/usr.bin/at/Makefile
    https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/usr.bin/at/at.c
    https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/usr.bin/at/privs.h
    https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/lib/libsys/open.2

    mtree pins jobs/spool to daemon(1):wheel(0), 0755; their parent is root.
    Setuid-root at opens jobs/.lockfile O_WRONLY|O_CREAT, requested mode 0600,
    before dropping privilege, and never writes it. open(2) assigns the parent's
    group, wheel. Only that exact empty file is allowed. at's subsequent .SEQ
    allocation is not an empty-queue proof and
    remains refused along with every job/output file. No general daemon-owned
    ancestry exception, umask-derived modes, or newly observed baseline is used.
    """
    enrollment._directory(root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors, edges = [], []

    def opened(name, parent=None):
        fd = os.open(name, flags, dir_fd=parent)
        descriptors.append(fd)
        before = os.fstat(fd)
        _require(_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _identity(before))
        edges.append((parent, name, fd, before))
        return fd, before

    def names(fd, allowed):
        result = set()
        with os.scandir(fd) as entries:
            for item in entries:
                _require(item.name in allowed and item.name not in result)
                result.add(item.name)
        return result

    try:
        parent, info = opened(root)
        # Admission's root gate makes geteuid() exactly zero. Keep the same
        # root-only rule for all jail ancestors, not just the immediate parent.
        for component in (None, "var", "at"):
            if component is not None:
                parent, info = opened(component, parent)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                     and not info.st_mode & 0o022)
        for name in ("jobs", "spool"):
            fd, before = opened(name, parent)
            _require(stat.S_ISDIR(before.st_mode) and before.st_uid == 1 and before.st_gid == 0
                     and stat.S_IMODE(before.st_mode) == 0o755)
            allowed = {".lockfile"} if name == "jobs" else set()
            initial = names(fd, allowed)
            if initial:
                lock = os.open(".lockfile", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                descriptors.append(lock)
                original = os.fstat(lock)
                edges.append((fd, ".lockfile", lock, original))
                _require(stat.S_ISREG(original.st_mode) and original.st_uid == 0 and original.st_gid == 0
                         and stat.S_IMODE(original.st_mode) == 0o600 and original.st_nlink == 1
                         and original.st_size == 0 and os.read(lock, 1) == b"")
                _require(_identity(original) == _identity(os.fstat(lock)) ==
                         _identity(os.stat(".lockfile", dir_fd=fd, follow_symlinks=False)))
            _require(names(fd, allowed) == initial and _identity(os.fstat(fd)) == _identity(before))
        for parent, name, fd, before in edges:
            _require(_identity(os.fstat(fd)) == _identity(before) ==
                     _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _scheduled_writers(deployment):
    """The sole installed user crontab is the source-bound Nextcloud template.

    /etc cron/periodic code is covered by the first-readiness trees. Spool jobs
    are outside those trees and must not become a retrospectively adopted hash.
    """
    c = deployment.config
    template = (PROJECT_ROOT / "resources/templates/nextcloud/www-crontab").read_bytes()
    for jail in (c.nextcloud_jail, c.onlyoffice_jail):
        root = deployment.jail_root(jail)
        _at_inventory(root)
        for relative in ("var/cron/tabs",):
            path = root / relative
            expected = {"www"} if relative == "var/cron/tabs" and jail == c.nextcloud_jail else set()
            if not os.path.lexists(path):
                _require(not expected)
                continue
            enrollment._directory(path, private=True)
            _require(stat.S_IMODE(path.lstat().st_mode) == 0o700)
            _require({item.name for item in path.iterdir()} == expected)
            for name in expected:
                # Includes private mode, owner, no links and bounded reads.
                enrollment._bytes(path / name)
        if jail == c.nextcloud_jail:
            result = deployment.jail(jail, "crontab", "-u", "www", "-l", hide_output=True)
            _require(result.returncode == 0 and result.stdout.encode() == template)


def _integrations(deployment):
    """Inspect authenticated code/config only; retain digests, never credentials."""
    backend = NativeBackend(deployment)
    apps = _json(backend.occ("app:list", "--output=json").encode())
    config = _json(backend.occ("config:list", "--private", "--output=json").encode())
    _require(set(apps) == {"enabled", "disabled"} and type(apps["enabled"]) is dict
             and type(apps["disabled"]) in (dict, list))
    enabled = apps["enabled"]
    _require(enabled.get("onlyoffice") == "10.2.1"
             and not {"files_external", "user_ldap", "user_external"}.intersection(enabled))
    root = deployment.jail_root(deployment.config.nextcloud_jail) / "usr/local/www/nextcloud"
    custom = root / "custom_apps"
    _require(not custom.is_symlink() and custom.is_dir()
             and {item.name for item in custom.iterdir()} == {"onlyoffice"})
    shipped = {item.name for item in (root / "apps").iterdir() if item.is_dir() and not item.is_symlink()}
    known = set(enabled) | set(apps["disabled"])
    _require(known == shipped | {"onlyoffice"})
    system, settings = config["system"], config["apps"]
    _require(type(system) is dict and type(settings) is dict
             and set(settings) <= known | {"core", "backgroundjob"})
    _require(system.get("datadirectory") == "/var/nc-data" and system.get("dbtype") == "mysql"
             and system.get("dbhost") in ("127.0.0.1", "localhost", "localhost:/var/run/mysql/mysql.sock"))
    _require(not any(system.get(key) for key in ("objectstore", "objectstore_multibucket",
                 "user_backends", "ldapProviderFactory", "mail_smtphost", "mail_smtpport",
                 "mail_smtpname", "mail_smtppassword", "mail_smtpauth", "mail_smtpsecure")))
    _require(system.get("mail_smtpmode") in (None, "", "null"))
    for name in ("files_external", "user_ldap", "user_external"):
        values = settings.get(name, {})
        _require(type(values) is dict and set(values) <= {"enabled", "installed_version", "types"})
    background = settings.get("backgroundjob", {})
    _require(type(background) is dict and set(background) <= {"lastjob"})
    return {"apps_sha256": hashlib.sha256(_encode(apps)).hexdigest(),
            "config_sha256": hashlib.sha256(_encode(config)).hexdigest()}


class SourceAdmission(AcceptanceHarness):
    """Construct only in trusted Python with a NativeState for the locked host.

    admit_source is pre-intent only. Resume uses the controller's retained
    admission; this adapter cannot admit a successor or a pending operation.
    """

    def __init__(self, native):
        _require(isinstance(native, NativeState))
        self.native = native

    def descriptor(self):
        return descriptor()

    def _original(self, deployment):
        from .maintenance import executor_record, require_instance_adapter

        registry, store = self.native.registry, self.native.store
        registry._require_lock()
        fence._root_required()
        _require(deployment.registry is registry
                 and self.native.executor == executor_record() and store.pending() is None)
        from .enrollment_start import _held
        _held(store, "operation.lock")
        _held(store, f"instances/{deployment.config.instance}/database-operation.lock")
        for path in (store.root, deployment.state):
            enrollment._directory(path, private=True)
            info = path.lstat()
            _require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        c = deployment.config.validate()
        _require(c.schema_version == 2 and c.tls_mode == "provided" and not c.onlyoffice_plugins)
        _require(not enrollment._exists(deployment.state / "plugins.json"))
        _require(deployment.state == store.root / "instances" / c.instance)
        require_instance_adapter(registry, c.instance)
        _require(_json(store._read("lifecycle/executor.json")) == self.native.executor)
        graph = store.graph()
        graph_ref = store._active()
        entry = graph["instances"][c.instance]
        _require(entry["kind"] == "managed" and entry["status"]["state"] == "ready")
        manifest = store._generation(c.instance, entry["generation"])
        _require(manifest["kind"] == "instance-generation" and manifest["predecessor"] is None
                 and manifest["origin"] == "legacy-enrollment" and manifest["recipe"] is None
                 and manifest["provenance"]["source_sha256"] == self.native.executor["source_sha256"])
        archive = store._archive(c.instance, manifest["archive"])
        _require(store._bound(manifest["provenance"]["policy"]) ==
                 (PROJECT_ROOT / "resources/versions.json").read_bytes())
        _require(_json(store._bound(manifest["config"])) == json.loads(c.to_json()))
        from .resolution import validate_plan
        plan = validate_plan(c, _json(store._bound(manifest["versions"])))
        _require(plan == deployment.versions)
        from .maintenance_generations import target_plan
        target_plan(store._bound(manifest["config"]), plan)
        resources = _json(store._bound(manifest["resources"]))
        _require(resources["schema"] == 1 and resources["adapter"] == enrollment.ADAPTER
                 and resources["instance"] == c.instance and resources["eligible"] is True
                 and resources["blockers"] == []
                 and resources["coverage"] == "first-readiness-static-identity-comparison"
                 and resources["source_sha256"] == self.native.executor["source_sha256"]
                 and resources["config_sha256"] == config_digest(c))
        required = {"config.json", "status.json", "deployment.json", "versions.json", "inventory.json",
                    "source.sha256", "inputs.sha256", "complete", "allow-start", enrollment.BASELINE}
        _require(set(resources["artifacts"]) == required)
        for name, digest in resources["artifacts"].items():
            reference = archive["files"][name]
            _require(reference["sha256"] == digest)
            data = store._bound(reference)
            # Enrollment replaced the live lookup with a descriptor, not config.
            actual = store._bound(manifest["config"]) if name == "config.json" else enrollment._bytes(deployment.state / name)
            _require(actual == data)
        baseline_ref = archive["files"][enrollment.BASELINE]
        baseline = _json(store._bound(baseline_ref))
        bindings = enrollment._baseline_bindings(deployment)
        _require(set(baseline) == {*bindings, "observation"}
                 and all(baseline[key] == value for key, value in bindings.items()))
        enrollment._idle(deployment)
        journal = Journal(deployment.state / "deployment.json", c)
        required_steps = {"instance ZFS storage", "private networking and PF", "FreeBSD jail roots",
                          "persistent mounts", "Nextcloud publication", "readiness checks", "boot activation"}
        _require(required_steps <= journal.data["steps"].keys()
                 and all(item.get("state") == "complete" for item in journal.data["steps"].values()))
        _require(not enrollment._exists(deployment.state / "enrollment-unavailable.json"))
        enrollment._inputs(deployment)
        deployment.validate_resume(journal)
        enrollment.validate_guard(deployment, dispatcher=PROJECT_ROOT / "installer/maintenance.py")
        return graph_ref, entry["generation"], manifest["resources"], baseline_ref, baseline["observation"]

    def admit_source(self, deployment):
        try:
            graph, generation, resources, baseline, expected = self._original(deployment)
            _trees(deployment, expected["trees"])
            # Only now may any installed executable inspect application state.
            packages = enrollment._packages(deployment, enrollment._json(deployment.state / "inventory.json"))
            _require(packages == _json(self.native.store._bound(resources))["package_inventory_sha256"])
            enrollment._plugins(deployment)
            startup = {jail: fence.startup_inventory(deployment.jail_root(jail),
                       nextcloud=jail == deployment.config.nextcloud_jail)
                       for jail in (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail)}
            _scheduled_writers(deployment)
            # The first full scan above already authenticated this exact tree
            # component before installed PHP. Collect every other observation
            # unchanged, then bracket it with the closing full scan below.
            _require(enrollment._observe_non_tree(deployment) ==
                     {key: value for key, value in expected.items() if key != "trees"})
            integrations = _integrations(deployment)
            # Detect moving inputs/trees rather than seal a mixture of identities.
            _require(self._original(deployment) == (graph, generation, resources, baseline, expected))
            _trees(deployment, expected["trees"])
            store = self.native.store
            record = dict(schema_version=1, kind="original-generation-admission",
                instance=deployment.config.instance, executor=self.native.executor, recipe=self.descriptor(),
                graph=graph, generation=generation, resources=resources, first_readiness=baseline,
                startup=startup, **integrations, native_acceptance="not-run", execution_authorized=False)
            store._mkdir("maintenance/admissions")
            evidence = store._write_once("maintenance/admissions/" + uuid.uuid4().hex + ".json",
                                         _encode(record), recover=False)
            return dict(startup=startup, evidence=evidence)
        except Exception:
            # Native diagnostics/configuration and private filenames stay private.
            raise ValueError(DENIED) from None
