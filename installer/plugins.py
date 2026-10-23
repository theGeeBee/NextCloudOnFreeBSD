"""Pinned, static ONLYOFFICE add-ons; no application or package execution.

Mutation callers hold the global installer operation lock. Library callers must
validate_lock against the reviewed catalog before trusting a saved lock; the CLI
does this itself. fetch(url) returns a closable binary stream. Failed atomic-write
temporaries are private diagnostics, retained rather than removed or reused.
"""

import argparse
from contextlib import closing
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import urllib.parse
import urllib.request
import uuid
import zipfile


CATALOG = Path(__file__).resolve().parent.parent / "resources/plugins/onlyoffice.json"
ROOT_UID = 0
ARCHIVE_LIMIT = 32 * 1024 * 1024
TREE_LIMIT = 128 * 1024 * 1024
ENTRY_LIMIT = 5000
CHUNK = 128 * 1024


def _require(condition, message="Invalid plugin metadata"):
    if not condition:
        raise ValueError(message)


def _fields(value, names):
    _require(isinstance(value, dict) and set(value) == set(names.split()))


def _match(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _relative(value):
    _require(isinstance(value, str) and 0 < len(value) <= 1024)
    parts = value.split("/")
    _require(all(p and p not in (".", "..") and not p.endswith((".", " "))
                 and not any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in p)
                 for p in parts), "Unsafe plugin path")
    return value


def _paths(paths):
    """Check aliases in both filenames and their implied directory components."""
    seen = {}
    files = set(paths)
    for path in files:
        parts = _relative(path).split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            folded = prefix.casefold()
            _require(folded not in seen or seen[folded] == prefix, "Plugin path collision")
            seen[folded] = prefix
            _require(index == len(parts) or prefix not in files, "Plugin path collision")


def _catalog(value):
    _fields(value, "schema docs_version source_commit plugins")
    _require(type(value["schema"]) is int and value["schema"] == 1
             and value["docs_version"] == "9.4.0"
             and _match(value["source_commit"], r"[0-9a-f]{40}")
             and isinstance(value["plugins"], dict) and len(value["plugins"]) <= 10)
    guids = set()
    for slug, record in value["plugins"].items():
        _require(_match(slug, r"[a-z][a-z0-9_-]{0,63}"))
        _fields(record, "name guid version format artifacts tree")
        _require(isinstance(record["name"], str) and 0 < len(record["name"]) <= 256
                 # Upstream Photo Editor's GUID contains the non-hex group AL24.
                 and _match(record["guid"], r"asc\.\{[A-Za-z0-9]{8}(?:-[A-Za-z0-9]{4}){3}-[A-Za-z0-9]{12}\}")
                 and _match(record["version"], r"[0-9]+(?:\.[0-9]+){0,3}")
                 and record["format"] in ("zip", "files"))
        _require(record["guid"].casefold() not in guids, "Duplicate plugin GUID")
        guids.add(record["guid"].casefold())
        tree = record["tree"]
        _require(isinstance(tree, dict) and 0 < len(tree) <= ENTRY_LIMIT and "config.json" in tree)
        _paths(tree)
        _require(all(_match(digest, r"[0-9a-f]{64}") for digest in tree.values()))
        artifacts = record["artifacts"]
        _require(isinstance(artifacts, list) and 0 < len(artifacts) <= ENTRY_LIMIT)
        paths = []
        for artifact in artifacts:
            _fields(artifact, "path url sha256 size")
            path = _relative(artifact["path"])
            paths.append(path)
            prefix = ("https://raw.githubusercontent.com/ONLYOFFICE/onlyoffice.github.io/"
                      f"{value['source_commit']}/sdkjs-plugins/content/{slug}/")
            url = artifact["url"]
            _require(isinstance(url, str) and url.startswith(prefix), "Unpinned plugin URL")
            suffix = url[len(prefix):]
            decoded = urllib.parse.unquote(suffix, errors="strict")
            _relative(decoded)
            _require(suffix in (urllib.parse.quote(decoded, safe="/"),
                                urllib.parse.quote(decoded, safe="/@")), "Unpinned plugin URL")
            if record["format"] == "files":
                _require(decoded == path, "Plugin URL does not identify the intended file")
            _require(_match(artifact["sha256"], r"[0-9a-f]{64}")
                     and type(artifact["size"]) is int and 0 <= artifact["size"] <= ARCHIVE_LIMIT)
        _require(len(set(paths)) == len(paths), "Duplicate plugin artifact")
        _paths(paths)
        if record["format"] == "zip":
            _require(paths == ["plugin.zip"])
        else:
            _require({a["path"]: a["sha256"] for a in artifacts} == tree
                     and sum(a["size"] for a in artifacts) <= TREE_LIMIT)
    return value


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def load_catalog(path=CATALOG):
    """Load reviewed public policy without probes or writes."""
    with open(path, "rb") as stream:
        data = stream.read(TREE_LIMIT + 1)
    _require(len(data) <= TREE_LIMIT)
    return _catalog(_json(data))


def make_lock(selection_str, catalog=None):
    catalog = _catalog(catalog) if catalog is not None else load_catalog()
    _require(isinstance(selection_str, str), "Invalid plugin selection")
    selection = selection_str.split(",") if selection_str else []
    _require(len(selection) == len(set(selection))
             and all(slug in catalog["plugins"] for slug in selection), "Invalid plugin selection")
    return {"schema": 1, "docs_version": catalog["docs_version"],
            "source_commit": catalog["source_commit"],
            "plugins": {slug: deepcopy(catalog["plugins"][slug]) for slug in selection}}


def validate_lock(lock, selection_str, catalog=None):
    _catalog(lock)
    expected = make_lock(selection_str, catalog)
    _require(lock == expected and list(lock["plugins"]) == list(expected["plugins"]),
             "Plugin lock differs from reviewed selection")


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _ancestors(path):
    _require(".." not in Path(path).parts, "Unsafe plugin directory")
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, ROOT_UID)
                 and (not info.st_mode & 0o022 or sticky), "Unsafe plugin directory")
    return path


def _exists(path):
    return path.exists() or path.is_symlink()


def _directory(path, mode, create=False):
    path = Path(path)
    _require(".." not in path.parts, "Unsafe plugin directory")
    if create and not _exists(path):
        if not _exists(path.parent):
            _directory(path.parent, mode, create=True)
        _ancestors(path.parent)
        path.mkdir(mode=mode)
        path.chmod(mode)
        _sync(path.parent)
    _ancestors(path)
    info = path.lstat()
    _require(info.st_uid == ROOT_UID and stat.S_IMODE(info.st_mode) == mode,
             "Incorrect plugin directory ownership or mode")
    return path


def _read(path, mode=0o600, limit=TREE_LIMIT):
    _ancestors(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == ROOT_UID
                 and stat.S_IMODE(info.st_mode) == mode and info.st_size <= limit,
                 "Unsafe plugin file")
        data = stream.read(limit + 1)
    _require(len(data) <= limit, "Plugin file too large")
    return data


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish(source, destination):
    # Both parents are root controlled; mutation callers serialize globally.
    _ancestors(source.parent)
    _ancestors(destination.parent)
    _require(not _exists(destination), "Refusing to replace existing plugin path")
    os.rename(source, destination)
    _sync(destination.parent)
    if source.parent != destination.parent:
        _sync(source.parent)


def _write(path, chunks, mode=0o600, temporary_dir=None):
    _ancestors(path.parent)
    temporary_dir = path.parent if temporary_dir is None else temporary_dir
    _ancestors(temporary_dir)
    temporary = temporary_dir / (".cloud-partial-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        for chunk in chunks:
            stream.write(chunk)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())
    _publish(temporary, path)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Plugin download redirect refused")


def default_fetch(url):
    return urllib.request.build_opener(_NoRedirect()).open(url, timeout=30)


def _download(artifact, fetch):
    try:
        with closing(fetch(artifact["url"])) as stream:
            _require(not hasattr(stream, "geturl") or stream.geturl() == artifact["url"])
            digest, size = hashlib.sha256(), 0
            while True:
                chunk = stream.read(min(CHUNK, artifact["size"] - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                _require(size <= artifact["size"])
                digest.update(chunk)
                yield chunk
            _require(size == artifact["size"] and digest.hexdigest() == artifact["sha256"])
    except Exception:
        raise ValueError("Plugin download failed integrity or transport checks") from None


def _artifact(path, artifact):
    data = _read(path, limit=ARCHIVE_LIMIT)
    _require(len(data) == artifact["size"] and _hash(data) == artifact["sha256"],
             "Plugin cache integrity mismatch")
    return data


def prepare(lock, cache, fetch=default_fetch):
    _catalog(lock)
    if not lock["plugins"]:
        return
    _require(os.geteuid() == ROOT_UID, "Plugin preparation requires root")
    cache = _directory(cache, 0o700, create=True)
    for slug, record in lock["plugins"].items():
        for artifact in record["artifacts"]:
            path = cache / slug / artifact["path"]
            _directory(path.parent, 0o700, create=True)
            for parent in path.relative_to(cache).parents:
                _directory(cache / parent, 0o700)
            if _exists(path):
                _artifact(path, artifact)
            else:
                _write(path, _download(artifact, fetch))


def check_cache(lock, cache):
    _catalog(lock)
    if not lock["plugins"]:
        return
    cache = _directory(cache, 0o700)
    for slug, record in lock["plugins"].items():
        for artifact in record["artifacts"]:
            path = cache / slug / artifact["path"]
            for parent in path.relative_to(cache).parents:
                _directory(cache / parent, 0o700)
            _artifact(path, artifact)


def check_payloads(lock, cache, docs_version="9.4.0"):
    """Read-only pre-provisioning validation of archive trees and Docs manifests."""
    check_cache(lock, cache)
    for slug, record in lock["plugins"].items():
        _payload(record, Path(cache) / slug, docs_version)


def _manifest(data, record, docs_version="9.4.0"):
    manifest = _json(data)
    _require(isinstance(manifest, dict) and manifest.get("guid") == record["guid"]
             and manifest.get("version") == record["version"], "Plugin manifest identity mismatch")
    def version(value):
        _require(_match(value, r"[0-9]+(?:\.[0-9]+){0,2}"), "Invalid plugin Docs requirement")
        return tuple(int(p) for p in value.split(".")) + (0,) * (2 - value.count("."))
    _require(_match(docs_version, r"9\.4\.(?:0|[1-9][0-9]*)"),
             "Plugin Docs version is outside the reviewed 9.4 family")
    selected = version(docs_version)
    _require(version(manifest.get("minVersion", "0")) <= selected
             and ("maxVersion" not in manifest or selected <= version(manifest["maxVersion"])),
             "Plugin does not support selected Docs version")
    def passive(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ("isSystem", "isSystemPlugin", "autoStart", "autostart"):
                    _require(child is False, "Automatic system plugins are not permitted")
                passive(child)
        elif isinstance(value, list):
            for child in value:
                passive(child)
    passive(manifest)


def _payload(record, cache, docs_version="9.4.0"):
    if record["format"] == "files":
        files = {a["path"]: _artifact(cache / a["path"], a) for a in record["artifacts"]}
    else:
        data = _artifact(cache / "plugin.zip", record["artifacts"][0])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            _require(len(entries) <= ENTRY_LIMIT
                     and sum(i.file_size for i in entries) <= TREE_LIMIT, "Plugin archive exceeds limits")
            names = []
            for entry in entries:
                name = entry.filename[:-1] if entry.is_dir() else entry.filename
                _relative(name)
                _require(entry.orig_filename == entry.filename and not entry.flag_bits & 1
                         and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                         "Unsupported plugin archive entry")
                kind = stat.S_IFMT(entry.external_attr >> 16)
                _require(kind in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG),
                         "Non-regular plugin archive entry")
                _require(not entry.is_dir() or entry.file_size == 0)
                names.append(name)
            _require(len(names) == len(set(names)), "Duplicate plugin archive path")
            # Check case aliases without treating explicit directories as files.
            _paths([i.filename for i in entries if not i.is_dir()])
            _require(len({n.casefold() for n in names}) == len(names), "Plugin path collision")
            regular = [i for i in entries if not i.is_dir()]
            prefix = ""
            if "config.json" not in [i.filename for i in regular]:
                roots = {i.filename.split("/")[0] for i in regular}
                _require(len(roots) == 1, "Missing plugin root manifest")
                prefix = next(iter(roots)) + "/"
            files = {i.filename[len(prefix):]: archive.read(i) for i in regular}
            directories = {name[:index] for name in files for index, c in enumerate(name) if c == "/"}
            for entry in entries:
                if entry.is_dir():
                    name = entry.filename.rstrip("/")
                    _require(name == prefix.rstrip("/") or
                             (name.startswith(prefix) and name[len(prefix):] in directories),
                             "Unexpected plugin archive directory")
    _require(sum(map(len, files.values())) <= TREE_LIMIT
             and {path: _hash(data) for path, data in files.items()} == record["tree"],
             "Plugin payload differs from reviewed tree")
    _manifest(files["config.json"], record, docs_version)
    return files


def _tree(root, expected, partial=False, staged=False):
    mode = stat.S_IMODE(root.lstat().st_mode)
    _require(mode in ((0o700, 0o755) if staged else (0o755,)), "Unsafe plugin tree mode")
    _directory(root, mode)
    directories = {name[:index] for name in expected for index, c in enumerate(name) if c == "/"}
    found, total = set(), 0
    def walk(parent):
        nonlocal total
        for path in parent.iterdir():
            name = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                _require(name in directories, "Unexpected plugin directory")
                _directory(path, 0o755)
                walk(path)
            else:
                _require(name in expected, "Unexpected plugin file")
                data = _read(path, mode=0o644)
                total += len(data)
                _require(total <= TREE_LIMIT and _hash(data) == expected[name], "Plugin tree drift")
                found.add(name)
    walk(root)
    _require(partial or found == set(expected), "Incomplete plugin tree")


def _receipt(lock, slug):
    return {"schema": 1, "lock_sha256": _hash(_encoded(lock)), "slug": slug,
            "plugin": lock["plugins"][slug]}


def _locations(lock, slug, root, state):
    receipt = _receipt(lock, slug)
    stage = root / f".cloud-{slug}-{receipt['lock_sha256'][:16]}"
    return root / slug, stage, state / (slug + ".intent.json"), state / (slug + ".complete.json"), receipt


def _existing(lock, slug, root, state, complete=False, docs_version="9.4.0"):
    destination, stage, intent, done, expected = _locations(lock, slug, root, state)
    if _exists(intent):
        _require(_json(_read(intent)) == expected, "Plugin ownership intent mismatch")
    else:
        _require(not complete and not any(_exists(p) for p in (destination, stage, done)),
                 "Refusing unowned plugin path")
    if _exists(done):
        _require(_json(_read(done)) == expected and _exists(destination), "Plugin receipt mismatch")
    else:
        _require(not complete, "Plugin installation is not complete")
    _require(not (_exists(stage) and _exists(destination)), "Conflicting plugin staging state")
    if _exists(destination):
        _tree(destination, expected["plugin"]["tree"])
        _manifest(_read(destination / "config.json", mode=0o644), expected["plugin"], docs_version)
    if _exists(stage):
        _tree(stage, expected["plugin"]["tree"], partial=True, staged=True)


def install(lock, cache, plugin_root, receipt_dir, docs_version="9.4.0"):
    _catalog(lock)
    if not lock["plugins"]:
        return
    _require(os.geteuid() == ROOT_UID, "Plugin installation requires root")
    check_cache(lock, cache)
    cache, root, state = Path(cache), Path(plugin_root), Path(receipt_dir)
    _directory(root, 0o755)
    if _exists(state):
        _directory(state, 0o700)
    for slug, record in lock["plugins"].items():
        _payload(record, cache / slug, docs_version)
        _existing(lock, slug, root, state, docs_version=docs_version)
    _directory(state, 0o700, create=True)
    for slug, record in lock["plugins"].items():
        destination, stage, intent, done, receipt = _locations(lock, slug, root, state)
        if _exists(done):
            continue
        if not _exists(intent):
            _write(intent, [_encoded(receipt)])
        if not _exists(destination):
            if not _exists(stage):
                _directory(stage, 0o700, create=True)
                _sync(root)
            for name, data in _payload(record, cache / slug, docs_version).items():
                path = stage / name
                if not _exists(path):
                    if path.parent != stage:
                        _directory(path.parent, 0o755, create=True)
                    _write(path, [data], mode=0o644, temporary_dir=root)
            _tree(stage, record["tree"], staged=True)
            stage.chmod(0o755)
            _sync(stage)
            _publish(stage, destination)
        _write(done, [_encoded(receipt)])


def verify(lock, plugin_root, receipt_dir, docs_version="9.4.0"):
    """Read-only, selected-plugin verification; no cache or network needed."""
    _catalog(lock)
    if not lock["plugins"]:
        return
    root, state = _directory(plugin_root, 0o755), _directory(receipt_dir, 0o700)
    for slug in lock["plugins"]:
        _existing(lock, slug, root, state, complete=True, docs_version=docs_version)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "verify"))
    for option in ("lock", "root", "state"):
        parser.add_argument("--" + option, required=True, type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--docs-version", default="9.4.0")
    args = parser.parse_args(argv)
    try:
        lock = _catalog(_json(_read(args.lock)))
        validate_lock(lock, ",".join(lock["plugins"]))
        if args.command == "install":
            _require(args.cache is not None, "Installation requires a plugin cache")
            install(lock, args.cache, args.root, args.state, args.docs_version)
        else:
            verify(lock, args.root, args.state, args.docs_version)
    except Exception:
        # This worker crosses a jail boundary: even decoder/transport exceptions
        # must not expose URLs, paths or tracebacks in the operator console.
        parser.exit(1, "Plugin operation failed validation or I/O checks\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
