#!/usr/bin/env python3
"""Reproduce the public ONLYOFFICE plugin catalog (maintainer-only, networked).

Pinned upstream: 2026-10-13; native package target: onlyoffice-documentserver
9.4.0_4. This reviews immutable bytes, not browser compatibility. No plugin code
is executed. Output and private download cache default to the ignored review
directory; explicitly review the generated JSON before updating the catalog.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import urllib.parse
import urllib.request
import zipfile


COMMIT = "f3263c055c25875874004463b46c2e6a7000a9fd"
DOCS_VERSION = "9.4.0"
SLUGS = "highlightcode mendeley ocr photoeditor speech thesaurus translator youtube zotero wordpress".split()
RAW = f"https://raw.githubusercontent.com/ONLYOFFICE/onlyoffice.github.io/{COMMIT}/sdkjs-plugins/content"
API = "https://api.github.com/repos/ONLYOFFICE/onlyoffice.github.io/git/trees/"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(f"redirect refused: {req.full_url}")


def download(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc not in {"raw.githubusercontent.com", "api.github.com"}:
        raise ValueError("unexpected download origin")
    request = urllib.request.Request(url, headers={"User-Agent": "cloud-installer-plugin-review"})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=90) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        raise ValueError("download exceeds review limit")
    return data


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)


def safe_path(value):
    path = PurePosixPath(value)
    if not value or "\\" in value or path.is_absolute() or any(p in {"", ".", ".."} for p in value.split("/")):
        raise ValueError(f"unsafe path: {value!r}")
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or ":" in value:
        raise ValueError(f"unsafe path: {value!r}")
    return value


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_url(slug, path):
    # Match the runtime validator's canonical URL spelling exactly.
    return RAW + "/" + slug + "/" + urllib.parse.quote(path, safe="/")


def git_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def check_tree_paths(files):
    spellings = {}
    for name in files:
        safe_path(name)
        parts = name.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            folded = prefix.casefold()
            if folded in spellings and spellings[folded] != prefix:
                raise ValueError(f"case-colliding path component: {prefix}")
            spellings[folded] = prefix
            if length < len(parts) and prefix in files:
                raise ValueError(f"file/directory collision: {prefix}")


def git_tree(cache, tree, recursive=False, git_dir=None):
    if git_dir is not None:
        command = ["git", "--git-dir=" + str(git_dir), "ls-tree", "-z"]
        if recursive:
            command.append("-r")
        output = subprocess.check_output(command + [tree], env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})
        result = []
        for entry in output.split(b"\0"):
            if entry:
                metadata, path = entry.decode("utf-8").split("\t", 1)
                mode, kind, digest = metadata.split()
                result.append({"path": path, "mode": mode, "type": kind, "sha": digest})
        return result
    path = cache / "metadata" / f"{tree}{'-recursive' if recursive else ''}.json"
    if not path.exists():
        save(path, download(API + tree + ("?recursive=1" if recursive else "")))
    value = json.loads(path.read_bytes())
    if value.get("truncated"):
        raise ValueError("truncated Git tree")
    return value["tree"]


def inspect_zip(data):
    files = {}
    seen = set()
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            name = safe_path(member.filename.rstrip("/") if member.is_dir() else member.filename)
            if name.casefold() in seen:
                raise ValueError(f"duplicate/case-colliding ZIP member: {name}")
            seen.add(name.casefold())
            kind = stat.S_IFMT(member.external_attr >> 16)
            if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError(f"nonregular ZIP member: {name}")
            if member.flag_bits & 1:
                raise ValueError("encrypted ZIP")
            total += member.file_size
            if total > 128 * 1024 * 1024 or len(seen) > 10000:
                raise ValueError("ZIP exceeds review limits")
            if not member.is_dir():
                files[name] = archive.read(member)
    check_tree_paths(files)
    return files


def runtime_path(path):
    # Source-only build/dev inputs. Keep committed bundles, documentation,
    # resources, translations, vendor code and all license notices.
    parts = PurePosixPath(path).parts
    if parts[0] in {"deploy", "src", ".dev", "node_modules", ".github"}:
        return False
    if len(parts) == 1 and (path.startswith("package") and path.endswith(".json") or path.startswith(("vite.config.", "postcss.config.")) or path in {".gitignore", ".prettierrc", ".prettierignore", "tsconfig.json"}):
        return False
    return True


def version_tuple(value):
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        raise ValueError(f"unsupported version: {value}")
    return tuple(int(p) for p in value.split(".")) + (0,) * (4 - len(value.split(".")))


def check_local_html_references(files):
    for path, data in files.items():
        if not path.endswith(".html"):
            continue
        text = data.decode("utf-8-sig").replace("\\/", "/")
        for target in re.findall(r'''(?:src|href)\s*=\s*["']([^"']+)''', text):
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path or parsed.path.startswith("/"):
                continue
            local = str(PurePosixPath(path).parent / urllib.parse.unquote(parsed.path))
            if local not in files:
                raise ValueError(f"missing literal HTML resource: {path}: {target}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, default=Path("build/plugin-review"))
    parser.add_argument("--git-dir", type=Path, help="optional existing shallow blob-filtered bare repository for tree metadata, avoiding API limits")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.workdir
    tree = COMMIT
    for part in ("sdkjs-plugins", "content"):
        tree = next(item["sha"] for item in git_tree(root, tree, git_dir=args.git_dir) if item["path"] == part and item["type"] == "tree")
    content = {item["path"]: item for item in git_tree(root, tree, git_dir=args.git_dir)}
    catalog = {"schema": 1, "docs_version": DOCS_VERSION, "source_commit": COMMIT, "plugins": {}}
    report = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        trees = dict(zip(SLUGS, pool.map(lambda slug: git_tree(root, content[slug]["sha"], True, args.git_dir), SLUGS)))
        for slug in SLUGS:
            blobs = {}
            seen = set()
            for item in trees[slug]:
                safe_path(item["path"])
                if item["type"] == "tree":
                    continue
                if item["mode"] != "100644" and item["mode"] != "100755":
                    raise ValueError(f"nonregular source: {slug}/{item['path']}")
                if item["path"].casefold() in seen:
                    raise ValueError("source case collision")
                seen.add(item["path"].casefold())
                blobs[item["path"]] = item
            check_tree_paths(blobs)

            def fetch_source(path):
                dest = root / "source" / slug / path
                if not dest.exists():
                    save(dest, download(source_url(slug, path)))
                data = dest.read_bytes()
                if ("size" in blobs[path] and len(data) != blobs[path]["size"]) or git_sha(data) != blobs[path]["sha"]:
                    raise ValueError(f"Git blob mismatch: {slug}/{path}")
                return path, data

            config_bytes = fetch_source("config.json")[1]
            config = json.loads(config_bytes)
            minimum = config.get("minVersion")
            if minimum is not None and version_tuple(minimum) > version_tuple(DOCS_VERSION):
                raise ValueError(f"requires newer Docs: {slug}")
            paths = sorted(path for path in blobs if runtime_path(path))
            archive_path = f"deploy/{slug}.plugin"
            archive_data = None
            archive_files = None
            review = {"source_version": config["version"], "minVersion": minimum,
                      "compatibility": "minimum satisfied; browser pending" if minimum else "minimum unspecified; browser pending"}
            if archive_path in blobs:
                archive_data = fetch_source(archive_path)[1]
                archive_files = inspect_zip(archive_data)
                packaged = json.loads(archive_files["config.json"])
                changed = sorted(path for path, data in archive_files.items() if path not in blobs or git_sha(data) != blobs[path]["sha"])
                missing = sorted(set(paths) - archive_files.keys())
                review.update({"archive_version": packaged.get("version"), "archive_guid": packaged.get("guid"),
                               "archive_minVersion": packaged.get("minVersion"), "archive_sha256": sha256(archive_data),
                               "archive_bytes": len(archive_data), "guid_matches": packaged.get("guid") == config["guid"],
                               "archive_changed_files": changed, "archive_missing_files": missing})
                # Exact source fidelity, including license/documentation completeness.
                if changed or missing or packaged.get("guid") != config["guid"]:
                    archive_data = None
            else:
                review["archive"] = "absent"
            artifacts = []
            if archive_data is not None:
                mode = "zip"
                files = archive_files
                save(root / "cache" / slug / "plugin.zip", archive_data)
                artifacts.append({"path": "plugin.zip", "url": source_url(slug, archive_path),
                                  "sha256": sha256(archive_data), "size": len(archive_data)})
            else:
                mode = "files"
                files = dict(pool.map(fetch_source, paths))
                for path, data in files.items():
                    save(root / "cache" / slug / path, data)
                    artifacts.append({"path": path, "url": source_url(slug, path),
                                      "sha256": sha256(data), "size": len(data)})
            check_local_html_references(files)
            if slug == "wordpress":
                endpoints = ("onlyoffice-proxy.herokuapp.com", "plugins-services.onlyoffice.com/proxy")
                review["proxy_endpoints"] = {
                    label: [endpoint for endpoint in endpoints if any(endpoint.encode() in data for data in payload.values())]
                    for label, payload in (("source", files), ("archive", archive_files or {}))
                }
            catalog["plugins"][slug] = {"name": config["name"], "guid": config["guid"], "version": config["version"],
                                        "format": mode, "artifacts": artifacts,
                                        "tree": {path: sha256(data) for path, data in sorted(files.items())}}
            review.update({"format": mode, "files": len(files), "bytes": sum(a["size"] for a in artifacts)})
            report[slug] = review
            print(f"{slug}: {config['version']} {mode}, {len(files)} files, {review['bytes']} bytes; minimum {minimum}", flush=True)
    save(root / "onlyoffice.json", (json.dumps(catalog, indent=2, ensure_ascii=False) + "\n").encode())
    save(root / "review.json", (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode())


if __name__ == "__main__":
    main()
