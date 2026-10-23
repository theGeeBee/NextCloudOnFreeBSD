#!/usr/bin/env python3
"""Build a reproducible, allowlisted release payload using only Python stdlib."""

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import shlex
import tarfile
from urllib.parse import unquote, urlsplit


ROOT_FILES = ("install.sh", "LICENSE", "pyproject.toml", "README.md")
# Explicit selection keeps release contents stable as documentation grows.
PUBLIC_DOCS = (
    "admin-checks.md", "backup-restore.md", "bootstrap.md", "configuration.md", "distribution.md", "firewall-transactions.md",
    "fonts.md", "freebsd-15.1.md", "freebsd-utilities.md", "fresh-install-profiles.md", "jails.md", "lifecycle-state.md",
    "maintenance-recovery.md", "onlyoffice-plugins.md", "onlyoffice.md", "operations.md",
    "reverse-proxy.md", "security-assessment.md", "ssh.md", "troubleshooting.md",
    "upgrade.md", "versions.md", "release.md", "third-party-notices.md",
    "nextcloud-update-recipe.md", "testing-boundaries.md", "verification.md",
)

# First-stage transport only. The authenticated payload owns policy checks and
# pkg/Python consent. No downloaded shell script, alternate installer or Python
# interpreter is needed before this has retained/extracted the trusted artifact.
RELEASE_COMMAND = r'''set +x
set +v
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
unset SSL_NO_VERIFY_PEER SSL_NO_VERIFY_HOSTNAME SSL_ALLOW_SSL3 TAR_OPTIONS TAR_READER_OPTIONS TAR_WRITER_OPTIONS
fail() { printf "Error: %s\n" "$*" >&2; exit 1; }
trap "exit 129" HUP
trap "exit 130" INT
trap "exit 143" TERM
[ "$(id -u)" = 0 ] || fail "Run as root on the destination FreeBSD host"
[ "$(uname -s)" = FreeBSD ] || fail "FreeBSD is required"
[ "$(sysctl -n security.jail.jailed)" = 0 ] || fail "Run outside a jail"
[ -t 0 ] && [ -t 1 ] || fail "An interactive terminal is required"
for path in /var/db/cloud-installer/lifecycle /var/db/cloud-installer/maintenance/pending.json; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || fail "Use the retained manager for lifecycle/recovery state"
done
check_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] || fail "Unsafe directory: $1"
    metadata=$(stat -f %u:%Lp "$1") || fail "Cannot inspect directory: $1"
    case "$metadata" in 0:*) ;; *) fail "Directory must be root-owned: $1" ;; esac
    mode=${metadata#0:}
    case "$mode" in ""|*[!0-7]*) fail "Invalid directory mode" ;; esac
    [ "$((0$mode & 022))" = 0 ] || fail "Directory is group/other writable: $1"
    [ "$2" != private ] || [ "$mode" = 700 ] || fail "Directory must be mode 0700: $1"
}
umask 077
for path in / /var /var/db; do check_dir "$path" ancestor; done
for path in /var/db/cloud-installer /var/db/cloud-installer/downloads; do
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then mkdir -m 700 "$path" || fail "Cannot create private cache"; fi
    check_dir "$path" private
done
stage=$(mktemp -d "/var/db/cloud-installer/downloads/$2.XXXXXXXX") || fail "Cannot create release directory"
check_dir "$stage" private
archive=$stage/release.tar.gz
printf "Retaining release at: %s\n" "$stage" >&2
(ulimit -f 131072 || exit 1; exec fetch -T 60 -o "$archive" "$1") || fail "Download failed; retained directory: $stage"
actual=$(sha256 -q "$archive") || fail "Cannot hash downloaded archive"
[ "$actual" = "$2" ] || fail "SHA256 mismatch; nothing extracted or executed"
tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$stage" || fail "Extraction failed; retained directory: $stage"
payload=$stage/cloud-installer
check_dir "$payload" private
for path in install.sh installer/main.py resources/versions.json; do
    [ -f "$payload/$path" ] && [ ! -L "$payload/$path" ] || fail "Incomplete release payload"
done
printf "Verified release ready: %s\n" "$payload" >&2
exec /bin/sh "$payload/install.sh" install'''


def validate_release_url(value):
    if not isinstance(value, str) or not value.isascii() or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Use a pinned HTTPS release archive URL without whitespace or controls")
    try:
        url = urlsplit(value)
        # Accessing port also rejects malformed bracket/port syntax.
        port = url.port
    except ValueError:
        raise ValueError("Invalid HTTPS release URL") from None
    path = unquote(url.path).lower()
    if (url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None
            or url.query or url.fragment or not path.endswith(".tar.gz")
            or (port is not None and not 1 <= port <= 65535)
            or re.search(r"(?:^|[/_.-])(?:latest|main|master|head|trunk)(?:$|[/_.-])", path)
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or "/refs/heads/" in path or any(part in (".", "..") for part in path.split("/"))):
        raise ValueError("Use a versioned HTTPS release archive URL, not credentials/query/fragment or a mutable branch/latest URL")
    return value


def install_command(url, digest):
    validate_release_url(url)
    if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
        raise ValueError("SHA256 must contain exactly 64 hexadecimal digits")
    return "/bin/sh -c " + shlex.quote(RELEASE_COMMAND) + " cloud-installer-release " + shlex.quote(url) + " " + shlex.quote(digest.lower())
NEXTCLOUD_TEMPLATES = (
    "certbot-cron", "certbot-deploy", "challenge.conf", "cloud_php_dirs", "httpd.conf",
    "https.conf", "external.conf", "my.cnf", "mysql-flush-logs", "newsyslog.conf", "packages.txt",
    "php-fpm.conf", "php.ini", "redis.conf", "www-crontab", "www.conf",
    "www-none.conf", "https-none.conf", "external-none.conf",
)
ONLYOFFICE_TEMPLATES = (
    "nginx.conf", "proxy.conf", "supervisord.conf",
)


def payload_files(root):
    """Exact resource names prevent runtime.json, keys or local config leaking."""
    paths = {root / name for name in ROOT_FILES}
    for pattern in ("installer/*.py", "resources/jails/*.sh", "resources/jails/*.php"):
        paths.update(root.glob(pattern))
    paths.update(root / "docs" / name for name in PUBLIC_DOCS)
    paths.update(root / "resources/templates/nextcloud" / name for name in NEXTCLOUD_TEMPLATES)
    paths.update(root / "resources/templates/onlyoffice" / name for name in ONLYOFFICE_TEMPLATES)
    paths.update(root / name for name in ("resources/versions.json", "resources/plugins/onlyoffice.json", "resources/packages/fonts.txt", "examples/config.json",
                                        "resources/vm/bootstrap.sh",
                                        "examples/external-proxy.json", "examples/nextcloud-only.json",
                                        "examples/eurooffice.json", "examples/collabora.json", "tools/build-release.py"))
    # All candidates are bounded by the allowlist, including any missing paths.
    files = []
    for path in sorted(paths):
        relative = path.relative_to(root)
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root):
            raise ValueError(f"Release payload must not contain symlinks: {relative}")
        if path.exists():
            if not path.is_file():
                raise ValueError(f"Release payload must contain regular files: {relative}")
            files.append(path)
    required = {"install.sh", "LICENSE", "pyproject.toml", "installer/__init__.py", "installer/main.py",
                  "installer/dashboard.py", "installer/updates.py",
                  "installer/upgrade.py", "installer/upgrade_native.py", "installer/upgrade_packages.py",
                  "installer/upgrade_nextcloud.py", "installer/upgrade_backup.py",
                  "installer/security_assessment.py", "installer/security_reports.py",
                  "installer/package_security.py",
                  "installer/runtime_inventory.py",
                  "installer/maintenance_state.py", "installer/maintenance_generations.py",
                  "installer/maintenance_preflight.py", "installer/maintenance_fence.py",
                   "installer/maintenance_native.py",
                   "installer/maintenance_pkg_layout.py",
                  "installer/maintenance_inspection.py",
                  "installer/nextcloud_update.py", "installer/maintenance_update.py",
                  "installer/maintenance_admission.py", "installer/bounded_process.py",
                  "installer/recovery_export.py",
                  "installer/maintenance_candidate.py",
                  "installer/maintenance_execution.py", "installer/maintenance_publication.py",
                  "installer/maintenance_validation.py", "installer/maintenance_opening.py",
                  "installer/maintenance_cancellation.py",
                 "installer/generations.py", "installer/enrollment.py", "installer/maintenance.py",
                 "installer/enrollment_start.py",
                 "installer/maintenance_journal.py", "installer/maintenance_operations.py",
                 "installer/maintenance_staging.py", "installer/recovery_sets.py",
                 "resources/jails/nextcloud.sh", "resources/jails/onlyoffice.sh", "resources/jails/nextcloud-bootstrap.php",
                  "resources/jails/nextcloud-cron-fence.php",
                  "resources/vm/bootstrap.sh",
                  "resources/jails/maintenance.php", "resources/jails/runtime-inventory.php", "resources/jails/ssh.sh", "resources/packages/fonts.txt",
                  "resources/versions.json", "resources/plugins/onlyoffice.json", "installer/plugins.py", "resources/jails/versions.sh", "installer/versions.py",
                 "installer/discovery.py", "installer/compatibility.py", "installer/resolution.py", "installer/version_runtime.py"}
    required.update("resources/templates/nextcloud/" + name for name in NEXTCLOUD_TEMPLATES)
    required.update("resources/templates/onlyoffice/" + name for name in ONLYOFFICE_TEMPLATES)
    if not required.issubset({path.relative_to(root).as_posix() for path in files}):
        raise ValueError("Required release entrypoint, metadata, installer or jail resources are missing")
    return files


def build_release(root, output):
    root, output = Path(root).resolve(), Path(output)
    if output.suffixes[-2:] != [".tar", ".gz"]:
        raise ValueError("Choose an output filename ending in .tar.gz")
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists; choose a new archive path")
    files = payload_files(root)
    directories = {"cloud-installer"}
    for path in files:
        relative = Path("cloud-installer") / path.relative_to(root)
        directories.update(parent.as_posix() for parent in relative.parents if parent != Path("."))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as raw:
        try:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for name in sorted(directories):
                        info = tarfile.TarInfo(name)
                        info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 0
                        archive.addfile(info)
                    for path in files:
                        data = path.read_bytes()
                        info = tarfile.TarInfo("cloud-installer/" + path.relative_to(root).as_posix())
                        info.size, info.mtime = len(data), 0
                        info.mode = 0o755 if data.startswith(b"#!") else 0o644
                        archive.addfile(info, io.BytesIO(data))
        except BaseException:
            output.unlink()
            raise
    with output.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="Explicit archive path, for example dist/cloud-installer.tar.gz (must not exist)")
    parser.add_argument("--url", help="Publisher-reviewed pinned HTTPS URL for these exact bytes; print the base-only installation command")
    args = parser.parse_args(argv)
    try:
        if args.url is not None:
            validate_release_url(args.url)
        digest = build_release(Path(__file__).resolve().parents[1], args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Release build failed: {error}\n")
    print(f"{digest}  {args.output}")
    if args.url is not None:
        print("\nPublish the exact archive and this command through a trusted channel; URL availability is not verified:\n")
        print(install_command(args.url, digest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
