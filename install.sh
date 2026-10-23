#!/bin/sh

# The sole operator entrypoint, from a checkout or a verified release archive.
set +x
set +v
set -eu

fail() {
	printf 'Error: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<'USAGE'
Usage: sh install.sh [--plain] [COMMAND]
  (no command)                 Open the interactive instance menu
  install | configure          Create an instance, or save its configuration
  install --config FILE [--yes] [--accept-licenses] [--accept-acme-terms]
  configure --config FILE      Use an authoritative schema-2 JSON recipe, no wizard
                                FILE is relative to caller's cwd; paths inside must be absolute
                                --yes approves pkg/Python bootstrap and APPLY only;
                                fresh credentials are generated; terminal and timed KEEP remain required
                                --accept-licenses accepts required Microsoft webfonts EULA:
                                https://corefonts.sourceforge.net/eula.htm
                                ACME terms require separate consent:
                                https://letsencrypt.org/repository/
  resume INSTANCE              Review and resume a retained installation
  list                         List registered instances
  status INSTANCE              Show retained instance state
  check-updates [NAME|--all] [--refresh] [--save-report] [--json]
                                Inspect update availability; never apply
  check-security [NAME|--all] [--refresh] [--save-report] [--json]
                                Independent core/package advisories; EOL coverage unknown
  upgrade INSTANCE [--nextcloud VERSION] [--plan | --verify | --restore SNAPSHOT_REPORT] [--skip-packages]
                                Optional native upgrade; initial NC35.0.1 -> 35.0.2
                                --plan may refresh signed pkg metadata; --verify is live/read-only
  maintenance register NAME     Explicitly enroll an eligible retained instance
  maintenance plan --instance NAME (--recovery-only | --target PROFILE) [--save] [--json]
                                Assess recovery preparation; target migration blocked
  maintenance stage PLAN-ID --artifacts DIR
  maintenance continue OP-ID --artifacts DIR
                                Inputs: DIR/<sha256>.pkg; hashes listed by maintenance plan
  maintenance prepare-target OP-ID --artifacts DIR
                                Authenticate target and inspect runtime before any boot fence
                                Inputs: local release/signature/key files and connector.archive
  maintenance cancel OP-ID      Cancel inert artifact staging after confirmation
  maintenance status [OP-ID] [--json]
                                Inspect lifecycle state or a retained operation
  maintenance recover          Continue the same interrupted enrollment
  maintenance recover OP-ID --assess [--json]
                                Read-only recovery assessment
  maintenance apply OP-ID       Always blocked; no native execution recipe
  verify INSTANCE              Check a completed instance
  remove INSTANCE [--purge-data]
  backup INSTANCE [--output PATH]
  restore INSTANCE BACKUP
  add-user INSTANCE            Add a Nextcloud user interactively
  recover-install INSTANCE     Reset interrupted, unpublished initialization
  recover-network              Recover an expired/interrupted PF transition
  plan FILE                    Validate and print an offline JSON plan
  resolve FILE [--metadata FILE] [--installed PLAN]
                               Inspect versions/upgrade feasibility; never apply
  --plan FILE | --configure-only | --verify INSTANCE   Compatibility aliases
  --help                       Show this help without host changes

Standalone entrypoint (no clone required):
  sh install.sh --archive HTTPS_URL_OR_LOCAL_TAR_GZ --sha256 TRUSTED_DIGEST COMMAND [ARGS]
Archive commands: install, configure, resume, verify, backup, remove, restore,
add-user, recover-install, recover-network (including compatibility aliases).
Menu, list, status, check-updates, check-security, maintenance, upgrade, plan and resolve require an unpacked payload.
Use a pinned cloud-installer/ release archive and its trusted SHA256. No release
is selected or downloaded automatically. See docs/distribution.md.
USAGE
}

require_host() {
	[ "$(id -u)" -eq 0 ] || fail 'Run as root on the target FreeBSD host.'
    [ "$(uname -s)" = FreeBSD ] || fail 'This installer requires a policy-supported FreeBSD host.'
	userland=$(freebsd-version -u)
	printf '%s\n' "$userland" | grep -Eq '^[0-9]+\.[0-9]+-RELEASE(-p[0-9]+)?$' \
		|| fail 'A stable FreeBSD RELEASE userland is required; update the OS separately.'
	[ "$(sysctl -n security.jail.jailed)" = 0 ] || fail 'Run on the host, outside any jail.'
	architecture=$(uname -m)
	case "$architecture" in ''|*[!A-Za-z0-9_]*) fail 'Invalid FreeBSD architecture.' ;; esac
	# FreeBSD base flua checks the same policy before optional pkg/Python bootstrap.
	# A standalone entrypoint cannot know the supplied artifact's support matrix
	# until it is authenticated and unpacked. Require existing Python in that case
	# rather than bootstrap packages on an environment with unknown compatibility.
	if [ -f "${script_dir:-.}/resources/versions.json" ]; then
		if ! /usr/libexec/flua - "${script_dir:-.}/resources/versions.json" "${userland%%-p*}" "$architecture" <<'LUA_HOST'
local p = require('ucl').parser()
assert(p:parse_file(arg[1]))
local policy = p:get_object()
for _, target in ipairs(policy.targets) do
    if target.release == arg[2] and target.architecture == arg[3] then os.exit(0) end
end
os.exit(1)
LUA_HOST
		then fail 'This FreeBSD release/architecture has no reviewed compatibility policy.'; fi
	else
		require_python
	fi
}

require_terminal() {
	[ -t 0 ] && [ -t 1 ] || fail 'An interactive terminal is required for bootstrap, configuration and apply.'
}

confirm() {
	require_terminal
	printf '%s [y/N]: ' "$1" >&2
	IFS= read -r reply || return 1
	case "$reply" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

require_python() {
	if ! command -v python3 >/dev/null 2>&1; then
		if [ "${mode:-}" = menu ]; then
			fail 'Python 3.11+ is required for the menu. Use explicit install or configure to review and consent to dependency bootstrap.'
		fi
		fail 'Python 3.11+ is required; this command does not install dependencies.'
	fi
	python3 -I -B -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
		|| fail 'Python 3.11+ is required; update an older Python separately.'
}

bootstrap_python() {
	# -N queries the base pkg shim without triggering automatic bootstrap.
	if ! /usr/sbin/pkg -N >/dev/null 2>&1; then
		bootstrap_consent 'Bootstrap missing pkg from FreeBSD-ports? Command: /usr/sbin/pkg bootstrap -y -r FreeBSD-ports' || fail 'pkg bootstrap declined.'
		/usr/sbin/pkg bootstrap -y -r FreeBSD-ports
	fi
	if ! command -v python3 >/dev/null 2>&1; then
		bootstrap_consent 'Install missing python3 and its dependencies from FreeBSD-ports? Command: pkg install -y -r FreeBSD-ports python3' \
			|| fail 'Python installation declined.'
		pkg install -y -r FreeBSD-ports python3
	fi
	require_python
}

bootstrap_consent() {
	if [ "${assume_yes:-0}" -eq 1 ]; then
		require_terminal
		printf '%s (--yes approved)\n' "$1" >&2
	else
		confirm "$1"
	fi
}

bootstrap_archive() {
	# This self-contained, stdlib verifier must work before installer/ exists.
	# stdout contains only the verified release directory; diagnostics use stderr.
	python3 -I -B - "$archive_source" "$archive_sha256" <<'PY_ARCHIVE'
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit

CACHE = Path("/var/db/cloud-installer/downloads")
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_ENTRIES = 4096
DIRECTORIES = {"installer", "resources", "docs", "examples", "tools"}
ROOT_FILES = {"install.sh", "LICENSE", "pyproject.toml", "README.md"}


def copy_bounded(source, destination, limit):
    total = 0
    while True:
        block = source.read(min(1024 * 1024, limit - total + 1))
        if not block:
            return total
        total += len(block)
        if total > limit:
            raise ValueError("Release archive exceeds the size limit")
        destination.write(block)


def validate_source(source):
    if any(ord(char) < 32 or ord(char) == 127 for char in source):
        raise ValueError("Archive source contains a control character")
    url = urlsplit(source)
    if url.scheme or url.netloc:
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
            raise ValueError("Use an HTTPS archive URL without credentials or a local file path")
        return True
    if not source:
        raise ValueError("An archive source is required")
    return False


def private_cache(cache):
    # Reject symlinks and writable ancestors before creating root-owned state.
    for parent in reversed(cache.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Archive cache ancestors must be root-owned directories without group/other writes")
    for directory in (cache.parent, cache):
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Archive cache directories must be root-owned, private (0700), and not symlinks")


def acquire(source, target):
    if validate_source(source):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("SSL_NO_VERIFY_PEER", "SSL_NO_VERIFY_HOSTNAME", "SSL_ALLOW_SSL3")}
        # fetch is in FreeBSD base; certificates are verified normally. Bound
        # the stream before writing it, even when Content-Length is missing.
        with subprocess.Popen(["/usr/bin/fetch", "-T", "60", "-o", "-", source],
                              stdout=subprocess.PIPE, env=environment) as process:
            try:
                with target.open("xb") as output:
                    copy_bounded(process.stdout, output, MAX_ARCHIVE)
                if process.wait(timeout=65):
                    raise ValueError("Archive download failed")
            except BaseException:
                process.kill()
                process.wait()
                raise
    else:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as input_file:
            if not stat.S_ISREG(os.fstat(input_file.fileno()).st_mode):
                raise ValueError("Local archive must be a regular file")
            with target.open("xb") as output:
                copy_bounded(input_file, output, MAX_ARCHIVE)


def checked_members(archive):
    members, names, expanded = [], {}, 0
    for member in archive:
        if len(members) >= MAX_ENTRIES:
            raise ValueError("Release archive contains too many entries")
        name = member.name.rstrip("/") if member.isdir() else member.name
        parts = name.split("/")
        if (len(name) > 1024 or not parts or parts[0] != "cloud-installer"
                or any(part in ("", ".", "..") for part in parts) or "\\" in name
                or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            raise ValueError("Unsafe release archive path")
        if name in names:
            raise ValueError("Duplicate release archive path")
        if not (member.isfile() or member.isdir()) or member.sparse is not None:
            raise ValueError("Release archive may contain only regular files and directories")
        if len(parts) == 1 and not member.isdir():
            raise ValueError("Release root must be a directory")
        if len(parts) > 1 and parts[1] not in DIRECTORIES:
            if len(parts) != 2 or parts[1] not in ROOT_FILES or not member.isfile():
                raise ValueError("Unexpected path outside the release payload allowlist")
        if member.size < 0 or member.size > MAX_FILE or (member.isdir() and member.size):
            raise ValueError("Release member exceeds the size limit")
        expanded += member.size
        if expanded > MAX_EXPANDED:
            raise ValueError("Expanded release exceeds the size limit")
        names[name] = member
        members.append((name, member))
    # Keep the bootstrap minimum compatible with older verified artifacts used
    # for original-artifact recovery; build-release.py enforces the current payload.
    required = {"cloud-installer/" + name for name in
                ("install.sh", "LICENSE", "pyproject.toml", "installer/__init__.py", "installer/main.py",
                 "resources/versions.json")}
    if not required.issubset(names) or any(not names[name].isfile() for name in required):
        raise ValueError("Archive is not a complete cloud-installer release")
    if not any(name.startswith("cloud-installer/resources/") and item.isfile() for name, item in members):
        raise ValueError("Release runtime resources are missing")
    for name, member in members:
        for parent in PurePosixPath(name).parents:
            if str(parent) in names and not names[str(parent)].isdir():
                raise ValueError("Release archive has conflicting file/directory paths")
    return members


def verify_and_extract(source, digest, destination):
    """Verify the exact bytes before inspecting/extracting into a fresh directory."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError("SHA256 must contain exactly 64 hexadecimal digits")
    with source.open("rb") as stream:
        if source.stat().st_size > MAX_ARCHIVE:
            raise ValueError("Release archive exceeds the size limit")
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != digest.lower():
        raise ValueError("Archive SHA256 mismatch; nothing was extracted or executed")
    # Bound the decompressed TAR itself before tarfile parses extended headers.
    # This also caps hostile gzip/PAX expansion, not just normal member sizes.
    with tempfile.TemporaryFile(dir=destination) as unpacked:
        with gzip.open(source, "rb") as compressed:
            copy_bounded(compressed, unpacked, MAX_EXPANDED)
        unpacked.seek(0)
        with tarfile.open(fileobj=unpacked, mode="r:") as archive:
            members = checked_members(archive)
            for name, member in members:
                target = destination / name
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(member) as input_file, target.open("xb") as output:
                    if copy_bounded(input_file, output, member.size) != member.size:
                        raise ValueError("Truncated release archive member")
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
    return destination / "cloud-installer"


def bootstrap(source, digest):
    validate_source(source)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError("SHA256 must contain exactly 64 hexadecimal digits")
    private_cache(CACHE)
    stage = Path(tempfile.mkdtemp(prefix=digest.lower()[:12] + "-", dir=CACHE))
    try:
        archive = stage / "release.tar.gz"
        acquire(source, archive)
        return verify_and_extract(archive, digest, stage)
    except BaseException:
        shutil.rmtree(stage)
        raise


if __name__ == "__main__":
    try:
        if os.geteuid() != 0 or not sys.platform.startswith("freebsd"):
            raise ValueError("Archive bootstrap requires root on the FreeBSD host")
        os.umask(0o077)
        print(bootstrap(sys.argv[1], sys.argv[2]))
    except KeyboardInterrupt:
        print("Archive bootstrap cancelled.", file=sys.stderr)
        raise SystemExit(130)
    except (OSError, ValueError, tarfile.TarError, EOFError, subprocess.SubprocessError) as error:
        print(f"Archive bootstrap failed: {error}", file=sys.stderr)
        raise SystemExit(1)
PY_ARCHIVE
}

launch_python() {
	require_python
	if [ -z "${script_dir:-}" ]; then
		script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd -P) || fail 'Cannot locate the installer.'
	fi
	[ -f "$script_dir/installer/main.py" ] || fail 'Installer payload missing; use a complete checkout or --archive and --sha256 with a supported explicit command; see --help.'
	umask 077
	ulimit -c 0
	PYTHONDONTWRITEBYTECODE=1
	export PYTHONDONTWRITEBYTECODE
	# Keep the caller's cwd: plan, backup and restore paths remain meaningful.
	# Isolated mode ignores user-site/PYTHONPATH code when running as root.
	exec python3 -I -B -c 'import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); sys.argv[0] = "install.sh"; runpy.run_module("installer.main", run_name="__main__")' "$script_dir" "$@"
}

main() {
	# Help is always offline, including a standalone downloaded entrypoint.
	for argument in "$@"; do
		case "$argument" in -h|--help) usage; return ;; esac
	done
	archive_source= archive_sha256= plain=0 assume_yes=0 config_file=
	# Remove bootstrap/global options without eval or losing quoted arguments.
	remaining=$#
	while [ "$remaining" -gt 0 ]; do
		case "$1" in
			--archive|--sha256)
				[ "$remaining" -ge 2 ] && [ -n "$2" ] || fail 'An archive and its SHA256 each need a value.'
				if [ "$1" = --archive ]; then
					[ -z "$archive_source" ] || fail 'Specify --archive once.'
					archive_source=$2
				else
					[ -z "$archive_sha256" ] || fail 'Specify --sha256 once.'
					archive_sha256=$2
				fi
				shift 2; remaining=$((remaining - 2))
				;;
			--plain) plain=1; shift; remaining=$((remaining - 1)) ;;
			*) set -- "$@" "$1"; shift; remaining=$((remaining - 1)) ;;
		esac
	done
	# Validate only the bootstrap routing shape; the Python parser owns the CLI.
	[ "$#" -eq 0 ] || [ -n "$1" ] || fail 'Unexpected empty command.'
	mode=${1:-menu}
	case "$mode" in
		menu) [ "$#" -eq 0 ] || fail 'Open the menu with: sh install.sh [--plain]' ;;
		install|configure|--configure-only)
			# Rotate only the validated recipe options, preserving quoted argv and cwd.
			seen_licenses=0 seen_acme=0
			remaining=$(( $# - 1 ))
			set -- "$@" "$1"; shift
			while [ "$remaining" -gt 0 ]; do
				case "$1" in
					--config)
						[ "$remaining" -ge 2 ] && [ -n "$2" ] && [ -z "$config_file" ] || fail 'Specify --config FILE once.'
						case "$2" in --*) fail 'Specify --config FILE.' ;; esac
						config_file=$2
						set -- "$@" "$1" "$2"; shift 2; remaining=$((remaining - 2)) ;;
					--config=*)
						[ -z "$config_file" ] && [ -n "${1#--config=}" ] || fail 'Specify --config FILE once.'
						config_file=${1#--config=}
						set -- "$@" "$1"; shift; remaining=$((remaining - 1)) ;;
					--yes)
						[ "$mode" = install ] && [ "$assume_yes" -eq 0 ] || fail '--yes is install-only and may be specified once.'
						assume_yes=1
						set -- "$@" "$1"; shift; remaining=$((remaining - 1)) ;;
					--accept-licenses)
						[ "$mode" = install ] && [ "$seen_licenses" -eq 0 ] || fail '--accept-licenses is install-only and may be specified once.'
						seen_licenses=1
						set -- "$@" "$1"; shift; remaining=$((remaining - 1)) ;;
					--accept-acme-terms)
						[ "$mode" = install ] && [ "$seen_acme" -eq 0 ] || fail '--accept-acme-terms is install-only and may be specified once.'
						seen_acme=1
						set -- "$@" "$1"; shift; remaining=$((remaining - 1)) ;;
					*) fail 'Unexpected recipe arguments.' ;;
				esac
			done
			if [ "$assume_yes$seen_licenses$seen_acme" != 000 ]; then
				[ -n "$config_file" ] || fail 'Install consent flags require --config FILE.'
			fi
			if [ -n "$config_file" ]; then
				[ -f "$config_file" ] && [ -r "$config_file" ] && [ ! -L "$config_file" ] || fail 'Configuration must be a readable regular file, not a symlink.'
			fi
			;;
		list|recover-network) [ "$#" -eq 1 ] || fail 'Unexpected command arguments.' ;;
		plan|--plan|resume|status|verify|--verify|add-user|recover-install)
			[ "$#" -eq 2 ] && [ -n "$2" ] || fail 'This command requires one file or instance.' ;;
		resolve) [ "$#" -ge 2 ] && [ -n "$2" ] || fail 'Usage: resolve FILE [--metadata FILE] [--installed PLAN]' ;;
		check-updates|check-security) : ;; # Python validates the inspection target and detailed flags.
		upgrade) [ "$#" -ge 2 ] && [ -n "$2" ] || fail 'Usage: upgrade INSTANCE [--nextcloud VERSION] [--plan | --verify | --restore SNAPSHOT_REPORT] [--skip-packages]' ;;
		maintenance)
			case "${2:-}" in
				register) [ "$#" -eq 3 ] && [ -n "$3" ] || fail 'Usage: maintenance register NAME'
					case "$3" in [a-z]*) ;; *) fail 'Invalid instance name.' ;; esac
					case "$3" in *[!a-z0-9]*|?????????*) fail 'Invalid instance name.' ;; esac ;;
				plan|stage|prepare-target|continue|cancel|status|recover|apply) : ;; # Python validates detailed flags, without bootstrap.
				*) fail 'Usage: maintenance register | plan | stage | prepare-target | continue | cancel | status | recover | apply' ;;
			esac ;;
		remove)
			[ "$#" -ge 2 ] && [ -n "$2" ] || fail 'Usage: remove INSTANCE [--purge-data]'
			[ "$#" -eq 2 ] || { [ "$#" -eq 3 ] && [ "$3" = --purge-data ]; } || fail 'Usage: remove INSTANCE [--purge-data]' ;;
		backup)
			[ "$#" -ge 2 ] && [ -n "$2" ] || fail 'Usage: backup INSTANCE [--output PATH]'
			[ "$#" -eq 2 ] || { [ "$#" -eq 4 ] && [ "$3" = --output ] && [ -n "$4" ]; } || fail 'Usage: backup INSTANCE [--output PATH]' ;;
		restore) [ "$#" -eq 3 ] && [ -n "$2" ] && [ -n "$3" ] || fail 'Usage: restore INSTANCE BACKUP' ;;
		*) usage >&2; fail 'Unknown command.' ;;
	esac
	case "$mode" in
		resume|status|verify|--verify|add-user|recover-install|remove|backup|restore|upgrade)
			case "$2" in [a-z]*) ;; *) fail 'Invalid instance name.' ;; esac
			case "$2" in *[!a-z0-9]*|?????????*) fail 'Invalid instance name.' ;; esac
			;;
	esac
	if [ -n "$archive_source$archive_sha256" ]; then
		[ -n "$archive_source" ] && [ "${#archive_sha256}" -eq 64 ] || fail 'Supply both --archive and its trusted 64-digit --sha256.'
		case "$archive_sha256" in *[!a-fA-F0-9]*) fail 'Invalid SHA256 digest.' ;; esac
		case "$archive_source" in https://?*) ;; *://*|-*|//*|https:*) fail 'Archive URL must use HTTPS; otherwise use a local file path.' ;; esac
		case "$mode" in
			menu|list|status|check-updates|check-security|maintenance|upgrade|plan|--plan|resolve)
				fail 'Menu, list, status, check-updates, check-security, maintenance, upgrade, plan and resolve require an already unpacked checkout/release; archive acquisition is unavailable for these commands.' ;;
		esac
	fi
	if [ "$plain" -eq 1 ]; then
		CLOUD_INSTALLER_PLAIN=1
		export CLOUD_INSTALLER_PLAIN
		set -- --plain "$@"
	fi
	script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd -P) || fail 'Cannot locate the installer.'
	case "$mode" in
		resolve)
			[ -z "$archive_source" ] || fail 'Version assessment requires an already unpacked artifact.'
			for argument in "$@"; do
				if [ "$argument" = --metadata ]; then launch_python "$@"; return; fi
			done
			;;
		plan|--plan)
			[ -z "$archive_source" ] || fail 'Offline planning requires an already unpacked checkout/release; no downloads are performed.'
			launch_python "$@"
			return
			;;
	esac
	PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
	export PATH
	require_host
	if [ ! -f "$script_dir/installer/main.py" ] && [ -z "$archive_source" ]; then
		fail 'Installer payload missing. Use a complete checkout or --archive HTTPS_URL_OR_LOCAL_FILE --sha256 TRUSTED_DIGEST with a supported explicit command; see --help.'
	fi
	# A lifecycle host must be checked before package/bootstrap/archive writes.
	# Offline plan/resolve have already returned and remain independent of host state.
	if [ -e /var/db/cloud-installer/lifecycle ] || [ -L /var/db/cloud-installer/lifecycle ] \
		|| [ -e /var/db/cloud-installer/maintenance/pending.json ] || [ -L /var/db/cloud-installer/maintenance/pending.json ]; then
		require_python
		[ -z "$archive_source" ] || fail 'Lifecycle hosts require their retained unpacked manager; historical archive dispatch is unsupported.'
		python3 -I -B -c 'import sys; sys.path.insert(0, sys.argv[1]); from installer.maintenance import entry_guard; entry_guard(sys.argv[2])' "$script_dir" "$mode" \
			|| fail 'Lifecycle state requires its matching manager or explicit enrollment recovery; no bootstrap performed.'
	fi
	case "$mode" in
		install|configure|--configure-only|resume)
			require_terminal
			if [ -f "$script_dir/resources/versions.json" ]; then
				bootstrap_python
			else
				require_python
			fi
			;;
		remove|restore|add-user|recover-install|recover-network) require_terminal; require_python ;;
		upgrade) require_python ;; # Native host guards apply even to --plan; never bootstrap pkg/Python.
		*) require_python ;;
	esac
	if [ -n "$archive_source" ]; then
		confirm 'Verify and unpack the supplied archive in the private /var/db/cloud-installer/downloads cache?' \
			|| fail 'Archive bootstrap declined.'
		umask 077
		script_dir=$(bootstrap_archive) || fail 'Verified archive bootstrap did not complete.'
		printf 'Verified release ready: %s\n' "$script_dir" >&2
	fi
	launch_python "$@"
}

main "$@"
