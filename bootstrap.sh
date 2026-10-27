#!/bin/sh
# Release transport only: verify and retain v2026.10.27, then hand off to its
# unmodified install.sh. No provisioning logic or prerequisite installation here.
set +x
set +v
set -eu
[ "$#" -eq 0 ] || { printf '%s\n' 'Usage: sh bootstrap.sh (fresh installation only)' >&2; exit 1; }
set -- 'https://github.com/theGeeBee/NextCloudOnFreeBSD/releases/download/v2026.10.27/NextCloudOnFreeBSD-2026.10.27.tar.gz' '688bf580cae161b867b27a0e07c70f3249596d0dd17c2fe4c361cafb412eaa3a'
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
exec /bin/sh "$payload/install.sh" install
