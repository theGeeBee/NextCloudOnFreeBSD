#!/usr/bin/env python3
"""Print the short, checksum-pinned launcher for a reviewed bootstrap.sh."""
import argparse
import re
import shlex


LAUNCHER = '''set -eu; PATH=/sbin:/bin:/usr/sbin:/usr/bin; export PATH; unset SSL_NO_VERIFY_PEER SSL_NO_VERIFY_HOSTNAME SSL_ALLOW_SSL3; [ "$(id -u)" = 0 ] && [ "$(uname -s)" = FreeBSD ] && [ -t 0 ] && [ -t 1 ] || { printf '%s\\n' 'Run as root in an interactive FreeBSD terminal' >&2; exit 1; }; umask 077; d=$(mktemp -d /tmp/nextcloud-bootstrap.XXXXXXXX); (ulimit -f 2048; exec fetch -T 60 -o "$d/bootstrap.sh" "$1"); [ "$(sha256 -q "$d/bootstrap.sh")" = "$2" ] || { printf '%s\\n' 'Bootstrap SHA256 mismatch; nothing executed' >&2; exit 1; }; exec /bin/sh "$d/bootstrap.sh"'''


def install_command(commit, digest):
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Use the full reviewed public commit ID")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Use the independently trusted bootstrap SHA256")
    url = f"https://raw.githubusercontent.com/theGeeBee/NextCloudOnFreeBSD/{commit}/bootstrap.sh"
    return "/bin/sh -c " + shlex.quote(LAUNCHER) + " bootstrap " + shlex.quote(url) + " " + digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        print(install_command(args.commit, args.sha256))
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
