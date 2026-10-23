"""Read actual CLI/main-FPM/callback-FPM modules without loading Nextcloud.

The helper is installed only by fresh same-artifact preparation, outside the web
document root. A missing helper blocks observation; inspection never retrofits it.
The caller supplies the existing verified numeric-JID command boundary and must
have validated owned resources. No environment/configuration contents are returned.
"""

import hashlib
import os
from pathlib import Path
import re
import stat

from .generations import _fields, _json
from .paths import RESOURCES


HELPER = "/usr/local/libexec/cloud-runtime-inventory.php"
MAX_BYTES = 32768
ROOT_UID = 0


def validate(value, context):
    _fields(value, "version sapi integer_size loaded_modules")
    if (context not in ("cli", "main_fpm", "callback_fpm")
            or type(value["version"]) is not str or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"])
            or value["sapi"] != ("cli" if context == "cli" else "fpm-fcgi")
            or type(value["integer_size"]) is not int or value["integer_size"] != 8):
        raise ValueError("Unsupported runtime observation")
    modules = value["loaded_modules"]
    if (type(modules) is not list or not 1 <= len(modules) <= 256
            or any(type(name) is not str or (name != "cgi-fcgi" and not re.fullmatch(r"[a-z][a-z0-9_ ]{0,63}", name))
                   or name == "cgi-fcgi" and context == "cli" for name in modules)
            or modules != sorted(set(modules))):
        raise ValueError("Invalid loaded runtime module inventory")
    return value


def _helper_identity(root):
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns,
                info.st_size, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
    path = Path(root) / HELPER.removeprefix("/")
    for parent in reversed(path.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError("Unsafe runtime helper ancestry")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o640 or info.st_size > MAX_BYTES):
        raise ValueError("Unsafe or missing retained runtime helper")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if identity(opened) != identity(info):
            raise ValueError("Runtime helper changed before observation")
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    if identity(after) != identity(path.lstat()) or identity(after) != identity(info):
        raise ValueError("Runtime helper changed during observation")
    if raw != (RESOURCES / "jails/runtime-inventory.php").read_bytes():
        raise ValueError("Runtime helper differs from the retained source")
    return hashlib.sha256(raw).hexdigest()


def collect_php(context):
    """context exposes config, jail_root and the verified-before/after jail call."""
    jail = context.config.nextcloud_jail
    root = context.jail_root(jail)
    try:
        identity = _helper_identity(root)
        result = {}
        for name, argument in (("cli", "cli"), ("main_fpm", "main"), ("callback_fpm", "callback")):
            probe = context.jail(jail, "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
                                 "LC_ALL=C", "/usr/local/bin/php", HELPER, argument,
                                 timeout=40, check=False, hide_output=True)
            if (probe.returncode != 0 or type(probe.stdout) is not str
                    or not 1 <= len(probe.stdout.encode()) <= MAX_BYTES or probe.stderr):
                raise ValueError("Incomplete runtime observation")
            result[name] = validate(_json(probe.stdout), name)
            if _helper_identity(root) != identity:
                raise ValueError("Runtime helper changed between observations")
        return result
    except (ValueError, OSError, RuntimeError, TypeError, KeyError, AttributeError):
        raise ValueError("CLI/FPM runtime inventory unavailable or unsafe; no package/module readiness is inferred") from None
