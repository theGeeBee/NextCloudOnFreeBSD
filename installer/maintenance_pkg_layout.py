"""Read-only fixed MariaDB PAM layout observation, never admission authority.

The caller must authenticate the original Nextcloud jail baseline and locked
package closure BEFORE calling, prove its jail/dataset identity, and compare
retained evidence on subsequent calls. Never use newly observed hashes to adopt
changed code. This helper neither executes PAM/pkg nor grants start permission.

FreeBSD ports 7831640f2ed6d44aa4a6e92876d8d944bb647618:
databases/mariadb123-server/{Makefile,pkg-plist}, UIDs (mysql=88).
MariaDB tag mariadb-12.3.3, scripts/mysql_install_db.sh:498-511 deliberately
sets this directory to mysql:0700 and its helper to root:04755, preserving groups.
"""
import hashlib
import os
from pathlib import Path
import stat


PAMDIR = '/usr/local/lib/mysql/plugin/auth_pam_tool_dir'
PAMFILE = PAMDIR + '/auth_pam_tool'
PASSWD = '/etc/passwd'
DENIED = 'Reviewed MariaDB PAM layout refused'


def _require(value):
    if not value:
        raise ValueError(DENIED)


def _identity(info):
    # atime can change on reads; every identity/content-change field is retained.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _metadata(info, kind):
    return dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                gid=info.st_gid, type=kind)


def capture_mariadb_pam(root, *, package_name, package_version, package_origin):
    """Return _runtime_files-compatible PAM directory/file and passwd identities.

    Only the fixed Nextcloud database recipe may call this. UID 88 is allowed at
    exactly PAMDIR, never elsewhere. All traversal is anchored to no-follow FDs;
    named edges and open identities are rechecked before returning observations.
    """
    _require(os.geteuid() == 0)
    _require((package_name, package_version, package_origin) ==
             ('mariadb123-server', '12.3.3', 'databases/mariadb123-server'))
    root = Path(root)
    _require(root.is_absolute() and '..' not in root.parts and root != Path('/'))
    descriptors, edges = [], []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def directory(parent, name, *, pam=False):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(stat.S_ISDIR(before.st_mode))
        if pam:
            _require((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (88, 0, 0o700))
        else:
            _require(before.st_uid == 0 and not before.st_mode & 0o022)
        fd = os.open(name, flags, dir_fd=parent)
        descriptors.append(fd)
        _require(_identity(os.fstat(fd)) == _identity(before))
        edges.append((parent, name, fd, before))
        return fd, before

    def file(parent, name, *, pam=False):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        limit = 1024 * 1024 if not pam else 16 * 1024 * 1024
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                 and before.st_nlink == 1 and 0 < before.st_size <= limit)
        if pam:
            _require(before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o4755)
        else:
            _require(not before.st_mode & 0o022)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        _require(_identity(os.fstat(fd)) == _identity(before))
        edges.append((parent, name, fd, before))
        digest, data, size = hashlib.sha256(), bytearray(), 0
        while True:
            block = os.read(fd, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            size += len(block)
            _require(size <= limit and size <= before.st_size)
            digest.update(block)
            if not pam:
                data.extend(block)
        _require(size == before.st_size)
        result = _metadata(before, 'file')
        result.update(size=size, sha256=digest.hexdigest())
        return result, data

    try:
        fd, _ = directory(None, '/')
        for part in root.parts[1:]:
            fd, _ = directory(fd, part)
        jail = fd
        etc, _ = directory(jail, 'etc')
        passwd, data = file(etc, 'passwd')
        entries = [line.split(':') for line in data.decode('utf-8').splitlines()
                   if line.split(':', 1)[0] == 'mysql']
        _require(len(entries) == 1 and len(entries[0]) == 7 and entries[0][2] == '88')
        for part in Path(PAMDIR).parts[1:-1]:
            fd, _ = directory(fd, part)
        parent, parent_info = directory(fd, 'auth_pam_tool_dir', pam=True)
        _require(set(os.listdir(parent)) == {'auth_pam_tool'})
        helper, _ = file(parent, 'auth_pam_tool', pam=True)
        _require(set(os.listdir(parent)) == {'auth_pam_tool'})
        for owner, name, opened, before in edges:
            _require(_identity(os.fstat(opened)) == _identity(before) ==
                     _identity(os.stat(name, dir_fd=owner, follow_symlinks=False)))
        return {PAMDIR: _metadata(parent_info, 'directory'), PAMFILE: helper, PASSWD: passwd}
    except (OSError, UnicodeError, ValueError):
        raise ValueError(DENIED) from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
