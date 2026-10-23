#!/bin/sh
# Internal worker invoked by the install.sh menu with public settings on stdin.
set +x
set +v
set -eu
umask 077
ulimit -c 0
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = FreeBSD ] \
    && [ "$(sysctl -n security.jail.jailed)" = 1 ] || {
    printf '%s\n' 'SSH worker requires root inside a managed FreeBSD jail.' >&2
    exit 1
}
PAYLOAD=/root/cloud-installer
RUNTIME=$PAYLOAD/runtime.json
fail() { printf '%s\n' "SSH worker: $*" >&2; exit 1; }
. "$PAYLOAD/resources/jails/versions.sh"
if [ -d /usr/local/www/nextcloud ]; then version_load nextcloud; else version_load onlyoffice; fi
version_environment
version_packages_check
# Python's program uses stdin; preserve the separate JSON input on descriptor 3.
exec 3<&0
exec /usr/local/bin/python3 - <<'PY'
import base64
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile


STATE = Path('/var/db/cloud-installer')
MARKER = STATE / 'ssh.json'
CONFIG = Path('/etc/ssh/sshd_config.cloud-installer')
DOAS = Path('/usr/local/etc/doas.conf')
RESERVED = {'root', 'operator', 'www', 'mysql', 'redis', 'nobody', 'sshd', 'toor'}
ZSHRC = '''# Local installer defaults; no downloaded shell framework or plugins.
umask 077
HISTFILE=$HOME/.zsh_history
HISTSIZE=1000
SAVEHIST=1000
setopt HIST_IGNORE_SPACE HIST_IGNORE_DUPS HIST_REDUCE_BLANKS HIST_SAVE_BY_COPY
unsetopt SHARE_HISTORY INC_APPEND_HISTORY
autoload -Uz compinit
compinit
PROMPT='%n@%m:%~%# '
'''


def run(*args, check=True, input=None):
    result = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=600,
                            umask=0o022 if args[0] == 'pkg' else 0o077)
    if check and result.returncode:
        raise RuntimeError('SSH setup command failed')
    return result


def validate(value):
    if not isinstance(value, dict) or set(value) != {'username', 'shell', 'public_key', 'admin'}:
        raise ValueError('Unexpected SSH configuration')
    user, shell, key = value['username'], value['shell'], value['public_key']
    if not isinstance(user, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', user) or user in RESERVED:
        raise ValueError('Choose a non-system username')
    if (shell not in ('sh', 'zsh') or not isinstance(key, str) or len(key) > 16384
            or type(value['admin']) is not bool):
        raise ValueError('Invalid shell/key')
    fields = key.strip().split()
    if (len(fields) != 2 or '\n' in key.strip() or fields[0] not in {
            'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com'}):
        raise ValueError('Expected one plain OpenSSH public key')
    blob = base64.b64decode(fields[1], validate=True)
    length = int.from_bytes(blob[:4], 'big')
    if length < 1 or blob[4:4 + length] != fields[0].encode('ascii') or len(blob) <= 4 + length:
        raise ValueError('Invalid public key blob')
    return user, shell, ' '.join(fields) + '\n', value['admin']


def root_directory(path, mode=0o755):
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=mode)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unsafe root-owned directory')


def read_root(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or info.st_mode & 0o022 or info.st_size > limit):
            raise ValueError('Unsafe root-owned input')
        return stream.read(limit + 1)


def write_at(directory, name, text, uid=0, gid=0, *, replace=True):
    temporary = '.cloud-installer-' + name
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fchown(stream.fileno(), uid, gid)
            os.fsync(stream.fileno())
        if not replace:
            # An existing user customization is not replaced on a later rerun.
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                return
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def sshd_config(user, subsystems):
    return '''# Managed jail-only sshd configuration. Host SSH is independent.
Port 22
AddressFamily inet
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM yes
HostbasedAuthentication no
IgnoreRhosts yes
StrictModes yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers ''' + user + '''
DisableForwarding yes
AllowTcpForwarding no
AllowStreamLocalForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
PermitUserRC no
LoginGraceTime 30
MaxAuthTries 3
LogLevel INFO
''' + '\n'.join(subsystems) + '\n'


def doas_policy(user, enabled):
    return ('# Managed by cloud-installer; jail SSH delegation only.\n'
            + ('permit nopass ' if enabled else 'deny ') + user + ' as root\n')


def configure_doas(user, enabled, owned):
    # Do not append grants to, or replace, someone else's privilege policy.
    existing = DOAS.exists() or DOAS.is_symlink()
    if existing:
        allowed = (doas_policy(user, False), doas_policy(user, True)) if owned else (
            read_root(Path('/usr/local/etc/doas.conf.sample')),)
        if read_root(DOAS) not in allowed:
            raise ValueError('Refusing to replace an unmanaged doas policy')
    binary = Path('/usr/local/bin/doas')
    if enabled and not binary.exists():
        raise ValueError('The locked doas prerequisite is missing; no implicit package installation is permitted')
    if not enabled and not existing:
        return
    for directory in (Path('/usr/local'), Path('/usr/local/etc')):
        root_directory(directory)
    policy = doas_policy(user, enabled)
    if binary.exists():
        with tempfile.NamedTemporaryFile(mode='w', dir=STATE, prefix='.doas-', delete=True) as candidate:
            candidate.write(policy)
            candidate.flush()
            run(str(binary), '-C', candidate.name)
    fd = os.open(DOAS.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        write_at(fd, DOAS.name, policy)
    finally:
        os.close(fd)
    if binary.exists():
        probe = run('mdo', '-u', user, str(binary), '-n', '/usr/bin/id', '-u', check=False)
        if enabled and (probe.returncode or probe.stdout.strip() != '0'):
            raise ValueError('Requested doas administration did not work')
        if not enabled and probe.returncode == 0:
            raise ValueError('Unprivileged SSH account still has doas administration')
    elif enabled:
        raise ValueError('doas package did not install the expected executable')


def main():
    with os.fdopen(3) as source:
        text = source.read(32769)
    if len(text) > 32768:
        raise ValueError('SSH input too large')
    user, shell, key, admin = validate(json.loads(text))
    for directory in (Path('/var'), Path('/var/db'), STATE):
        root_directory(directory, 0o700 if directory == STATE else 0o755)
    if STATE.stat().st_mode & 0o077:
        raise ValueError('SSH state must be root-private')
    old = json.loads(read_root(MARKER)) if MARKER.exists() or MARKER.is_symlink() else None
    home = '/usr/home/' + user
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        account = None
    if old is None and account is not None:
        raise ValueError('Refusing to adopt an existing account')
    if old is not None and (old.get('username') != user or account is None
                            or old.get('uid') != account.pw_uid or account.pw_dir != home):
        raise ValueError('Managed SSH account identity changed')
    if account is not None and (account.pw_uid < 1000 or account.pw_gid < 1000
                                or grp.getgrgid(account.pw_gid).gr_name != user
                                or any(group.gr_gid != account.pw_gid and user in group.gr_mem
                                       for group in grp.getgrall())):
        raise ValueError('SSH account must retain its private group without supplementary memberships')
    running = run('service', 'sshd', 'onestatus', check=False).returncode == 0
    if old is None and running:
        raise ValueError('Refusing to replace an existing SSH service')
    for directory in (Path('/etc'), Path('/etc/ssh'), Path('/usr'), Path('/usr/home')):
        root_directory(directory)
    with tempfile.NamedTemporaryFile(mode='w', dir=STATE, prefix='.ssh-public-', delete=True) as candidate:
        candidate.write(key)
        candidate.flush()
        run('ssh-keygen', '-l', '-f', candidate.name)
    selected = '/bin/sh'
    if shell == 'zsh':
        if not Path('/usr/local/bin/zsh').exists():
            raise ValueError('The locked zsh prerequisite is missing; no implicit package installation is permitted')
        selected = '/usr/local/bin/zsh'
        if selected not in read_root(Path('/etc/shells')).splitlines():
            raise ValueError('zsh package did not register its login shell')
    if account is None:
        # -w no sets an unusable password, without locking public-key access.
        run('pw', 'useradd', '-n', user, '-m', '-d', home, '-s', selected, '-w', 'no', '-G', '')
        account = pwd.getpwnam(user)
        if account.pw_uid < 1000 or account.pw_gid < 1000 or grp.getgrgid(account.pw_gid).gr_name != user:
            raise ValueError('New account is not an ordinary user')
        # Retain ownership evidence even if a subsequent sshd check fails.
        fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            write_at(fd, MARKER.name, json.dumps({'username': user, 'uid': account.pw_uid}) + '\n')
        finally:
            os.close(fd)
    else:
        run('pw', 'usermod', '-n', user, '-s', selected)
    home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(home_fd).st_uid != account.pw_uid:
            raise ValueError('Unexpected home directory owner')
        os.fchmod(home_fd, 0o700)
        try:
            os.mkdir('.ssh', 0o700, dir_fd=home_fd)
        except FileExistsError:
            pass
        ssh_fd = os.open('.ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        try:
            if os.fstat(ssh_fd).st_uid not in (0, account.pw_uid):
                raise ValueError('Unexpected .ssh directory owner')
            os.fchown(ssh_fd, account.pw_uid, account.pw_gid)
            os.fchmod(ssh_fd, 0o700)
            write_at(ssh_fd, 'authorized_keys', key, account.pw_uid, account.pw_gid)
        finally:
            os.close(ssh_fd)
        if shell == 'zsh':
            write_at(home_fd, '.zshrc', ZSHRC, account.pw_uid, account.pw_gid, replace=False)
    finally:
        os.close(home_fd)
    configure_doas(user, admin, old is not None)
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        write_at(fd, MARKER.name, json.dumps({'username': user, 'uid': account.pw_uid, 'admin': admin}) + '\n')
    finally:
        os.close(fd)
    original = read_root(Path('/etc/ssh/sshd_config'))
    subsystems = [line.strip() for line in original.splitlines()
                  if re.match(r'^\s*Subsystem\s+', line, re.IGNORECASE)]
    if not subsystems:
        subsystems = ['Subsystem sftp internal-sftp']
    candidate_text = sshd_config(user, subsystems)
    run('ssh-keygen', '-A')
    with tempfile.NamedTemporaryFile(mode='w', dir=STATE, prefix='.sshd-', delete=True) as candidate:
        candidate.write(candidate_text)
        candidate.flush()
        run('/usr/sbin/sshd', '-t', '-f', candidate.name)
        effective = run('/usr/sbin/sshd', '-T', '-f', candidate.name).stdout.splitlines()
        for expected in ('permitrootlogin no', 'passwordauthentication no',
                         'kbdinteractiveauthentication no', 'authenticationmethods publickey',
                         'disableforwarding yes', 'allowusers ' + user):
            if expected not in effective:
                raise ValueError('SSH policy did not take effect')
    fd = os.open(CONFIG.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        write_at(fd, CONFIG.name, candidate_text)
    finally:
        os.close(fd)
    run('sysrc', 'sshd_enable=YES', 'sshd_flags=-f ' + str(CONFIG))
    run('service', 'sshd', 'onerestart' if running else 'onestart')
    run('service', 'sshd', 'onestatus')
    print(json.dumps({'username': user, 'shell': shell, 'admin': admin}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Jail SSH setup failed; no credentials or private keys were printed.') from None
PY
