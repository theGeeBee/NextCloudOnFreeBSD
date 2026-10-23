#!/bin/sh
# Alpine guest only. Public settings are a private JSON file; no application
# credentials or image/container selection belong in this common Docker phase.
set -eu
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
fail() { printf '%s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] && [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] \
    && [ -f /etc/alpine-release ] && [ -x /sbin/rc-service ] \
    || fail 'Guest bootstrap requires the selected root Alpine x86_64/OpenRC VM.'
[ "$#" -eq 1 ] || fail 'Supply exactly the protected public guest runtime file.'
CONFIG=$1
STATE=/var/lib/cloud-installer/office
EXPECTED=$STATE/daemon.json.expected

# Python belongs to the selected cloud-init image, not an opportunistic pip or
# host dependency. No eval/sourced JSON or Linux package-version lock framework.
decision=$(python3 - "$CONFIG" "$STATE" <<'PY'
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

def refuse():
    raise ValueError('Guest public configuration or ownership is invalid; no package operation performed')

def private(path, directory=False):
    info = path.lstat()
    if ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid != 0 or info.st_mode & 0o077 or (not directory and info.st_nlink != 1)):
        refuse()

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: refuse()
        result[key] = value
    return result

try:
    source = Path(sys.argv[1])
    if not source.is_absolute() or source.resolve(strict=True) != source: refuse()
    private(source)
    if source.stat().st_size > 65536: refuse()
    c = json.loads(source.read_text(), object_pairs_hook=unique)
    if (not isinstance(c, dict) or set(c) != {'schema_version', 'alpine_branch', 'address', 'docker_network', 'managed_networks'}
            or type(c['schema_version']) is not int or c['schema_version'] != 1): refuse()
    branch = c['alpine_branch']
    if (not isinstance(branch, str) or not re.fullmatch(r'[1-9][0-9]*\.(?:0|[1-9][0-9]*)', branch)
            or not re.fullmatch(re.escape(branch) + r'\.[0-9]+\n?', Path('/etc/alpine-release').read_text())): refuse()
    if not isinstance(c['address'], str) or not isinstance(c['docker_network'], str): refuse()
    address = ipaddress.IPv4Address(c['address'])
    if str(address) != c['address']: refuse()
    ranges = [ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    if not any(address in n for n in ranges): refuse()
    docker = ipaddress.IPv4Network(c['docker_network'], strict=True)
    if docker.prefixlen != 24 or not any(docker.subnet_of(n) for n in ranges): refuse()
    if (not isinstance(c['managed_networks'], list) or not c['managed_networks']
            or len(c['managed_networks']) > 256 or len(set(c['managed_networks'])) != len(c['managed_networks'])): refuse()
    if any(not isinstance(n, str) for n in c['managed_networks']): refuse()
    networks = [ipaddress.IPv4Network(n, strict=True) for n in c['managed_networks']]
    if any(str(n) != raw for n, raw in zip(networks, c['managed_networks'])): refuse()
    if any(docker.overlaps(n) for n in networks) or not any(address in n for n in networks): refuse()
    live = subprocess.run(['ip', '-4', 'address', 'show'], check=True, capture_output=True, text=True).stdout
    if not re.search(r'\binet ' + re.escape(str(address)) + '/', live): refuse()
    allowed = {f'{scheme}://dl-cdn.alpinelinux.org/alpine/v{branch}/{group}'
               for scheme in ('http', 'https') for group in ('main', 'community')}
    repository_file = Path('/etc/apk/repositories')
    info = repository_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1: refuse()
    repositories = [line.strip() for line in repository_file.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith('#')]
    if not repositories or any(line not in allowed for line in repositories): refuse()
    daemon = json.dumps({'bip': str(docker.network_address + 1) + '/24',
                         'hosts': ['unix:///var/run/docker.sock'], 'log-driver': 'json-file',
                         'log-opts': {'max-size': '10m', 'max-file': '3'}}, sort_keys=True, indent=2) + '\n'
    state = Path(sys.argv[2])
    if state != Path('/var/lib/cloud-installer/office'): refuse()
    for directory in (state.parent, state):
        if directory.exists() or directory.is_symlink(): private(directory, directory=True)
        else: directory.mkdir(mode=0o700)
    expected = state / 'daemon.json.expected'
    prior = expected.exists() or expected.is_symlink()
    if prior:
        private(expected)
        if expected.read_text() != daemon: refuse()
    elif Path('/var/run/docker.sock').exists():
        refuse()  # Do not adopt an already-running administrator-managed engine.
    current = Path('/etc/docker/daemon.json')
    if current.parent.exists() or current.parent.is_symlink():
        info = current.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: refuse()
    if current.exists() or current.is_symlink():
        private(current)
        if current.read_text() != daemon: refuse()
    complete = state / 'bootstrap-complete.json'
    started = state / 'bootstrap-apk-started.json'
    if complete.exists() or complete.is_symlink():
        private(complete)
        done = json.loads(complete.read_text(), object_pairs_hook=unique)
        if (not isinstance(done, dict) or set(done) != {'schema_version', 'runtime_sha256', 'packages_sha256', 'daemon_sha256', 'docker_version'}
                or type(done['schema_version']) is not int or done['schema_version'] != 1
                or done['runtime_sha256'] != hashlib.sha256(source.read_bytes()).hexdigest()
                or done['daemon_sha256'] != hashlib.sha256(daemon.encode()).hexdigest()): refuse()
        for file in (state / 'packages.txt', state / 'docker-version.txt', current): private(file)
        inventory = (state / 'packages.txt').read_bytes()
        if (hashlib.sha256(inventory).hexdigest() != done['packages_sha256']
                or (state / 'docker-version.txt').read_text().strip() != done['docker_version']
                or current.read_text() != daemon): refuse()
        live = subprocess.run(['apk', 'info', '-v'], check=True, capture_output=True, text=True).stdout
        if sorted(live.splitlines()) != sorted(inventory.decode().splitlines()): refuse()
        print('complete')
        sys.exit(0)
    if started.exists() or started.is_symlink():
        sys.exit('Guest APK bootstrap effects are uncertain; inspect retained state before explicit recovery. No APK replay performed.')
    if not prior:
        with expected.open('x') as stream:
            stream.write(daemon)
            stream.flush()
            os.fsync(stream.fileno())
    desired = ''.join(f'https://dl-cdn.alpinelinux.org/alpine/v{branch}/{group}\n' for group in ('main','community'))
    descriptor, pending = tempfile.mkstemp(prefix='.cloud-repositories-', dir=repository_file.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(desired)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, repository_file)
    finally:
        if os.path.exists(pending): os.unlink(pending)
    with started.open('x') as stream:
        json.dump({'schema_version': 1, 'runtime_sha256': hashlib.sha256(source.read_bytes()).hexdigest()}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(state, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
    print('initial')
except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
    sys.exit('Guest public configuration/identity refused; inspect protected inputs (values not printed)')
PY
) || fail 'Guest bootstrap validation/reconciliation failed; no package replay permitted.'

if [ "$decision" = complete ]; then
    rc-service docker status < /dev/null
    current_version=$(docker --host=unix:///var/run/docker.sock version --format '{{.Server.Version}}' < /dev/null)
    [ "$current_version" = "$(cat "$STATE/docker-version.txt")" ] || fail 'Saved guest Docker version differs; no upgrade performed.'
    printf '%s\n' 'Existing guest bootstrap reconciled; no package installation or service start performed.'
    exit 0
fi
[ "$decision" = initial ] || fail 'Invalid guest bootstrap decision.'

# This common phase has public settings only, never application/JWT input. Keep
# its native diagnostics private instead of losing them in captured SSH output.
LOG=$STATE/bootstrap.log
if [ -e "$LOG" ] || [ -L "$LOG" ]; then
    [ -f "$LOG" ] && [ ! -L "$LOG" ] && [ "$(stat -c %u:%a:%h "$LOG")" = 0:600:1 ] \
        || fail 'Guest bootstrap diagnostic log identity differs.'
else
    (set -C; : > "$LOG")
fi
exec >> "$LOG" 2>&1

# APK verifies the branch-matched repository/package signatures against the
# image's trust keys. Never use edge, --allow-untrusted or a blanket upgrade.
env -i PATH="$PATH" apk add --no-cache docker < /dev/null
dockerd --validate --config-file "$EXPECTED" < /dev/null
install -d -m 700 /etc/docker
if [ ! -f /etc/docker/daemon.json ]; then
    install -m 600 "$EXPECTED" /etc/docker/daemon.json
fi
rc-update add cgroups boot < /dev/null
rc-service cgroups start < /dev/null
rc-update add docker default < /dev/null
rc-service docker start < /dev/null
rc-service docker status < /dev/null
docker_version=$(python3 - <<'PY_DOCKER_READY'
import re,subprocess,sys,time
deadline=time.monotonic()+60
while time.monotonic()<deadline:
    try:
        result=subprocess.run(['docker','--host=unix:///var/run/docker.sock','version','--format','{{.Server.Version}}'],
                              check=False,capture_output=True,text=True,timeout=5)
        version=result.stdout.strip()
        if result.returncode==0 and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version):
            print(version)
            break
    except (OSError,subprocess.TimeoutExpired):
        pass
    time.sleep(1)
else:
    sys.exit('Guest Docker API did not become ready within the bounded startup wait.')
PY_DOCKER_READY
)
printf '%s\n' "$docker_version" > "$STATE/docker-version.txt"
test -s "$STATE/docker-version.txt" || fail 'Docker did not return a server version.'
apk info -v < /dev/null > "$STATE/packages.txt.new"
test -s "$STATE/packages.txt.new" || fail 'Guest package inventory is empty.'
mv "$STATE/packages.txt.new" "$STATE/packages.txt"
python3 - "$CONFIG" "$STATE" <<'PY_COMPLETE'
import hashlib,json,os,sys,tempfile
from pathlib import Path
source,state=Path(sys.argv[1]),Path(sys.argv[2])
value={'schema_version':1,'runtime_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
       'packages_sha256':hashlib.sha256((state/'packages.txt').read_bytes()).hexdigest(),
       'daemon_sha256':hashlib.sha256((state/'daemon.json.expected').read_bytes()).hexdigest(),
       'docker_version':(state/'docker-version.txt').read_text().strip()}
fd,pending=tempfile.mkstemp(prefix='.bootstrap-complete-',dir=state)
with os.fdopen(fd,'w') as out:
    os.fchmod(out.fileno(),0o600);json.dump(value,out);out.flush();os.fsync(out.fileno())
os.replace(pending,state/'bootstrap-complete.json')
directory=os.open(state,os.O_RDONLY)
try:os.fsync(directory)
finally:os.close(directory)
PY_COMPLETE
printf '%s\n' 'Guest Docker bootstrap complete; no office container installed.'
