# Native utility contracts

Audit: 2026-10-17, FreeBSD **15.1-RELEASE amd64** policy. Inventory covers
`install.sh`, `installer/*.py`, jail shell/PHP workers, template rc/helpers and
generated boot guards. It is a command-family inventory, not a claim that every
dynamic argument or installed port version has passed native acceptance.
No guest commands were executed for this audit. Linux implementations are not
evidence for these contracts. Bounded native `ps` verification is identified
separately below.

## Process-field formatting

Do not combine header-suppressed fields as `-o pid=,ppid=,comm=` or
`-o pid=,ppid=,comm=,args=`. FreeBSD treats the text
following the first `=` as the first field's header, not additional fields.
Use a separate `-o field=` for **each** field. Process/writer closure and wrapper
identification must reject the one-column/header shape rather than treating it
as an empty process inventory. Repeated-field syntax has bounded native probe and
offline parser coverage. Native cold maintenance acceptance remains separate
and incomplete.

Evidence: [15.1 ps(1)][ps], [format parser][ps-source] (`parsefmt`, header consumes
the remainder after `=`). This is a verified FreeBSD incompatibility, not merely
a GNU-looking spelling. In contrast, FreeBSD supports `find -maxdepth/-mindepth`
and bsdtar's long extraction options.

## Contract ledger

Service-action planning evidence is recorded [below](#service-action-contracts); it does not
introduce new production commands or claim native acceptance.

In the table, **reviewed** means the named 15.1 source/manual was fetched during
this audit; **reference** means the authoritative location is provided but the
entire flag/output contract still needs version-pinned verification. **Offline**
means deterministic mocked coverage, never native acceptance. Paths abbreviated
below are under `installer/` unless otherwise specified.

| Utility / provenance | Used flags and output contract | Callsites | Evidence; coverage / gap |
|---|---|---|---|
| `ps` / base | `-ax`, `-ww -p PID`, repeated `-o pid=`, `ppid=`, `uid=`, `comm=`, `args=`; no headers; decimal IDs; `comm` is executable, not script identity | `maintenance_native`; `nextcloud-cron-fence.php` | **Reviewed** [ps][ps], [parser][ps-source]; native repeated-field probe and offline positive/negative parser/argv tests. All three known bad combined-header calls corrected. |
| `pgrep`, `kill` / base | `pgrep -u www -x php`: nonzero distinguishes no match from probe failure; `kill -QUIT PID` for pinned FPM | `operations`, `maintenance_native` | Reference `bin/pkill/pkill.1`, `bin/kill/kill.1`; no new native probe. Python `os.killpg` is a syscall boundary, not a `kill` shell option. |
| `stat`, `realpath` / base | `stat -f %u:%Lp`, `%u:%g:%Lp`, `%z`, `%d`, `%d:%i`; numeric owner, permissions without file type, byte size, device/inode; `realpath PATH` canonical absolute path | workers; recovery, opening, cancellation, generated guards | **Reviewed** `usr.bin/stat/stat.1`; new mocked large-device/inode test and human-output rejection. Symlink metadata remains `lstat` in Python/PHP where required. |
| `find` / base | `-mindepth 1 -maxdepth 1 ! -name .zfs -print`; `-path`, `-prune`, `-o`, grouped `-type`, `-exec … {} +` | `nextcloud.sh`, `onlyoffice.sh` | **Reviewed** `usr.bin/find/find.1`; depth limits are supported on 15.1. New tests do not execute traversal. |
| `install`, `mktemp`, `cp`, `mv`, `rm`, `chown`, `chmod` / base | `install -d/-S -o -g -m`; `mktemp -d …XXXXXX`; `cp -p/-Rp`; `rm -rf`; `chown -R/-h`; numeric/symbolic modes (`u=rwX,g=rX,o=`) | workers, rc helper, bootstrap | **Reviewed** `usr.bin/xinstall/install.1`: `-S` safe-copy and leaf directory mode differ from GNU assumptions. Other references `bin/{cp,mv,rm,chmod}/`, `usr.sbin/chown/`, `usr.bin/mktemp/`; mutation semantics not native-tested here. |
| `sh`, `env`, `test`, `cat`, `printf`, `awk`, `grep`, `id`, `sleep` / base | POSIX shell/builtins; `sh -s --`, `env -i`, `grep -Eq`; numeric `id -u/-g`; awk field comparisons and locks; controlled PATH/locale where configured | entrypoint, workers, generated prepare guard, security wrapper | References `bin/sh/sh.1`, `usr.bin/{env,awk,grep,id}/`; shell syntax coverage exists in worker tests (not rerun). Embedded Python and PHP do not imply shell invocation. |
| `uname`, `freebsd-version`, `sysctl` / base | `uname -s/-m/-U`, `freebsd-version -u/-r`; `sysctl -n` jail flag, memory/page counts, forwarding/bridge flags, `kern.boottime`; boot is `{ sec = N, usec = N } …`, not Linux epoch text | host/discovery/candidate, network, all maintenance phases | References `usr.bin/uname`, `bin/freebsd-version`, `sbin/sysctl`; new boot timeval acceptance/range/multiline refusal tests. Full textual boottime is compared; stable locale remains important. |
| `jls`, `jexec` / base | `jls -j NAME jid name path`, `-d … dying [host.hostname]`, `-h`; `-h` **adds** a header; explicit fields without it omit header. `dying` is `true/false`; `jexec [-U root] numeric-JID argv…` | deploy, enrollment, cold recovery, lifecycle, operations | **Reviewed** `usr.sbin/jls/jls.8`; references `lib/libjail/jail.c`, `usr.sbin/jexec/jexec.8`. Exact JID/root checks precede/follow calls; empty inventory only means no jails where explicitly allowed. No new native lifecycle probe. |
| `bastille` / **port** | `bootstrap --pkgbase`; `create -T -B --no-boot -g -n`; config `get/set`; start/stop/restart; `list -j NAME path`; `destroy -y` | deploy/lifecycle/enrollment/maintenance | [Bastille source](https://github.com/BastilleBSD/bastille); pinned 1.4.4 contract in project docs. Not base `jail(8)` flags. Success alone is not a live-jail proof; full flag audit still pending. |
| `service`, `sysrc` / base | `status/start/restart/graceful`; `onestatus/onestart/onestop/onerestart` bypass enable check; `sysrc -n`, `-f FILE`, `-x KEY`, assignments | workers, fences, start/stop/publication, rc templates | References `usr.sbin/service/service.sh`, `usr.sbin/sysrc/sysrc`; rc-specific actions belong to the installed port script. Clean database shutdown and process closure require independent evidence, not exit zero. |
| `mdo`, `pw`, `crontab`, `lockf` / base | `mdo -u www COMMAND` with inherited phase-specific descriptors; `pw useradd/usermod -n/-m/-d/-s/-w/-G`, `groupmod -m`; `crontab -u www -l/FILE`; `lockf -t 0` | helpers, SSH worker, cron fence, ONLYOFFICE worker | **Reviewed** `usr.bin/mdo/mdo.1`, `usr.sbin/cron/crontab/crontab.c`: absent table emits `crontab: no crontab for www\n`, exit 1; do not accept arbitrary errors. `mdo` is **FreeBSD base**, not a port dependency. References `usr.sbin/pw`, `usr.bin/lockf`. Descriptor contract has prior project evidence; not reprobed. |
| `mount`, `df` / base | `mount -p` six fstab-style columns; reject escaped paths; `df -P PATH` header plus one six-field row; compare filesystem and mountpoint, not human size units | cold capture/export/recovery, enrollment, host, guards | **Reviewed** `sbin/mount/mount.8`; reference `bin/df/df.1`. Existing recovery fixtures cover topology; native nullfs aliases/dying jails remain an acceptance gate. No shell `umount` boundary found in audited runtime. |
| `zfs`, `zpool` / base OpenZFS | `get -Hp -o value/property,value/value,source`; `list -H[p] -o … -t filesystem,volume/snapshot/bookmark -r`; decimal GUID/TXG/bytes; `yes`, `-`, local/inherited sources are significant | storage, cold recovery, export/rehearsal, lifecycle | Reference `sys/contrib/openzfs/man/man8/zfs-{get,list}.8`; source-aware ownership and tab/whitespace schemas are not JSON. Full native snapshot/restore gate outstanding. |
| `zfs` mutations / base OpenZFS | create `-u -o`, set, mount; one multi-name `snapshot -o …`; nonrecursive `rollback SNAP`; owned lifecycle `destroy -r`; `zpool list -H -o name/health`, `get -Hp -o value guid` | deploy, initialization, recovery_sets/export, lifecycle | References same OpenZFS man tree. Snapshot GUID and common createtxg must be independently verified; no recursive rollback. New mocked stream argv test only, not destructive verification. |
| `zfs send/receive` / base OpenZFS | estimate `send -nP -p SNAP`: exactly one `size\tBYTES` record on **stdout**; full `send -p` is binary stdout; `receive -u -o canmount=off -o mountpoint=none …` must not mount | `recovery_export:314`, `NativeStreams` | **Reviewed** [15.1 libzfs send implementation][zsend]: dry-run selects stdout; parsable size is bytes. Do not “fix” this to stderr based on another implementation/version. New offline send/receive argv test; actual independent send/receive rehearsal still required. |
| `pfctl` / base | `-nf`, `-f`, `-e/-d`, `-s Running/Anchors/info`, `-sr/-sn`, `-t TABLE -T show`, `-k SRC [-k DST]`, rollback-specific `-F states` only if initially enabled | firewall, host, lifecycle, generated guard | **Reviewed** `sbin/pfctl/pfctl.8`; exit-status Running probe and canonical live rule/table snapshots, not Linux firewall formats. No new PF execution. |
| `ifconfig`, `route`, `netstat`, `sockstat`, `kldstat`, `kldload`, `devfs` / base | bridge create/destroy/inet/up; `-a inet`; `route -n get default`; `netstat -rn -f inet`; `sockstat -46l -P tcp -p`; `kldstat -q -m`, `kldload -n`; `devfs rule -s 13 show` | host, deploy, firewall, guards | References `sbin/{ifconfig,route,kldstat,kldload,devfs}`, `usr.bin/netstat`, `usr.bin/sockstat`; textual `member:`, route/interface and listener schemas need native fixtures. No networking mutations in audit. |
| `fetch`, `sha256`, `tar` / base | `fetch -q -T SECONDS -o FILE/-`; normal HTTPS verification; `sha256 -q`; bsdtar `-xjf`, `--strip-components 1 --no-same-owner --no-same-permissions -C` | entrypoint, version worker, Nextcloud and ONLYOFFICE | References `usr.bin/fetch`, `sbin/md5`, `contrib/libarchive/tar/bsdtar.1`; bsdtar is not GNU tar. Archive extraction and TLS execution not retested. |
| `newsyslog` / base | `-n -f FILE` syntax/dry run; config `R` helper receives signal-number argument, helper ignores it and uses native SQL flush | workers, `templates/nextcloud/{newsyslog.conf,mysql-flush-logs}` | **Reviewed** `usr.sbin/newsyslog/newsyslog.8`; existing template cites 15.1 config/source evidence. Rotation scheduling/reopen requires native acceptance, not just dry-run. |
| `openssl`, `ssh-keygen`, `bsddialog`, `flua` / base | x509 `-in -noout -checkend -checkhost`; keygen `-l -f`; dialog `--output-fd 2`, explicit exit codes and widgets; `/usr/libexec/flua -` with `require('ucl')` | host, UI, install, version worker | References base source manuals; bsddialog and Lua modules are FreeBSD-specific, not GNU dialog/Lua substitutes. Existing UI/bootstrap tests not rerun. |
| `pkg` / base **shim** + **port** engine | shim `/usr/sbin/pkg -N/bootstrap`; `/usr/local/sbin/pkg -C /dev/null -o …`; query `%n/%v/%o/%q/%Fp`; rquery dependency/checksum formats; install `-n -y -U -r FreeBSD-ports`, update, audit `-F -f/--raw=json` | discovery, deploy, versions worker, package_security, maintenance | [pkg source](https://github.com/freebsd/pkg); signed isolated catalogue and exact dependency closure; `-n` solver status depends on reviewed pkg release. JSON audit is pkg schema, **not base utility JSON**; schema/error fixtures exist, installed-version revalidation pending. |
| `curl`, `gpg` / **ports** | curl `--silent --show-error --fail --noproxy '*' --max-time --resolve/--connect-to --header --cacert --output --write-out %{http_code}`; gpg `--homedir --batch --no-tty --import/--status-fd 1 --verify` | maintenance HTTP checks, source authentication/workers | [curl options](https://curl.se/docs/manpage.html), [GnuPG](https://www.gnupg.org/documentation/manuals/gnupg/); parse fixed status code/VALIDSIG fingerprint, not human messages. Port version and backend TLS behavior not newly tested. |
| PHP/Python, `cgi-fcgi`, MariaDB clients, Redis client / **ports** | PHP `-d/-r/-f`, occ `--no-interaction` commands and JSON; Python `-I -B/-c`; CGI `-bind -connect`; MariaDB `--no-defaults --protocol=socket --batch --skip-column-names --execute/-e`; Redis `-s … PING` | workers, inventory, candidate, updater, validation, operations | Version policy plus application manuals/source; JSON is application/helper schema; TSV SQL and CGI headers must not be replaced by invented JSON. Existing inventory/native tests; new tests don't execute interpreters or databases. |
| Apache/nginx/PHP-FPM, `supervisorctl`, `fc-cache`, `certbot`, optional `doas`/zsh / **ports** | apachectl configtest, `-k graceful/graceful-stop`; nginx `-t`; FPM `-t`; supervisor status `ds:docservice ds:metrics`; font cache `-f`; certbot certonly webroot/renew; doas `-n` probe | workers, templates, maintenance, SSH | Installed port rc/layout and upstream manuals are authoritative. Service names aren't executable guarantees; supervisor RUNNING rows not JSON. Fonts, callbacks, log reopening and restart behavior require native checks. |

2026-10-19 native extension: repeat rollback uses base `ifconfig -l`, full
`ifconfig bridgeN` inspection, then `ifconfig bridgeN inet ADDRESS -alias` to
withdraw only the recorded new address **before** PF reload expands `self`.
FreeBSD15.1 native recovery passed with existing PF/states and original services
preserved. `tests/test_firewall_transaction.py` uses native-formatted `inet` /
`member:` fixtures and checks ordering, foreign-member/address refusal, inspection
failure, interrupted withdrawal and strict live-snapshot failure. See
[the ifconfig15.1 manual](https://man.freebsd.org/cgi/man.cgi?query=ifconfig&sektion=8&manpath=FreeBSD+15.1-RELEASE).

2026-10-20 VM boot source review: base `/usr/bin/env -i PATH=... COMMAND` clears
inherited environment; FreeBSD15.1 `usr.bin/env/env.1` explicitly defines `-i`.
`libexec/rc/rc.subr:load_rc_config` loads service-specific config from `/etc` and
each `local_startup` location (stripping a final `/rc.d`). VM helpers therefore
check later `rc.conf.d/vm` overrides and the effective default datastore, not just
the owned `/etc` file. Deterministic tests cover refusal, isolated pre-import
source checks and generated shell syntax; those tests alone are not native boot
publication evidence. See [validation limits](verification.md).

All base source paths in this table are relative to
[FreeBSD releng/15.1](https://github.com/freebsd/freebsd-src/tree/releng/15.1).
References are not assertions of support on 14.x, another 15.x release or Linux.
No direct runtime utility invocation of `sed`, `date`, `daemon`, `umount`, GNU
`timeout`, `readlink -f`, `systemctl`, `ip` or `ss` was identified; similarly named
Python APIs/comments are not commands. Port rc scripts may themselves use base
`daemon`; their transitive command inventory remains a port-level follow-up.

## Workstation boundary and validation

### Base-only release transport (2026-10-22)

The existing release builder can print a POSIX `/bin/sh -c` command, not a new
downloaded bootstrap script. FreeBSD15.1 source manuals reviewed:
[sh(1)](https://github.com/freebsd/freebsd-src/blob/releng/15.1/bin/sh/sh.1),
[fetch(1)](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.bin/fetch/fetch.1)
and [bsdtar(1)](https://github.com/freebsd/freebsd-src/blob/releng/15.1/contrib/libarchive/tar/bsdtar.1).
`ulimit -f 131072` uses **512-byte blocks** on FreeBSD sh, bounding the acquisition
subshell's file size to64MiB. `fetch -T 60 -o FILE URL` has network timeouts, not an
absolute whole-transfer deadline. Status is checked without a download pipeline.
`sha256 -q FILE` is compared before extraction; base tar uses `-C DIR`,
`--no-same-owner --no-same-permissions` and umask077 on authenticated builder output.
`stat -f %u:%Lp` supplies numeric owner/octal permissions, and `mktemp -d TEMPLATE`
creates a unique persistent private directory. Existing private directories must
already be root-owned0700, not symlinks; no chmod/chown repair is attempted.
Sandbox tests model native stat output and command ordering; GNU tar in the Linux
harness is not native compatibility proof. Bounded native execution subsequently
passed on October 23 without preinstalled Git, Bash or Python, including wrong-SHA
refusal before extraction. Private transport and certificate reuse did not test
public routing or ACME. See the [validation matrix](verification.md).

### Bounded removal teardown probe (2026-10-22)

Removal uses base `jls --libxo json -d jid name path dying` on the reviewed
FreeBSD15.1 target. Native capture confirmed schema
`{"__version":"2","jail-information":{"jail":[]}}` when empty; populated rows
have **string** `jid`, `name`, `path`, and `dying` (`"true"`/`"false"`). `-d`
includes both live and dying jails. A successful complete enumeration establishes
absence; targeted-query failure is not accepted as proof. Nonzero status,
diagnostics, malformed/ambiguous records or changed target roots refuse removal.
See [jls.8](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.sbin/jls/jls.8)
and [jls.c](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.sbin/jls/jls.c)
(`xo_parse_args`, jail-information/jail output and enumeration error handling).

The post-stop wait pins JID/root/name, waits only for dying state, uses monotonic
10-second deadlines and 0.25-second sleeps, and limits each command to the lesser
of 2 seconds and the remaining budget. The deadline is checked after commands;
late output cannot authorize continuation. No Runner, stop command, boot/network,
ownership/mount or destruction-checkpoint semantics are replaced.

Targeted native helper integration passed on a separate FreeBSD15.1 VM.
An attached fixture child created an
AF_UNIX socket and passed its descriptor to a host parent via SCM_RIGHTS. After
the child exited, normal `jail -r` left the genuine kernel jail dying until that
descriptor closed. No `jls` output was fabricated or production clock patched.

Seven bounded native cases passed: live refusal, ordinary immediate disappearance,
dying-to-absent after descriptor release (1.016s), wrong JID/root refusal, real
10-second deadline refusal (10.0001s), and successful retry after release without
another remove command. Roots remained present; the final kernel inventory was
empty. Caller fixtures were unnetworked, with IPv4/IPv6 disabled and no VNET/PF,
application installation or recursive filesystem deletion. Bastille stop ordering,
all-root destruction guards and journal/replay integration are deterministic
offline tests, **not** a new full installed-instance removal acceptance claim.
The normal stop command remains unchanged; this is evidence for the probe/wait
seam only, not a new complete application/removal acceptance result.

Scanner selection uses base `grep -Fxq files_antivirus` on the newline-separated
validated app IDs, not substring matching. FreeBSD 15.1 [grep(1)](https://man.freebsd.org/cgi/man.cgi?query=grep&sektion=1&manpath=FreeBSD+15.1-RELEASE)
documents fixed-string/whole-line/quiet flags and exit 0 for a match, 1 for no match;
other failures refuse the phase. Focused shell tests cover exact versus containing
IDs and probe errors; no native scanner reinstallation was performed.

Sizing inspection uses base `zpool list -Hp -o
size,allocated,free,health POOL` and `zfs list -Hp -t filesystem -o
name,used,available,referenced,usedbysnapshots,quota,refquota,reservation,refreservation
POOL [EXISTING-PARENTS...]`, with `zfs list -H NAME` existence checks. Selection
is limited to the pool and relevant installer storage parents, not a recursive
dataset inventory. Output format verified read-only on FreeBSD 15.1-RELEASE
(earlier recursive probe): byte fields, including absent
quotas/reservations as decimal `0`, with tab-separated rows and no header.
`tests/test_storage_inspection.py` retains representative native-format values
and rejects human sizes/malformed records; narrowed destination selection is
covered offline. Parent `used` includes descendants;
never sum parent and child usage. `usedbysnapshots` is per-dataset. Inspection
does not prove thin backing-store capacity or constitute native quota-creation
acceptance. Reference: [FreeBSD 15.1 zfs-list(8)](https://man.freebsd.org/cgi/man.cgi?query=zfs-list&sektion=8&manpath=FreeBSD+15.1-RELEASE).

Bounded property probe (2026-10-19): native `zfs create -u -o NAME=VALUE ...`
with `mountpoint=none` and the generated lz4/atime/dedup/sync/primarycache/recordsize/
exec/setuid properties passed on one new empty dataset. `zfs get -H -o
property,value,source` verified local values; `set recordsize=128K` on that same
dataset passed after 16K creation. No existing datasets or snapshot GUIDs changed;
the additional test dataset was retained. Property syntax evidence only, not a
performance benchmark or native application installation acceptance.

Linux/libvirt utilities, process/filesystem probes and browser test tooling are
not production dependencies or FreeBSD command contracts. Linux output must not
be mechanically converted into FreeBSD fixtures.

Focused deterministic utility checks, from a source checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_freebsd_utility_contracts.py -v
git diff --check
```

Remaining priorities: obtain real 15.1 cold
closure/capture/export/rehearsal/restore evidence; expand reviewed pkg,
Bastille, PF/listener and port-specific output fixtures without weakening refusal
on unknown formats. Passing offline contracts never grants native update authority.

## pkg 2.8.4 checkpointed inventory contract — 2026-10-18

Bounded native inspection found both jails running `pkg|2.8.4|ports-mgmt/pkg`,
`READ_LOCK=no`, an empty `PLUGINS` list, and byte-identical main databases across
supported inspection queries. Both had zero-byte WAL and 32-KiB SHM files, with
no rollback journal. This is component evidence, not complete recovery acceptance.

Reviewed [2.8.4 query](https://github.com/freebsd/pkg/blob/2.8.4/src/query.c#L1239-L1246)
uses `PKGDB_DEFAULT_READONLY`. The [database open path](https://github.com/freebsd/pkg/blob/2.8.4/libpkg/pkgdb.c#L1131-L1206)
participates in WAL/SHM coordination and may fall back to immutable access;
only writable connections perform schema upgrades or the
[close-time checkpoint](https://github.com/freebsd/pkg/blob/2.8.4/libpkg/pkgdb.c#L1278-L1292).
Query success alone is not checkpoint proof. The
[FreeBSD 2.8.4 port](https://github.com/freebsd/freebsd-ports/tree/7e1abc7fc95dde712fda36f2e7422b48d8938c0e/ports-mgmt/pkg)
has no pkgdb/query behavior patch. Do not substitute the older 2.6.2 open contract.

`maintenance_native._pkg_database_identity` brackets the entire per-jail runtime
inventory sequence. It pins no-follow directory/file descriptors, requires safe
root ownership (the privileged executor UID), and checks paths for replacement.
The main database remains fully hashed with the existing serialized receipt shape.
WAL must be absent or empty; any rollback journal refuses. SHM may be absent or a
safe regular file of at most **32768 bytes**, the observed single-region profile;
larger layouts remain unsupported. Its contents/timestamps are coordination state,
not durable package identity. Sidecar identity/size/permissions are checked only
within a call, not serialized across restore. Appearance or disappearance during
the bracket refuses, including newly created empty sidecars; no files are removed.
Cold/reclosure checks retain exact main-database equality and execute no pkg.

Follow-up native component evidence on 2026-10-18 found only empty-WAL ctime
changed across the full query/runtime sequence; main bytes/metadata, WAL inode,
ownership, mode, link count, size and mtime were unchanged. The exact
[pkg 2.8.4 vendored SQLite 3.53.2 unixOpen](https://github.com/freebsd/pkg/blob/2.8.4/external/sqlite/sqlite3.c#L46901-L46913)
calls `robustFchown` for WAL/journal opens; the
[root-only wrapper](https://github.com/freebsd/pkg/blob/2.8.4/external/sqlite/sqlite3.c#L40899-L40910)
can change ctime even when owner/group remain identical. Accordingly only WAL
ctime is excluded from its transient comparison. WAL mtime and every structural
field remain checked, as do main-database ctime/hash and rollback-journal absence.
This models a native read interface, not arbitrary concurrent package writes.

Live inspection uses `pkg -o PKG_ENABLE_PLUGINS=false config KEY` for `READ_LOCK`,
`PLUGINS` and `PKG_DBDIR`, requiring `no`, empty output and `/var/db/pkg` respectively.
It does not override `READ_LOCK` during inspection. Subsequent queries use
`pkg -o PKG_ENABLE_PLUGINS=false -o READ_LOCK=false query FORMAT [PACKAGE]`.
The inventory must identify pkg exactly as `2.8.4` / `ports-mgmt/pkg`.
[Configuration output](https://github.com/freebsd/pkg/blob/2.8.4/src/config.c) and
[plugin loading](https://github.com/freebsd/pkg/blob/2.8.4/libpkg/plugins.c#L276-L331)
are reviewed; suppress plugins before inspection, not after they could load.
Existing admission authenticates executables/configuration before these commands.

The operator must exclude unmanaged package transactions during maintenance.
Controller host/database locks serialize our operations, not arbitrary root pkg
commands; sidecar metadata and process-name scans are not writer-exclusion proofs.
No SQL/checkpoint command, SQLite extension, permission change or persistent pkg
configuration change is introduced. Focused offline tests cover safe sidecars,
replacement/drift, unsupported settings and query-free cold identity checks.

## Service-action contracts

Source review, 2026-10-17; not native service-upgrade acceptance. Verify installed
port scripts and add deterministic command/output regressions when implementing
the recipe; these observations alone do not enable execution.

| Interface | Reviewed behavior and limitation |
| --- | --- |
| FreeBSD 15.1 base [`service`](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.sbin/service/service.sh) / [`rc.subr`](https://github.com/freebsd/freebsd-src/blob/releng/15.1/libexec/rc/rc.subr) | Dispatches service-specific actions; port script behavior is not a generic base guarantee. Use verified numeric JID before/after jailed commands. |
| Port [`php_fpm`](https://github.com/freebsd/freebsd-ports/blob/main/lang/php85/files/php_fpm.in) | `configtest` calls FPM `-t`; reload checks config then sends USR2, stop uses QUIT. Multi-profile loop can exit zero despite profile failures: validate each explicitly. This main-branch reference must be matched to installed bytes before use. |
| Port [`apache24`](https://github.com/freebsd/freebsd-ports/blob/a3fbcaec539824a635d1bd53a2508fafae06ec6a/www/apache24/files/apache24.in) | `configtest` uses `httpd -t`; reload uses `httpd -k graceful`. Require `apache24_configcheck_disable=NO`. Successful reload is not proof of effective settings/readiness. |
| Port [Bastille 1.4.4 `update`](https://github.com/BastilleBSD/bastille/blob/1.4.4/usr/local/share/bastille/update.sh) | Existing thick-jail update uses root-scoped pkgbase transaction and a running jail; release-name update affects only the cache. Automatic startup/catalog refresh/acceptance cannot replace our fence and locked-transaction contracts. Jail-base upgrades are not implicit application dependencies. |

## Native app/scanner interfaces

Source review 2026-10-18; deterministic worker tests are not native acceptance.
Bounded native component checks exercised scanner/socket/signature and supervised
temporary Mail-PF seams; these are not broad mail-delivery or antivirus guarantees.
The new app selection and scanner integration are implemented for the reviewed
FreeBSD 15.1 profile; no workstation command provisions a jail or installs apps.

| Interface | Reviewed behavior and limitation |
| --- | --- |
| [NC35 `occ app:install`](https://github.com/nextcloud/server/blob/v35.0.2/core/Command/App/Install.php), [`app:list`](https://github.com/nextcloud/server/blob/v35.0.2/core/Command/App/ListApps.php) | Native signing, dependency/compatibility checks and enabling; already-installed install returns 1. Combine native inventory/installed_version with our private running marker to refuse uncertain replay. Never use force/unstable overrides. |
| [FreeBSD ClamAV port](https://github.com/freebsd/freebsd-ports/blob/main/security/clamav/Makefile), observed 1.5.4_2,1 | `security/clamav` selected through existing signed package/dependency locks, only inside NC jail. Uses clamav account/group and /var/{db,run,log}/clamav. Main-branch observations do not pin future catalog versions. |
| [clamd rc](https://github.com/freebsd/freebsd-ports/blob/main/security/clamav/files/clamav_clamd.in), [freshclam rc](https://github.com/freebsd/freebsd-ports/blob/main/security/clamav/files/clamav_freshclam.in) | Services `clamav_clamd`/`clamav_freshclam`, native onestart/onestop/onestatus and boot enable knobs. PID files /var/run/clamav/{clamd,freshclam}.pid; private clamd.sock. Stop updater/scanner during affected maintenance, restart scanner before web access. |
| [Freshclam 1.5.4](https://github.com/Cisco-Talos/clamav/blob/clamav-1.5.4/freshclam/freshclam.c) | Native DNS/HTTPS signature update protocol and validation retained; one-shot initial signature update precedes scanner readiness. Do not replace with an unsigned download. Native acquisition and sigtool verification passed for main/daily/bytecode databases; not a signature-distribution certification. |
| FreeBSD base `pw groupmod clamav -m www`, stat -f ownership/mode checks | Give www only the scanner socket's group access; do not put the scanner in www's application/data group. FPM restart picks up supplementary groups. No Linux stat fixtures are used as FreeBSD evidence. |
| Python 3 standard-library fsync/replace | Existing jail Python writes/fsyncs a private app-operation marker and its parent directory before occ mutation. Stale temporary intent refuses replay. This is a tiny durability boundary, not a new journal framework or abrupt-power-loss acceptance result. |
| FreeBSD 15.1 base timeout, test harness only | Default mode is a reaper that waits for descendants, including newly started persistent daemons. The version-matched native manual's foreground option (`-f`) bounds only the foreground command. Used for scanner component tests; never apply this as a shortcut to weaken detached network worker-group termination. |
| Native PF verbose output, test harness only | Self rules expand to individual host addresses; verbose table names include counts (for example `<cloud_noninternet:9>`), and ports may print service names. Counters were parsed on FreeBSD, not inferred from Linux service-name mappings. Candidate cancellation restored verified committed live/disk snapshots without disabling PF/flushing states. |

[ps]: https://github.com/freebsd/freebsd-src/blob/releng/15.1/bin/ps/ps.1
[ps-source]: https://github.com/freebsd/freebsd-src/blob/releng/15.1/bin/ps/keyword.c
[zsend]: https://github.com/freebsd/freebsd-src/blob/releng/15.1/sys/contrib/openzfs/lib/libzfs/libzfs_sendrecv.c
