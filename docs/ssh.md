# Optional direct SSH into both jails

Configure direct jail SSH through `sh install.sh`. It is opt-in, with a separate
key-only OS account in each jail, **unprivileged by default**. This account is independent of
Nextcloud users and the Nextcloud administrator. Host-root application and
database operations remain available through the same installer menu.

Choose an unused username such as `cloudop`. FreeBSD already has a system
account named `operator`; it must not be reused. Existing accounts and existing
unmanaged running SSH services are refused. The installer records the created
account's UID so a later run cannot silently adopt a different account.

Provide an absolute path to a root-owned OpenSSH **public** key on the host
(for example `/root/cloudop.pub`). A public key may be mode `0644` but must not
be group/world-writable or reached through symlinks. Supply one plain key line;
authorized_keys command/options, certificates, multiple keys and private keys
are not accepted. Ed25519, supported ECDSA, RSA and OpenSSH security-key public
key formats are accepted; `ssh-keygen` validates the complete key in each jail.
Keep the private key on your SSH client.

## Network access

The host PF configuration maps the selected ports to jail TCP 22, restricted to
the configured management CIDR. Defaults are:

| Host port | Destination |
| --- | --- |
| 2201 | `<instance>nc`, Nextcloud jail |
| 2202 | `<instance>oo`, ONLYOFFICE jail |

Connect from an allowed management address, using the host/router management
address selected during setup. For example, with host address `192.0.2.10`:

```sh
ssh -p 2201 -i ~/.ssh/cloudop cloudop@192.0.2.10
ssh -p 2202 -i ~/.ssh/cloudop cloudop@192.0.2.10
```

These examples are client connections, not additional installer entrypoints.
The web hostname and management address need not be the same. A router needs
matching port forwarding if management access crosses its NAT. Restrict that
router rule to the same management sources.

Each jail generates its own SSH host keys. Verify host-key fingerprints through
your trusted host administration session before accepting the first connection.
Known-host entries include the nonstandard port; do not disable host-key checking
to resolve a mismatch after a reinstall.

## Account and daemon policy

- The OS password is unusable; SSH requires a public key. Root, password and
  keyboard-interactive authentication are disabled.
- Only the selected username is permitted. It has a private primary group and
  no supplementary groups. The default selection grants no root privileges.
- The home and `.ssh` directory are `0700`; `authorized_keys` is `0600` and owned
  by the account. A later managed run replaces the authorized key with the
  selected public key.
- Agent, TCP, Unix-socket, X11 and tunnel forwarding are disabled. SSH forwarding
  restrictions are not a sandbox for shell users; host PF still controls network
  reachability.
- SFTP's base subsystem definition is retained (or `internal-sftp` is supplied
  if absent). Normal shell and SFTP access are available within the account's
  filesystem permissions.
- Jail sshd uses `/etc/ssh/sshd_config.cloud-installer`, selected by its rc
  configuration. The candidate is checked with `sshd -t` and effective policy
  with `sshd -T` before service activation. It listens on IPv4 TCP 22 inside
  each jail, with normal OpenSSH cryptographic defaults and INFO logging.

The setup worker receives username, shell choice, public key and the explicit
administrator-selection boolean via stdin.
It never copies the host credential bundle or an SSH private key into a jail.
An unprivileged account cannot access root-private payload/state or private
application credentials. Privileged application maintenance is available through
the host menu.

### Explicit administrator option

If you select and confirm administrator access, `ssh_admin=true` includes the
jail-local FreeBSD `doas` package in the resolved application-phase package lock
and writes a root-owned `0600`
`/usr/local/etc/doas.conf` containing `permit nopass <username> as root`. This
grants the selected key **full root administration inside both jails**, including
access to application data and runtime credentials. Root SSH login remains
disabled; no wheel membership is needed. `doas` uses its default sanitized
environment, and its policy is syntax-checked and exercised with an `id -u`
probe before SSH setup succeeds.

An initial packaged `doas.conf` is accepted only if it exactly matches the package's
sample; it is not permission to adopt a custom policy. Only the installer's own
delegation policy can be replaced on a later managed
run. Selecting unprivileged access then writes a deny rule and verifies root
delegation is unavailable. Foreign `doas.conf` files are refused. This does not
terminate already-running privileged sessions or undo changes an administrator
has made.

## sh and optional zsh

`ssh_shell` accepts `sh` (default, `/bin/sh`) or `zsh`. Selecting zsh includes
`zsh` and its dependency closure in both jails' resolved package locks before
application inventories are finalized. SSH setup never selects additional/newer
packages; missing or changed prerequisites are refused. It checks registration
in `/etc/shells`, and selects
`/usr/local/bin/zsh` for this account.

The initial local `.zshrc` has a simple user/jail/directory prompt, standard
completion, private `umask 077`, and bounded history. Leading-space commands
are excluded from saved history; duplicate/extra whitespace entries are
reduced, and cross-session/incremental history sharing is disabled. Existing
user `.zshrc` customizations are preserved on a later setup run. There is no
downloaded shell framework, plugin bootstrap or change to root's shell.

History exclusion is a convenience, not a secret transport: a leading-space
command still has process arguments and briefly remains in zsh's in-memory
history. Use the host menu for passwords, database work and user creation.
Installer workers continue to use `/bin/sh` regardless of the interactive shell.

## Sources and acceptance

Reviewed 2026-10-14:

- [FreeBSD Handbook: OpenSSH](https://docs.freebsd.org/en/books/handbook/security/#openssh)
- [FreeBSD 15.1 sshd_config(5)](https://man.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5&manpath=FreeBSD+15.1-RELEASE)
- [FreeBSD 15.1 pw(8) source](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.sbin/pw/pw.8)
- [FreeBSD doas port and package policy](https://github.com/freebsd/freebsd-ports/tree/main/security/doas)
- [doas configuration syntax](https://github.com/slicer69/doas/blob/master/doas.conf.5)
- [zsh history options](https://zsh.sourceforge.io/Doc/Release/Options.html#History)

Offline tests cover input validation, generated policy, worker syntax and
optional host orchestration. On an approved disposable FreeBSD installation,
verify both jail logins/SFTP from the management CIDR, denial from another
source, rejection of root/password login, disabled forwarding, default denial
and opt-in success of `doas`, and persistence after a host reboot. Test both
shell selections.
