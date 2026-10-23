# One entrypoint: checkout or verified archive

Run **`sh install.sh`** from an interactive terminal on a FreeBSD 15.1-RELEASE
amd64 ZFS host. It opens the instance menu. The entrypoint locates its own
payload, so it also works when invoked from another directory. File arguments
remain relative to your current directory.

The runtime uses Python **3.11+ and its standard library**. No pip installation,
Git installation on the target, or extra UI framework is needed. The shell
checks root, FreeBSD userland, architecture and that it is outside a jail before
offering dependency installation. Python also checks the running kernel before
deployment. Missing `pkg` and `python3` each require affirmative consent during
explicit installation/configuration/resume; package
operations select **FreeBSD-ports**, without upgrading the host. Bastille is
handled after plan review and the final deployment confirmation.

On a lifecycle-enabled host, the current shell checks lifecycle/source fences
**before** package bootstrap or archive acquisition. Keep its original protected,
unpacked executor path. Enrollment/status/recovery never acquire an archive or
install prerequisites; independent historical entrypoints are unsupported after
enrollment. See [source and boot restrictions](lifecycle-state.md).

## Commands

```text
sh install.sh [--plain]                     interactive instance menu
sh install.sh install                      configure, review and install
sh install.sh install --config FILE [--yes] [--accept-licenses] [--accept-acme-terms]
                                            reuse JSON; network KEEP stays attended
sh install.sh configure                    save private configuration
sh install.sh configure --config FILE       save settings from the same JSON reader
sh install.sh resume INSTANCE              review a retained installation
sh install.sh recover-network              recover an interrupted PF transition
sh install.sh recover-install INSTANCE     reset unpublished initialization
sh install.sh list                         list registered instances
sh install.sh status INSTANCE              inspect retained state
sh install.sh check-updates [NAME | --all] [--refresh] [--save-report] [--json]
sh install.sh check-security [NAME | --all] [--refresh] [--save-report] [--json]
sh install.sh upgrade INSTANCE [--nextcloud VERSION] [--plan | --verify | --restore SNAPSHOT_REPORT] [--skip-packages]
sh install.sh maintenance register NAME     explicit same-artifact enrollment
sh install.sh maintenance status            inspect lifecycle/pending state
sh install.sh maintenance recover           exact pending metadata recovery
sh install.sh maintenance plan --instance NAME --recovery-only
                                            read-only recovery preparation
sh install.sh verify INSTANCE              verify an installed instance
sh install.sh remove INSTANCE [--purge-data]
sh install.sh backup INSTANCE [--output PATH]
sh install.sh restore INSTANCE BACKUP
sh install.sh add-user INSTANCE
sh install.sh plan FILE
sh install.sh resolve FILE [--metadata FILE] [--installed PLAN]
sh install.sh --help
```

Compatibility aliases are `--plan FILE`, `--configure-only`, and
`--verify INSTANCE`. `--plain` may appear before or after the command. Instance
names are 1–8 lowercase letters/digits, beginning with a letter.

The [maintenance preparation guide](maintenance-recovery.md) documents explicit plan saving,
local staging, operation status/continuation/cancellation and recovery assessment.
Native maintenance apply remains blocked; no executable recipe is shipped.
The separate optional [native upgrade assistant](upgrade.md) supports the reviewed
35.0.1→35.0.2 transition and compatible application-jail package changes, not
arbitrary version updates. `upgrade INSTANCE --restore SNAPSHOT_REPORT` explicitly
restores its pre-upgrade ZFS snapshot set; restoration is never automatic.
`restore INSTANCE BACKUP` instead retains the historical same-instance,
version-compatible database/configuration backup contract, not snapshot recovery.

`plan` and help work on Linux without host probes, dependency bootstrap, cache
creation or bytecode writes. Planning requires an already unpacked payload and
an existing Python 3.11+ interpreter. For example:

```sh
sh /path/to/NextCloudOnFreeBSD/install.sh plan ./examples/config.json
```

`resolve --metadata` is also offline and read-only. Live `resolve` requires the
selected FreeBSD target and existing pkg/Python; it writes only disposable signed
catalog state and never bootstraps or installs packages. See [version management](versions.md).

The menu, `list`, `status`, `check-updates`, `check-security` and `verify` use the target host's
root-owned state and existing Python; they never install dependencies. Opening
the dashboard or reading reports does not create registry state or take its
operation lock. Missing Python gives prerequisite guidance, not a bootstrap
prompt. See [dashboard/update reports](operations.md#dashboard-and-update-reports).
Configuration and approval workflows
require a terminal; `backup` can also run without a terminal using existing
Python. Explicit new installation, configuration and resume can bootstrap
missing dependencies; choosing one from the menu re-enters the same shell
entrypoint before acquiring mutation locks. Removal and restoration have their own explicit reviews;
`--purge-data` is a deliberate request to remove instance data.

## Terminal interface

On a supported terminal the installer uses **FreeBSD base `bsddialog`**. The
[FreeBSD 15.1 manual](https://man.freebsd.org/cgi/man.cgi?query=bsddialog&sektion=1&manpath=FreeBSD+15.1-RELEASE)
documents its menu/input/yes-no dialogs, `--output-fd`, and exit statuses (0 OK,
1 Cancel/No, 5 ESC, 255 error). It first shipped in FreeBSD 14.0. Dialog stdout
remains attached to the foreground terminal; only its explicit response fd 2 is
captured. Ordinary messages and progress remain visible on terminal stdout.

Use `--plain` for numbered prompts. This fallback is also automatic when
`bsddialog` is missing, `TERM` is unsupported, the screen is too small, or dialog
initialization fails. Enter a menu number or its key; `0`, Ctrl-C, or end-of-input
cancels. Dialog Cancel/ESC likewise cancels rather than accepting a default.
Confirmation defaults to No. Passwords always use hidden `getpass` input,
never dialog defaults or subprocess arguments. Progress reports completed
steps as `[current/total]`. Long private-input phases also print elapsed-time
heartbeats, not guessed completion percentages; worker output stays private.

The document fonts/plugins section offers **None**, **All 10**, and **Choose
individual plugins**. None is the initial default. The review lists the exact
requested set and external-service implications; keys/accounts are configured
separately, never placed in public runtime settings. Macros is built in and
discontinued EasyBib is not offered. See [plugin policy](onlyoffice-plugins.md).
Existing immutable instances do not silently gain a plugin selection on Resume.
The release includes the reviewed public `resources/plugins/onlyoffice.json`
catalog and `installer/plugins.py`; selected payloads are acquired and hashed
separately, not bundled with credentials or fetched during static `plan`.

## Multiple instances

Each instance gets separate jail identities, private networks, bridges, storage,
configuration and credentials. Bastille is shared at
`/srv/cloud-installer/bastille`; instance datasets live under
`POOL/cloud-installer/instances/INSTANCE`. The wizard allocates unused private
`/29` blocks and bridge names using the registry, carries forward the shared
pool/uplink/management policy, and shows the remaining aggregate memory budget.
Host inspection and preflight check the reviewed configuration before applying.

The default additional instance on the same host IPv4 uses an external HTTPS
reverse proxy and an unused HTTP backend port starting at 8080. Supply trusted
proxy CIDRs; only those sources may reach that backend. The proxy must terminate
HTTPS for the public hostname and forward the hostname and protocol headers.
The public HTTPS port is configurable independently of the host backend port.
An additional assigned host IPv4 can instead use its own ACME or provided TLS
certificate. ACME needs public TCP 80 to reach the selected instance.

Jail hostnames may be customized independently of the short Bastille jail names,
including hyphenated names or FQDNs. Optional jail SSH uses an administrator
**public** key, selected forwarded ports, and the shared management CIDR. Login
is unprivileged by default; root administration through `doas` requires explicit
consent. Choose base `sh` or optionally install zsh with local defaults. Font choices include
standard/comprehensive profiles and an optional absolute directory containing
additional fonts. The current native ONLYOFFICE package requires Microsoft
webfonts: explicit operator [EULA consent](fonts.md#microsoft-fonts-require-explicit-consent)
is required regardless of the open-font profile.

## No-clone installation

### Clean FreeBSD: one generated command, no preinstalled Python

A maintainer can use the existing builder to print a single copy-and-paste
`/bin/sh -c ...` command for the **exact archive just built**:

```sh
# Maintainer workstation; replace this example URL with the reviewed, pinned
# HTTPS release-asset location. This does not upload or publish anything.
python3 tools/build-release.py --output dist/cloud-installer.tar.gz \
  --url 'https://ARTIFACT_HOST/releases/REVIEWED_RELEASE/cloud-installer.tar.gz'
```

Publish those exact archive bytes and the printed command/digest through a trusted
channel. On the clean destination FreeBSD 15.1 amd64 ZFS host, as root in an
interactive terminal, paste the **whole printed command**. It is one shell command
(formatted across lines for review), not a script downloaded into a shell pipe.
No Git, Bash or Python is needed for this first stage. It uses FreeBSD base
`fetch`, `sha256`, `tar`, `stat`, `mkdir` and `mktemp`; then invokes the retained
payload's own `install.sh install`, without `--yes` or other consent flags.
The existing policy/platform checks, explicit missing pkg/Python consent, wizard,
APPLY, KEEP and provisioning sequence are unchanged.

The command validates root/FreeBSD/outside-jail/TTY and existing lifecycle fences,
then validates root-owned, non-symlink, non-group/world-writable ancestors. Existing
installer/cache directories must be exactly `0700`; they are never repaired or
overwritten. It creates a unique persistent directory beneath
`/var/db/cloud-installer/downloads/`, downloads `release.tar.gz`, and compares the
embedded SHA256 **before parsing/extracting or executing it**. TLS-bypass and tar
option environment overrides are cleared. Acquisition has a 64-MiB file limit in
a subshell and a fetch network timeout of 60 seconds (not an overall wall-clock
deadline); the file limit is not inherited by the installer. Extraction ignores
archived ownership/permissions and uses umask `077`. Caller cwd is preserved.

This path trusts the pinned digest and the builder-produced archive. It is not a
second implementation of the general member/expansion validator described below.
The archive and original unpacked release remain at the printed private path,
including on errors/interrupts; no download/payload is automatically deleted or
replaced. Keep that original payload for Resume/recovery, using its absolute
`install.sh` path rather than a fresh checkout.

**Confirm publication before use.** Availability is established by the
maintainer's release announcement and independently trusted digest. See the
[version-pinned installation instructions](release.md).
`--url` cannot verify publication or prove URL immutability: the publisher
must choose a versioned asset URL and the digest pins its bytes. Known mutable
latest/branch forms, credentials, query strings and fragments are refused. Never
substitute a mutable latest URL, GitHub automatic source archive or `curl | sh`.

### Standalone entrypoint with existing Python

The standalone `install.sh` recognizes a missing `installer/main.py`. Supply a
specific release-format archive and a SHA256 obtained through a trusted channel:

An entrypoint without its policy payload requires **Python already installed**:
it cannot safely authorize prerequisite bootstrap for an unknown release/architecture
before authenticating that payload. A complete reviewed checkout/extracted artifact
can still offer missing pkg/Python installation after checking its central target
policy using FreeBSD base flua. Root/platform/jail/stable-release guards remain first.

```sh
# Replace both values with an operator-reviewed artifact and its trusted digest.
ARCHIVE='/path/to/cloud-installer.tar.gz'
SHA256='REPLACE_WITH_EXACT_64_HEXADECIMAL_SHA256'
sh install.sh --archive "$ARCHIVE" --sha256 "$SHA256" install
```

An HTTPS URL is also accepted:

Archive acquisition supports explicit `install`, `configure`, `resume`, `verify`,
`backup`, `remove`, `restore`, `add-user`, `recover-install` and `recover-network`
commands, including their compatibility aliases, with the usual command arguments.
The menu, `list`, `status`, `check-updates`, `check-security`, `maintenance`,
`upgrade`, `plan` and `resolve` require an already unpacked checkout/release.
Archive acquisition always requires terminal consent,
including for `verify` and `backup`.

```sh
# PLACEHOLDERS: this document does not announce published release assets.
ARCHIVE='https://YOUR_TRUSTED_ARTIFACT_HOST/PINNED_RELEASE/cloud-installer.tar.gz'
SHA256='REPLACE_WITH_EXACT_64_HEXADECIMAL_SHA256'
sh install.sh --archive "$ARCHIVE" --sha256 "$SHA256" install
```

The canonical repository is
[theGeeBee/NextCloudOnFreeBSD](https://github.com/theGeeBee/NextCloudOnFreeBSD).
Use a reviewed, published release archive and its independently trusted digest,
or build an operator-reviewed artifact below. This guide does not announce asset
availability. No guessed version, mutable branch archive, or automatic “latest”
fallback is used. GitHub's automatic source archives have a different layout and
are not these release payloads.

Obtain the standalone entrypoint from the same reviewed source. For example,
after replacing the placeholder with a full trusted commit ID:

```sh
COMMIT='REPLACE_WITH_REVIEWED_FULL_COMMIT_ID'
fetch -o install.sh "https://raw.githubusercontent.com/theGeeBee/NextCloudOnFreeBSD/$COMMIT/install.sh"
sha256 -q install.sh
# Compare with your independently trusted entrypoint digest before executing it.
```

The bootstrap uses FreeBSD base `fetch` for HTTPS sources, or copies a local
regular file. It asks before writing the root-owned `0700` cache at
`/var/db/cloud-installer/downloads`. It verifies the supplied SHA256 **before
parsing or extracting the payload**, then checks the whole archive before
creating payload files. Only regular files and directories below
`cloud-installer/` are accepted. Absolute/traversal paths, duplicate names,
conflicting paths, symbolic/hard links, sparse files, devices and unexpected
top-level payloads are rejected. Limits are 64 MiB compressed, 256 MiB expanded
TAR, 32 MiB per file and 4096 entries. Archived ownership and permission bits are
not trusted; extracted files are private and executable bits are normalized.
The bootstrap minimum accepts older verified release payloads without newer
dashboard/update modules, preserving original-artifact resume/recovery workflows.
The current release builder still requires those modules for newly built artifacts.

A successful bootstrap prints the private release directory. Its own
`install.sh` can subsequently be invoked directly, without another download.
Supplying `--archive` explicitly always requests a fresh, verified cache entry;
it is not an application-upgrade command. Offline `plan` never downloads or
extracts archives. A digest checks integrity against the value you supplied;
trust the source of that digest and the standalone script as executable code.

## Build an operator-reviewed artifact

From a reviewed source tree, using existing Python 3.11+:

```sh
python3 tools/build-release.py --output dist/cloud-installer.tar.gz
```

Add `--url PINNED_HTTPS_RELEASE_URL` to print the base-only command above; omitting
it preserves the existing digest/output format. Invalid URLs fail before building.

This is an offline build. The output path is explicit, existing files are not
overwritten, and the SHA256 is printed for publication through your trusted
channel. The builder uses a fixed payload allowlist: installer Python modules,
named runtime resources, `install.sh`, licensing/metadata, explicitly listed public operator guides, the
public examples and the build tool. Git metadata, caches, tests, state, live
configuration, credentials and arbitrary resource files are excluded. Symlinks
in the selected payload are rejected. `PUBLIC_DOCS` in the existing builder is a
positive allowlist: new Markdown files are not included automatically. Only public
operator and technical-reference guides are selected. Required runtime resources
and original-artifact validation remain unchanged. Tests are available in the
source repository but are not needed in an installation archive.

Archive member order, modes, ownership, timestamps and the gzip header are
normalized, so the same payload yields identical bytes. It expands to one
`cloud-installer/` root with runtime `resources/` beside `installer/`; that layout
works directly without pip. `pyproject.toml` supplies Python project metadata
and the `installer.main:entrypoint` console-script contract for packaging tools;
the development metadata version is not a published release identifier.
