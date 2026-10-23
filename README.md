# NextCloudOnFreeBSD

Install and manage isolated Nextcloud instances on a **FreeBSD 15.1-RELEASE
amd64 ZFS host**, with an optional integrated document server. A guided terminal
installer reviews settings, resolves compatible packages and asks for approval
before making changes.

**Legacy users:** existing `install.conf`, host-service deployments and bundled
Document Server installations are not imported, migrated or upgraded. Retain
their original installer and arrange a separately reviewed migration.

## Features and architecture

- Nextcloud runs in a Bastille thick VNET jail with Apache HTTP Server, PHP-FPM,
  MariaDB and Redis. Optional apps include antivirus integration with ClamAV.
- Choose native ONLYOFFICE in a separate jail, Euro-Office or Collabora CODE in a
  dedicated Alpine Linux/bhyve/Docker VM, or Nextcloud without a document server.
- Multiple instances have separate private networks, storage and credentials;
  shared host PF rules provide routing, NAT and isolation.
- Reviewed version policy, immutable installation records, resumable phases,
  explicit recovery commands and timed network confirmation protect deployments.
- TLS supports Let's Encrypt, supplied certificates or a trusted external HTTPS
  reverse proxy. No pip dependencies or Bash are required.

## Requirements

- Root access outside a jail on **FreeBSD 15.1-RELEASE amd64**, with a matching
  updated kernel and a healthy existing ZFS pool. Pool creation and host OS
  maintenance are administrator responsibilities.
- **8 GiB RAM minimum without antivirus; 16 GiB or more recommended** for default
  selections. ClamAV adds a 3-GiB planning allowance. Reserve memory for the host
  and ZFS ARC; multiple instances require aggregate capacity.
- Space for jail bases, packages, application/database data, user files, caches
  and snapshots. Comprehensive fonts can add several GiB. VM profiles additionally
  allocate at least **2 vCPU, 4096 MiB RAM and a 16-GiB guest disk**, plus Nextcloud
  and host resources; 8 GiB is not enough for their default configuration.
- An initially clean jail/firewall host, or one already managed by this installer.
  Unrelated jails, VMs and firewall configurations are not adopted.
- Static host IPv4, working DNS/package access, unused private networks and
  ingress ports, an explicit management CIDR and SSH port, console recovery access
  and a second SSH session for network confirmation.
- A public HTTPS hostname. Direct TLS requires matching IPv4 DNS and no AAAA
  record; external HTTPS proxies may serve IPv6 with a restricted private HTTP
  backend. VM profiles also require usable bhyve virtualization/second-level paging.

See [version policy](docs/versions.md), [network/TLS setup](docs/reverse-proxy.md)
and [storage and operations](docs/operations.md) before installation.

## Install

**Clean host without Git, Bash or Python:** use the FreeBSD-base-only command
generated for a reviewed, version-pinned release archive. It downloads with
`fetch`, verifies SHA256 before extraction, retains the payload and starts the
existing installer. See [release installation instructions](docs/release.md)
and the [distribution guide](docs/distribution.md#no-clone-installation) for
artifact availability and verification.

From a reviewed checkout or verified, extracted release, run as root in an
interactive terminal on the destination host:

```sh
sh install.sh install
```

Missing `pkg` and Python 3.11+ are offered with consent. Bastille and deployment
prerequisites follow plan review. The wizard collects host-specific settings;
review them and type **APPLY**. After each PF transition, test a second SSH session
and enter **KEEP** within the displayed deadline. There is no unattended bypass.
Native ONLYOFFICE requires separate Microsoft webfonts license consent.

With Python already available, `sh install.sh` opens the instance menu. Use
`sh install.sh --plain` for numbered prompts. Common commands:

```sh
sh install.sh list
sh install.sh status INSTANCE
sh install.sh verify INSTANCE
sh install.sh resume INSTANCE
sh install.sh add-user INSTANCE
```

For reusable settings, copy an [example](examples/config.json), restrict it with
`chmod 600`, and edit all destination-specific values. Do not put passwords or
private keys in JSON. Review a static plan with existing Python:

```sh
sh install.sh plan settings.json
sh install.sh install --config settings.json
```

Planning also works on Linux without probing or changing the host. See the
[configuration guide](docs/configuration.md) and
[full command reference](docs/distribution.md#commands).

Fresh installs resolve stable compatible releases within supported families and
all configured constraints. An optional recipe entry can narrow those families:

```json
"version_families": {"nextcloud": "35", "php": "8.5", "database": "12.3"}
```

This is an entry in a complete recipe, not a standalone configuration. A family
is **not certification of every exact combination**. Minima, exact pins, signed
catalogs, dependency checks and immutable locks still apply; Resume never
reselects. See [family selection and defaults](docs/versions.md#optional-fresh-install-family-selection).

## Document server choices and validation

| Choice | Layout |
| --- | --- |
| ONLYOFFICE (default) | Two separate Bastille jails |
| Euro-Office | Nextcloud jail + dedicated Alpine VM |
| Collabora CODE | Nextcloud jail + dedicated Alpine VM |
| `none` | Nextcloud jail only |

Historical Nextcloud 35.0.1 artifacts received bounded operator acceptance,
including office editing and VM-profile reboot checks. On October 23, all four
profiles passed real signed-catalog/native solver checks with Nextcloud 35.0.2;
a fresh Nextcloud-only installation also passed Verify, strict-TLS API/DAV and
retained-data removal checks. Office runtime, reboot and recovery were **not
rerun on that family-selection source**. See the [validation matrix](docs/verification.md)
for the exact distinction and remaining limits.

These are limited integration results, **not production certification** or a
complete recovery test matrix. No native tests were run for this documentation
refresh. Profiles cannot be switched after installation. Native-only upgrade and
database/configuration backup/restore contracts do not extend to VM or `none`
profiles. See [profile details](docs/fresh-install-profiles.md).

## Limitations and recovery

FreeBSD is not an upstream-listed Nextcloud server OS. Assess support,
availability, capacity and independent backups before using this on important data.
Physical-host compatibility and complete maintenance/recovery acceptance remain
unverified. Experimental maintenance execution remains guarded.

Retain the **original extracted installer** and private host records for Resume
and recovery. Do not replace an enrolled installation's artifact or edit its
immutable configuration. On interruption, inspect status and use the documented
`recover-network`, `recover-install` or Resume workflow; do not reset state manually.
Database/configuration backups exclude user file contents and are **not full
disaster recovery**. The optional native upgrade assistant has a narrow reviewed
scope and offers restoration only by explicit operator choice.

## Documentation

- [Installation, commands and distribution](docs/distribution.md)
- [Operations and readiness limitations](docs/operations.md)
- [Validation matrix](docs/verification.md) · [Troubleshooting](docs/troubleshooting.md)
- [Backup and restore](docs/backup-restore.md) · [Native upgrades](docs/upgrade.md)
- [Jail isolation](docs/jails.md) · [PF recovery](docs/firewall-transactions.md)
- [Fonts and license consent](docs/fonts.md) · [Jail SSH](docs/ssh.md)
- [Release candidate notes](docs/release.md)

## Offline tests

With Python 3.11+ available, run `python3 -m unittest discover -s tests -v`.
The regression suite uses temporary fixtures and mocked host operations; it does
not provision a server. Native installation and recovery need separate,
explicitly approved testing on a disposable FreeBSD host.

## License and acknowledgments

The installer is licensed under the [BSD 3-Clause License](LICENSE).
Upstream applications, fonts and plugins retain their own licenses and terms.
See [third-party acknowledgments](docs/third-party-notices.md) for the projects and
contributors that make this integration possible. No upstream endorsement is implied.
