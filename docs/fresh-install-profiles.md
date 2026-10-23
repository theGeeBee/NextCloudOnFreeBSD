# Fresh-install profiles

An instance selects one immutable document-server profile. Replacing an installed
backend, migrating between profiles or sharing an office VM is not supported.

| Choice | Resources | Example |
| --- | --- | --- |
| Native ONLYOFFICE (default) | Separate Nextcloud and ONLYOFFICE Bastille thick VNET jails | [Native recipe](../examples/config.json) |
| Euro-Office | One Nextcloud jail and one dedicated Alpine/bhyve/Docker VM | [Euro-Office recipe](../examples/eurooffice.json) |
| Collabora CODE | One Nextcloud jail and one dedicated Alpine/bhyve/Docker VM | [CODE recipe](../examples/collabora.json) |
| `none` | One Nextcloud jail, without integrated office runtime or connector | [Nextcloud-only recipe](../examples/nextcloud-only.json) |

## Validation status

The [validation matrix](verification.md) separates historical Nextcloud 35.0.1
operator-accepted artifacts from the October 23 family-selection source. The
latter passed live signed-catalog/native solver checks for all four profiles and
a fresh minimal Nextcloud-only installation, Verify, strict-TLS API/DAV and
retained-data removal. Office runtime/editing and host reboot were not repeated
on that source; historical results must not be presented as those reruns.

These bounded results do not certify every optional app, physical hosts or full
maintenance/recovery. Dated source-review entries in `resources/versions.json`
describe evidence available when each policy entry was reviewed, not a current
acceptance ledger. Offline tests alone do not prove native operation.

## Resource and security boundaries

Each integrated instance uses separate private Nextcloud/office networks with
host PF routing and restricted frontend/callback traffic. VM provisioning SSH is
private and key-only; no public Docker API or VM SSH listener is exposed.
Instance identity, package locks, datasets and retained runtime source are checked
before mutation. Secrets are sent only to the relevant phase over protected
channels, never copied as a complete host credential bundle.

VM profiles require usable bhyve virtualization and at least 2 vCPU, 4096 MiB RAM
and a 16-GiB guest disk, in addition to the Nextcloud jail and host reserve. These
are project allocation floors, not upstream workload-capacity guarantees.
Signed Alpine repositories, OpenRC startup, pinned container identities,
persistent volumes and bounded logs are used. Container updates are not automatic.

Euro-Office uses the `eurooffice` connector, JWT and the public `/eurooffice/`
path. Its container includes database/queue services unlike native ONLYOFFICE 9.4.
CODE uses `richdocuments`, strict WOPI/TLS trust, native proof keys and the public
`/collabora/` path. No embedded `richdocumentscode` server is selected.

The `none` profile allocates no office VM/jail, office network, office connector,
office font deployment or office plugins. Transitive Nextcloud dependencies may
include font libraries. An upstream Nextcloud Office overview menu can still be present;
that is not an integrated document server. Manually configuring an external
server later is outside installer-managed integration.

## Maintenance and recovery

Native-only upgrade, maintenance assessment and database/configuration
backup/restore contracts do not support VM or `none` profiles. Arrange independent
administrator-managed backups and maintenance for these profiles. Unsaved editor
state is not durable data. Keep original artifacts, immutable version/configuration
records and private recovery evidence. Never patch retained resources to force Resume.

See [operations](operations.md), [version policy](versions.md),
[TLS/proxy setup](reverse-proxy.md) and [troubleshooting](troubleshooting.md).
