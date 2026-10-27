# Nextcloud on FreeBSD

A terminal installer for Nextcloud on FreeBSD. It sets up application services,
ZFS storage, private networking and HTTPS, with multiple instances on one host.

Choose an office backend when installing:

- **ONLYOFFICE** (default): Nextcloud and native ONLYOFFICE in separate Bastille VNET jails.
- **Euro-Office** or **Collabora CODE**: one Nextcloud jail and a dedicated Alpine Linux VM running Docker under bhyve.
- **Nextcloud only**: one jail, without an office server or connector.

The backend cannot be changed after installation. The current release is a prerelease.

## Requirements

- FreeBSD **15.1-RELEASE amd64**, a healthy ZFS pool and root access outside a jail.
- A clean jail/firewall host, or one already managed by this installer.
- Static IPv4, working DNS, package repository access and a public HTTPS hostname.
- Enough memory and storage for the selected services; **16 GiB RAM or more** is recommended for default selections.
- For VM backends, working bhyve hardware or nested virtualization.
- An interactive terminal, console recovery access and a second SSH session.

HTTPS can use Let's Encrypt, supplied certificates or an external reverse proxy.
Direct HTTPS requires matching IPv4 DNS and no AAAA record.
Host OS updates and backups remain your responsibility.

## Install

For a fresh installation, run the command on the
[release page](https://github.com/theGeeBee/NextCloudOnFreeBSD/releases/tag/v2026.10.27)
as root on the destination host.

If you already have the installer locally, run from its directory:

```sh
sh install.sh install
```

The wizard asks for storage, networking, HTTPS and application settings.
It offers to install missing pkg/Python prerequisites with your consent.
Native ONLYOFFICE also requires consent to the Microsoft webfonts licence.

Review the plan and type `APPLY`. When prompted, open a second SSH session,
confirm connectivity and enter `KEEP` before the displayed deadline.
Installation requires your attendance.

Add `--plain` for numbered text prompts.

To use a JSON recipe instead, copy the matching file from `examples/`, edit it
for your host and run:

```sh
cp examples/config.json settings.json
chmod 600 settings.json
vi settings.json
sh install.sh install --config settings.json
```

Keep the recipe root-owned and private. Do not put passwords or private keys in it.

## After installation

Open the displayed HTTPS address. Generated credentials are stored privately in:

```text
/var/db/cloud-installer/instances/INSTANCE/secrets.json
```

Keep that file private, and retain the installer directory.

```sh
sh install.sh                 # Open the menu; requires existing Python 3.11+
sh install.sh list
sh install.sh status INSTANCE
sh install.sh add-user INSTANCE
sh install.sh resume INSTANCE
sh install.sh --help
```

Replace `INSTANCE` with your instance name. Resume requires the same installer
and unchanged saved configuration. If an operation stops, follow its recovery
message before retrying.
