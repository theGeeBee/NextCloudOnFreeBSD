# Acknowledgments and third-party notices

NextCloudOnFreeBSD is an independent integration project. Names and trademarks
belong to their respective owners; listing them does not imply endorsement.
The installer's [BSD 3-Clause License](../LICENSE) does not relicense third-party
software, fonts, plugins or container contents.

## Core platform and application stack

| Project | Role | Upstream |
| --- | --- | --- |
| FreeBSD | Host, jails, PF and base utilities | https://www.freebsd.org/ |
| OpenZFS | Datasets and snapshots through FreeBSD ZFS | https://openzfs.org/ |
| BastilleBSD | Thick VNET jail management | https://bastillebsd.org/ |
| Nextcloud | File collaboration server and selected apps | https://nextcloud.com/ |
| Python | Host orchestration and standard-library tooling | https://www.python.org/ |
| Apache HTTP Server | Nextcloud web server and office reverse proxy | https://httpd.apache.org/ |
| PHP | Nextcloud runtime, using PHP-FPM | https://www.php.net/ |
| MariaDB | Nextcloud database | https://mariadb.org/ |
| Redis | Nextcloud cache and locking | https://redis.io/ |

## Optional integrations

| Project | When used | Upstream |
| --- | --- | --- |
| ClamAV | Selected antivirus integration | https://www.clamav.net/ |
| Let's Encrypt / Certbot | ACME HTTP-01 TLS mode | https://letsencrypt.org/ · https://certbot.eff.org/ |
| ONLYOFFICE Docs | Default native document-server profile and its connector | https://www.onlyoffice.com/ |
| Euro-Office | Selected document-server container and connector | https://github.com/euro-office |
| Collabora Online CODE | Selected document-server container and Nextcloud `richdocuments` connector | https://www.collaboraonline.com/code/ |
| bhyve / vm-bhyve | Dedicated VM for Euro-Office or CODE | https://bhyve.org/ · https://github.com/freebsd/vm-bhyve |
| Alpine Linux | Minimal guest OS for VM profiles | https://alpinelinux.org/ |
| Docker / Moby | Container engine inside the Alpine guest, never on the FreeBSD host | https://www.docker.com/ · https://mobyproject.org/ |
| nginx / Supervisor | Native ONLYOFFICE frontend and service supervision | https://nginx.org/ · https://supervisord.org/ |

Other dependencies, selected Nextcloud apps, font families and ONLYOFFICE plugins
are identified in the version policy, package inventory and plugin catalog.
See [fonts](fonts.md) and [plugins](onlyoffice-plugins.md). The native
ONLYOFFICE package requires explicit consent to the Microsoft webfonts EULA;
custom fonts require appropriate redistribution and usage rights.

This source release contains integration code, templates and catalogs, not a
redistribution of the upstream application binaries or container images. Packages,
applications and images are acquired separately during approved installation.
Keep their supplied copyright/license notices and comply with the terms of the
exact selected versions, including any source-offer or source-availability duties
when redistributing or modifying them. Redis and other upstream licensing can
vary by version; this document is not a substitute for those licenses.

## Project contributors

Copyright (c) 2022, Gibran Khan; the original BSD notice is preserved unchanged
in `LICENSE`. Thanks to all contributors whose work remains recorded in the
public Git history. In particular, Pavel Knoblokh (@Pashugan) contributed PHP
timezone, OPcache memory, notification sender, MariaDB compatibility, TLS session
cache and typed Nextcloud settings improvements (PRs #18 and #20–24). Bui Anh
Tuan (@johndo100) contributed external reverse-proxy TLS support and jail-aware
pre-install handling (PR #11). The redesigned implementation reworks or
supersedes some of these historical behaviors; these credits do not imply
review or endorsement of the current release.
