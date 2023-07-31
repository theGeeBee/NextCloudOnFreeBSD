# NextCloud on FreeBSD
Script to automate installation of Nextcloud on: FreeBSD13+, HardenedBSD13
The finished installation passes all nextcloud configuration checks.

## Instructions

1. Clone repository or download release to your machine and extract
2. `cd` to folder as root
3. Run `pre_install.sh` as root to create a boot environment and config file before installing, then reboot before moving on
5. Open `install.conf` with your favourite editor
6. Change the values of variables as required to suite your environment
7. Save the file
9. Run `install.sh` as root
10. Please be patient while the script runs
11. Done

**Installs the following:**

* Nextcloud 27
* Apache 2.4
* MariaDB 10.6
* PHP 8.2 (php-fpm)
* Redis
* ClamAV

------------

## Configuration

* HTTP/2 over TLS
* TLS1.3 only
* HSTS Enabled
* PHP with APCu enabled (for fi

### NextCloud Apps Installed/Activated by default in config

* Antivirus for Files
* Calendar
* Contacts
* Deck
* Mail
* Notes
* Nextcloud Talk
* Tasks
* External storage support (including `samba` and `ftp`) (Can be disabled independently)
  
