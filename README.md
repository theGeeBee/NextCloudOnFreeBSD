# NextCloud on FreeBSD
Script to automate installation of Nextcloud on FreeBSD

## Instructions

1. Clone repository or download release to your machine and extract
2. `cd` to folder as root
3. Open install.sh with your favourite editor
4. Change the values of variables as required to suite your environment
5. Save the file
6. Run `install.sh` as root
7. Please be patient while the script runs
8. Done

**Installs the following:**

* Apache 2.4
* MySQL 8.0
* PHP 8.0
* ClamAV
* Nextcloud 23

*Note: **Nextcloud 24** does not yet support Community Document Server*
*For full list, see `requirements.txt`*

------------

## Configuration

* HTTP/2
* SSL Enabled, TLS1.2+ only
* HSTS Enabled
* Linux partitions mounted
* PHP Memory Caching APCu

### NextCloud Apps Installed/Activated

* Community Document Server
* OnlyOffice
* Antivirus for Files
* Calendar
* Contacts
* Deck
* Mail
* Notes
* Nextcloud Talk
* Tasks
* External storage support (Including `samba` shares)
