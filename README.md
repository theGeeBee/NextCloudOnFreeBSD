# NextCloud on FreeBSD
Script to automate installation of Nextcloud on: FreeBSD12+, Truenas CORE 12 + (in a base jail), HardenedBSD13
This is very much a work in progress, this script will change constantly as I get everything I want integrated in the best possible way.

## Instructions

01. Clone repository or download release to your machine and extract
02. `cd` to folder as root
03. Open install.sh with your favourite editor
04. Change the values of variables as required to suite your environment
05. Save the file
06. Run `pre_install.sh` as root to create a boot environment before installing, then reboot (or restart jai) before moving on
07. Run `install.sh` as root
08. Please be patient while the script runs
09. Done
10. Optional: run `optional/install_docserver.sh` if you wish to have the integrated Community Document Server running (FreeBSD only) (Requires OnlyOffice)

**Installs the following:**

* Apache 2.4
* MySQL 8.0
* PHP 8.1
* ClamAV
* Nextcloud 26

------------

## Configuration

* HTTP/2
* SSL Enabled, TLS1.3 only
* HSTS Enabled
* PHP with APCu enabled
* Redis installed and enabled

### NextCloud Apps Installed/Activated

* Antivirus for Files
* Calendar
* Contacts
* Deck
* Mail
* Notes
* Nextcloud Talk
* Tasks
* External storage support (including `samba` and `ftp`)
* OnlyOffice is disabled by default.

### Optional Scripts (this doesn't work, fix in progress)

* `install_docserver.sh` will install the Community Document Server plugin on Nextcloud (FreeBSD only) and configure Onlyoffice accordingly.
