# NextCloud on FreeBSD
Script to automate installation of Nextcloud on: FreeBSD13+, HardenedBSD13

## Instructions

1. Clone repository or download release to your machine and extract
2. `cd` to folder as root
3. Run `pre_install.sh` as root to create a boot environment before installing, then reboot (or restart jail) before moving on
5. Open `install.conf` with your favourite editor
6. Change the values of variables as required to suite your environment
   - note: if you wish to use a hostname instead of an IP address, uncomment line 184 of `install.sh`
7. Save the file/s
9. Run `install.sh` as root
10. Please be patient while the script runs
11. Done

**Installs the following:**

* Apache 2.4
* MariaDB 10.6
* PHP 8.2
* ClamAV
* Nextcloud 27

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
  
