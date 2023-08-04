# NextCloud on FreeBSD

Script to automate installation of Nextcloud on FreeBSD13+ and HardenedBSD13.
The finished installation passes all nextcloud configuration checks.
This script follows recommended configuration as per https://docs.nextcloud.com/server/stable/admin_manual/installation/system_requirements.html

## Instructions

1. Clone repository or download release to your machine and extract.
2. `cd` to folder.
3. Switch to root by using `su`.
4. Run `pre_install.sh` as root to create a boot environment and config file before installing, then reboot before moving on.
5. `su` again after rebooting, and `cd` to the folder.
6. Open `install.conf` with your favourite editor.
   (Note: see https://www.php.net/manual/en/timezones.php for your time zone)
7. Change the values of variables as required to suite your environment.
8. Save the file.
9. Run `install.sh`
10. Please be patient while the script runs
11. Done

**Installs the following:**

* Nextcloud 27
* Apache 2.4
* MariaDB 10.6
* PHP 8.2 (plus all php-extensions required)
* Redis
* ClamAV

------------

## Configuration

* Apache 2.4 + PHP using `php-fpm`
* HTTP/2 over TLS
* TLS1.3 only
* HSTS enabled
* APCu enabled
* Redis enabled (allows transactional file locking)

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
  
