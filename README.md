# NextCloud on FreeBSD
Script to automate installation of NextCloud on FreeBSD

Installs the following:

* Apache 2.4
* MySQL 8.0
* PHP 8.0
* ClamAV
* Linux Compatibility Layer
* NextCloud

------------

## Configuration

* HTTP/2
* SSL Enabled, TLS1.2+ only
* Linux partitions mounted
* PHP Memory Caching APCu

### NextCloud Apps Pre-Installed

* Community Document Server
* OnlyOffice
* Antivirus for Files

------------

#### Notes for post-installation:

##### ONLYOFFICE

After installing using default settings with self-signed certificate, under ONLYOFFICE settings, change server address to IP address and disable certificate verification.

##### Anti-Virus for Files

To get things working immediately, set the following under SETTINGS -> SECURITY

**Mode:** ClamAV Executable
**Path to Clamscan:** /usr/local/bin/clamscan
