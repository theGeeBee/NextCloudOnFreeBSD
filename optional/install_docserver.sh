#!/bin/sh

###
# Install Document Server add-on for NextCloud
# Tested on:
# ----------
# 1. FreeBSD 12+
# Last update: 2022-06-07
# https://github.com/theGeeBee/NextCloudOnFreeBSD/
###

MY_IP="10.0.0.10" ## set to the same IP as Nextcloud

### Check for root privileges
if ! [ $(id -u) = 0 ]; then
   echo "This script must be run with root privileges."
   echo "Type in \`su\` to switch to root and remain in this directory."
   exit 1
fi

### HardenedBSD Block
###
r_uname="`uname -r`"
hbsd_test="HBSD"

### lib32 test
###
if [ -d "/usr/lib32" ]
	then
		lib32="true"
	else
		lib32="false"
fi

if test "${r_uname#*$hbsd_test}" != "${r_uname}" # If HBSD is found in uname string
    then
	    hbsd_test="true"
    else 
	    hbsd_test="false"
fi 

if ($hbsd_test == "true" || $lib32 == "false")
    then
        echo "This script can only be run on FreeBSD with lib32 support."
        exit 1
fi

### Install required packages and then start services
### Load required kernel modules

kldload linux.ko linux64.ko linprocfs.ko linsysfs.ko

### Install required packages

pkg install -y linux_base-c7

### Enable services

sysrc linux_enable="YES"

### Set linux compatibility mount points
cat fstab >> /etc/fstab

### Start services

service linux start

### Document Server Community Edition

echo "Installing Document Server for Nextcloud."
### ONLYOFFICE
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:enable onlyoffice
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install documentserver_community

	# set ONLYOFFICE to accept the self-signed certificate and point it to ${MY_IP} instead of localhost
	# ${HOST_NAME} would work instead if DNS is set up correctly
	sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:app:set onlyoffice verify_peer_off --value="true"
	sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:app:set onlyoffice DocumentServerUrl --value="https://${MY_IP}/apps/documentserver_community/"