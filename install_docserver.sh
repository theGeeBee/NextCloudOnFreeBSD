#!/bin/sh

#
# Install Document Server add-on for NextCloud
# This is untested on NC27
# Last update: 2023-07-23
# https://github.com/theGeeBee/NextCloudOnFreeBSD/
#

# Load config settings
. install.conf

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run with root privileges."
   echo "Type 'su' to switch to root and remain in this directory."
   exit 1
fi

# Check lib32 support #
if [ -d "/usr/lib32" ]; then
    lib32=true
else
    lib32=false
fi

# Check if HBSD is present in uname string ###
hbsd_test=$(uname -a | grep -o 'HBSD')

# Verify FreeBSD with lib32 support
if [ "$hbsd_test" ] || ! $lib32; then
    echo "This script can only be run on FreeBSD with lib32 support."
    exit 1
fi

# Install required packages and then start services
# Load required kernel modules
kldload linux.ko linux64.ko linprocfs.ko linsysfs.ko

# Install required packages
pkg install -y linux_base-c7

# Enable services
sysrc linux_enable="YES"

# Set linux compatibility mount points
cat fstab >> /etc/fstab

# Start services
service linux start

# Document Server Community Edition
echo "Installing Document Server for Nextcloud."

# ONLYOFFICE
sudo -u www php "${WWW_DIR}/nextcloud/occ" app:enable onlyoffice
sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install documentserver_community

# set ONLYOFFICE to accept the self-signed certificate and point it to ${MY_IP} instead of localhost
# ${HOST_NAME} would work instead if DNS is set up correctly
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set onlyoffice verify_peer_off --value="true"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set onlyoffice DocumentServerUrl --value="https://${MY_IP}/apps/documentserver_community/"
