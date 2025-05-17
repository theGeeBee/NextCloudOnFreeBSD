#!/bin/sh

#
# Install Document Server add-on for NextCloud
# Last update: 2025-05-17
# https://github.com/theGeeBee/NextCloudOnFreeBSD/
#

# Load config settings
CONFIG_FILE="${PWD}/install.conf"

if [ -f "$CONFIG_FILE" ]; then
    . "$CONFIG_FILE"
else
    echo "Config file '$CONFIG_FILE' not found."
    exit 1
fi

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

# Check if HBSD is present in uname string
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
sudo pkg install -y linux_base-rl9

# Enable services
sysrc linux_enable="YES"

# Set linux compatibility mount points
cat "${PWD}/includes/fstab" >> /etc/fstab

# Start services
service linux start

# Document Server Community Edition
echo "Installing Document Server for Nextcloud."

# ONLYOFFICE
sudo -u www php "${WWW_DIR}/${HOST_NAME}/occ" app:install onlyoffice
sudo -u www php "${WWW_DIR}/${HOST_NAME}/occ" app:install documentserver_community

# set ONLYOFFICE to accept the self-signed certificate and point it to ${MY_IP} instead of localhost
# ${HOST_NAME} would work instead if DNS is set up correctly
sudo -u www php "${WWW_DIR}/${HOST_NAME}/occ" config:app:set onlyoffice verify_peer_off --value="true"
if [ "$USE_HOSTNAME" = "true" ]; then
    sudo -u www php "${WWW_DIR}/${HOST_NAME}/occ" config:app:set onlyoffice DocumentServerUrl --value="https://${HOST_NAME}/apps/documentserver_community/"
else
    sudo -u www php "${WWW_DIR}/${HOST_NAME}/occ" config:app:set onlyoffice DocumentServerUrl --value="https://${MY_IP}/apps/documentserver_community/"
fi
