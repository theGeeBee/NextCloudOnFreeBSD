#!/bin/sh

# Check for root privileges
if ! [ "$(id -u)" = 0 ]; then
   echo "This script must be run with root privileges."
   exit 1
fi

#
# Copy the default config, ready for editing, and pre-populate the IP address
cp install.conf.sample install.conf
ip_address=$(ifconfig | sed -n '/.inet /{s///;s/ .*//;p;}' | head -1)
sed -i '' "s|IP_ADDRESS_VALUE|${ip_address}|" install.conf

#
# Create Boot Environment
#
echo "Creating Boot Environment for Nextcloud"
bectl create nextcloud
bectl activate nextcloud

echo "
Next steps:
-----------

1. Reboot the system
2. su - again and edit the variables in install.sh
4. run install.sh

That should be it.
Please log a ticket on the github page should you have any issues"
