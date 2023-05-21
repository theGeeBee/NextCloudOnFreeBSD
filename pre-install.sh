#!/bin/sh

### Check for root privileges
if ! [ "$(id -u)" = 0 ]; then
   echo "This script must be run with root privileges."
   exit 1
fi

### Create Boot Environment
###
echo "Creating Boot Environment for Nextcloud"
bectl create nextcloud
bectl activate nextcloud

### Reboot the system
echo "
Next steps:
-----------

1. Reboot the system
2. su - again and edit the variables in install.sh
4. run install.sh

That should be it.
Please log a ticket on the github page should you have any issues"
