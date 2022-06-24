#!/bin/sh

###
# Install Nextcloud on FreeBSD (and derivatives)
# Tested on:
# ----------
# 1. FreeBSD 12.3 13.0 13.1
# 2. HardenedBSD 13-STABLE (Build 470+)
# 3. TrueNAS CORE 13 (in base jail)
# Last update: 2022-06-24
# https://github.com/theGeeBee/NextCloudOnFreeBSD/
###

#############################################
###            START OF CONFIG            ###
#############################################

### All fields are required

### Common settings
###
MY_USERNAME="nextcloud-admin" # This is a username that will be used for the Nextcloud Web UI
HOST_NAME="nextcloud.my.domain" # Advisory: set to the same as your DNS entry
MY_IP="10.0.0.10"
MY_EMAIL="${MY_USERNAME}@${HOST_NAME}"
SERVER_EMAIL="nextcloud-alert" # will have ${HOST_NAME} automatically appened, used to send out alerts from the server by `sendmail`
NEXTCLOUD_VERSION="24" # The integrated document_server app does not yet work on v24+
WWW_DIR="${WWW_DIR}"

### Settings for Nextcloud, logging, and openSSL:
###
COUNTRY_CODE="XW" # Example: US/UK/CA/AU/DE, etc.
TIME_ZONE="UTC" # See: https://www.php.net/manual/en/timezones.php

### Nextcloud settings
###
ADMIN_USERNAME="admin"
ADMIN_PASSWORD=$(openssl rand -base64 12)
DATA_DIRECTORY="/mnt/nextcloud_data" ## Please use something like /path/to/zfs/dataset/ - and use the script to create a subdirectory for NC data 

### mySQL setttings
###
DB_ROOT_PASSWORD=$(openssl rand -base64 16)
DB_USERNAME="nextcloud"
DB_PASSWORD=$(openssl rand -base64 16)
DB_NAME="nextcloud" 


#############################################
###             END OF CONFIG             ###
#############################################


### Check for root privileges
###
if ! [ $(id -u) = 0 ]; then
   echo "This script must be run with root privileges."
   echo "Type in \`su\` to switch to root and remain in this directory."
   exit 1
fi

### HardenedBSD Check (if there's a better way, please let me know!)
###
r_uname="`uname -r`"
hbsd_test="HBSD"

if test "${r_uname#*$hbsd_test}" != "${r_uname}" # If HBSD is found in uname string
then
	hbsd_test="true"
else 
	hbsd_test="false"
fi 

### Set `sysctl` values (necessary for `redis`)
###
sysctl kern.ipc.somaxconn=1024
echo "kern.ipc.somaxconn=1024" >> /etc/sysctl.conf

### Set `pkg` to use LATEST (optional)
###
mkdir -p /usr/local/etc/pkg/repos
echo "FreeBSD: { enabled: no }" > /usr/local/etc/pkg/repos/FreeBSD.conf
cp /etc/pkg/FreeBSD.conf /usr/local/etc/pkg/repos/nextcloud.conf
sed -i '' "s|quarterly|latest|" /usr/local/etc/pkg/repos/nextcloud.conf

### Install `pkg`, update repository, upgrade existing packages
###
echo "Installing pkg and updating repositories"
pkg bootstrap -y
pkg update
pkg upgrade -y

### Install required packages
###
cat includes/requirements.txt | xargs pkg install -y

### Update virus definitions
###
freshclam

### Enable services
###
sysrc sendmail_enable="YES"
sysrc clamav_clamd_enable="YES"
sysrc clamav_freshclam_enable="YES"
sysrc apache24_enable="YES"
sysrc mysql_enable="YES"
sysrc php_fpm_enable="YES"
sysrc redis_enable="YES"

### Start services
###
service sendmail start
service clamav-clamd onestart
service redis start
apachectl start
service mysql-server start
service php-fpm start

### Update virus definitions again to report update to daemon
###
freshclam --quiet

### Add user `www` to group `redis`
###
pw usermod www -G redis

### Download and verify Nextcloud
###
FILE="latest-${NEXTCLOUD_VERSION}.tar.bz2"
if ! fetch -o /tmp https://download.nextcloud.com/server/releases/"${FILE}" https://download.nextcloud.com/server/releases/"${FILE}".asc https://nextcloud.com/nextcloud.asc
then
	echo "Failed to download Nextcloud"
	exit 1
fi
gpg --import /tmp/nextcloud.asc
if ! gpg --verify /tmp/"${FILE}".asc
then
	echo "GPG Signature Verification Failed!"
	echo "The Nextcloud download is corrupt."
	exit 1
fi

### Extract Nextcloud and give `www` ownership of the directory
###
tar xjf /tmp/"${FILE}" -C ${WWW_DIR}/
chown -R www:www ${WWW_DIR}/nextcloud

### Create self-signed SSL certificate
###
OPENSSL_REQUEST="/C=${COUNTRY_CODE}/CN=${HOST_NAME}"
openssl req -x509 -nodes -days 3652 -sha512 -subj $OPENSSL_REQUEST -newkey rsa:2048 -keyout /usr/local/etc/apache24/server.key -out /usr/local/etc/apache24/server.crt

### Copy pre-writting config files and edit in place
###
cp -f "${PWD}"/includes/php.ini /usr/local/etc/php.ini
sed -i '' "s|MYTIMEZONE|${TIME_ZONE}|" /usr/local/etc/php.ini
### Disable PHP Just-in-Time compilation for HardenedBSD support
if $hbsd_test == "true"
	then
		sed -i '' "s|pcre.jit=1|pcre.jit=0|" /usr/local/etc/php.ini
	fi
cp -f "${PWD}"/includes/www.conf /usr/local/etc/php-fpm.d/
cp -f "${PWD}"/includes/redis.conf /usr/local/etc/redis.conf
cp -f "${PWD}"/includes/httpd.conf /usr/local/etc/apache24/
sed -i '' "s|MY_IP|${MY_IP}|" /usr/local/etc/apache24/httpd.conf
cp -f "${PWD}"/includes/nextcloud.conf /usr/local/etc/apache24/Includes/
cp -f "${PWD}"/includes/030_php-fpm.conf /usr/local/etc/apache24/modules.d/
cp -f "${PWD}"/includes/php-fpm.conf /usr/local/etc/

### Restart Services for modified configuration to take effect
###
apachectl restart
service php-fpm restart
service redis restart

### Create Nextcloud log directory
###
mkdir -p /var/log/nextcloud/
chown www:www /var/log/nextcloud

### Create NextCloud data directory
###
mkdir -p "${DATA_DIRECTORY}"
chown www:www "${DATA_DIRECTORY}"

### Create mySQL database
### Secure database, set mysql root password, create Nextcloud DB, user, and password
###
mysql -u root -e "CREATE DATABASE ${DB_NAME};"
mysql -u root -e "CREATE USER '${DB_USERNAME}'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY '${DB_PASSWORD}';"
mysql -u root -e "GRANT ALL ON nextcloud.* TO 'nextcloud'@'localhost';"
mysql -u root -e "DELETE FROM mysql.user WHERE User='';"
mysql -u root -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -u root -e "DROP DATABASE IF EXISTS test;"
mysql -u root -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
mysqladmin --user=root password "${DB_ROOT_PASSWORD}" reload

### The next two lines allow `root` to login to mysql> without a password
###
cp -f ${PWD}/includes/my.cnf /root/.my.cnf 
sed -i '' "s|MYPASSWORD|${DB_ROOT_PASSWORD}|" /root/.my.cnf 

### Create reference file
###
cat >> /root/${HOST_NAME}_reference.txt <<EOL
Nextcloud installation details:
===============================

Server address : https://${HOST_NAME} or https://${MY_IP}
Data directory : ${DATA_DIRECTORY}

Login Information:
------------------
Username : ${ADMIN_USERNAME}
Password : ${ADMIN_PASSWORD}

Database Information:
---------------------
Database name       : ${DB_NAME}
Database username   : ${DB_USERNAME}
Database password   : ${DB_PASSWORD}
mySQL root password : ${DB_ROOT_PASSWORD}

EOL

### CLI installation and configuration of Nextcloud
###
sudo -u www php ${WWW_DIR}/nextcloud/occ maintenance:install --database="mysql" --database-name="${DB_NAME}" --database-user="${DB_USERNAME}" --database-pass="${DB_PASSWORD}" --database-host="localhost" --admin-user="${ADMIN_USERNAME}" --admin-pass="${ADMIN_PASSWORD}" --data-dir="${DATA_DIRECTORY}"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set mysql.utf8mb4 --type boolean --value="true"
sudo -u www php ${WWW_DIR}/nextcloud/occ db:add-missing-primary-keys
sudo -u www php ${WWW_DIR}/nextcloud/occ db:add-missing-indices
sudo -u www php ${WWW_DIR}/nextcloud/occ db:add-missing-columns
sudo -u www php ${WWW_DIR}/nextcloud/occ db:convert-filecache-bigint --no-interaction
sudo -u www php ${WWW_DIR}/nextcloud/occ maintenance:mimetype:update-db
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set logtimezone --value="${TIME_ZONE}"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set default_phone_region --value="${COUNTRY_CODE}"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set log_type --value="file"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set logfile --value="/var/log/nextcloud/nextcloud.log"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set loglevel --value="2"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set logrotate_size --value="104847600"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set filelocking.enabled --value=true
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set memcache.local --value="\OC\Memcache\APCu"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set redis host --value="/var/run/redis/redis.sock"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set redis port --value=0 --type=integer
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set memcache.distributed --value="\OC\Memcache\Redis"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set memcache.locking --value="\OC\Memcache\Redis"
### Uncomment the following lines only if DNS works properly on your network.
#sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set overwritehost --value="${HOST_NAME}"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set overwrite.cli.url --value="https://${MY_IP}"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set overwriteprotocol --value="https"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set htaccess.RewriteBase --value="/"
sudo -u www php ${WWW_DIR}/nextcloud/occ maintenance:update:htaccess
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set trusted_domains 0 --value="${MY_IP}"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set trusted_domains 1 --value="${HOST_NAME}"

### Set Nextcloud to use sendmail (you can change this later in the GUI)
###
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set mail_smtpmode --value="sendmail"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set mail_sendmailmode --value="smtp"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set mail_domain --value="${HOST_NAME}"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:system:set mail_from_address --value="${SERVER_EMAIL}"

### Enable external storage support (Example: mount a SMB share in Nextcloud)
### Users are allowed to mount external storage, but can be disabled under Settings -> Admin -> External Storage
###
sudo -u www php ${WWW_DIR}/nextcloud/occ app:enable files_external
sudo -u www php ${WWW_DIR}/nextcloud/occ config:app:set files_external allow_user_mounting --value="yes"
sudo -u www php ${WWW_DIR}/nextcloud/occ config:app:set files_external user_mounting_backends --value="ftp,dav,owncloud,sftp,amazons3,swift,smb,\\OC\\Files\\Storage\\SFTP_Key,\\OC\\Files\\Storage\\SMB_OC"

### Install Nextcloud Apps
### Featured Apps (alphabetical)
###
clear
echo "Nextcloud is now installed, installing recommended Apps..."
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install calendar
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install contacts
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install deck
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install mail
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install notes
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install spreed # Nextcloud Talk
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install tasks

### Antivirus for Files
###
clear
echo "Now installing and configuring Antivirus for File using ClamAV..."
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install files_antivirus
	### set correct value for path on FreeBSD and set default action
	sudo -u www php ${WWW_DIR}/nextcloud/occ config:app:set files_antivirus av_mode --value="socket"
	sudo -u www php ${WWW_DIR}/nextcloud/occ config:app:set files_antivirus av_socket --value="/var/run/clamav/clamd.sock"
	sudo -u www php ${WWW_DIR}/nextcloud/occ config:app:set files_antivirus av_stream_max_length --value"104857600"
	sudo -u www php ${WWW_DIR}/nextcloud/occ config:app:set files_antivirus av_infected_action --value="only_log"
	sudo -u www php ${WWW_DIR}/nextcloud/occ config:app:set activity notify_notification_virus_detected --value="1"

### ONLYOFFICE
###
clear
echo "Now installing OnlyOffice (will be disabled by default)..."
sudo -u www php ${WWW_DIR}/nextcloud/occ app:install --keep-disabled onlyoffice

### SERVER SIDE ENCRYPTION 
### Server-side encryption makes it possible to encrypt files which are uploaded to this server.
### This comes with limitations like a performance penalty, so enable this only if needed.
###
# sudo -u www php ${WWW_DIR}/nextcloud/occ app:enable encryption
# sudo -u www php ${WWW_DIR}/nextcloud/occ encryption:enable

### Set Nextcloud to run maintenace tasks as a cron job
###
sudo -u www php ${WWW_DIR}/nextcloud/occ background:cron
crontab -u www ${PWD}/includes/www-crontab
# sudo -u www /usr/local/bin/php -f ${WWW_DIR}/nextcloud/cron.php &>/dev/null &

### All done!
### Print copy of reference info to console
###
clear
echo "Installation Complete!"
echo ""
cat /root/${HOST_NAME}_reference.txt
echo "These details have also been written to /root/${HOST_NAME}_reference.txt"
