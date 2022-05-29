#!/bin/sh
# Install NextCloud on FreeBSD
# Tested on FreeBSD 13+
# https://github.com/theGeeBee/NextCloudOnFreeBSD/

# Check for root privileges
if ! [ $(id -u) = 0 ]; then
   echo "This script must be run with root privileges."
   exit 1
fi

### Configuration (All fields are required)
### Common settings
HOST_NAME="nextcloud.zion.internal" # Advisory: set to the same as your DNS entry **required
MY_IP="192.168.6.1"
MY_EMAIL="nextcloud_admin@${HOST_NAME}"
SERVER_EMAIL="nextcloud-alert" # will have ${HOST_NAME} automatically appened, used to send out alerts from the server by `sendmail`
NEXTCLOUD_VERSION="23" # apps don't work on v24 yet, as of 2022/05/28
### Settings for Nextcloud, loggings, and openSSL
COUNTRY_CODE="ZA"
TIME_ZONE="UTC"
### Nextcloud settings
ADMIN_USERNAME="admin"
ADMIN_PASSWORD=$(openssl rand -base64 12)
DATA_DIRECTORY="/mnt/files" ## Please use something like /path/to/zfs/dataset/without/dedup/ - and use the script to create a subdirectory for NC data 
### mySQL setttings
DB_ROOT_PASSWORD=$(openssl rand -base64 16)
DB_USERNAME="nextcloud"
DB_PASSWORD=$(openssl rand -base64 16)
DB_NAME="nextcloud" 

#####
# Install required packages and then start services
# Load required kernel modules

kldload linux linux64 linprocfs linsysfs

# Install required packages

cat includes/requirements.txt | xargs pkg install -y

# Enable services

sysrc apache24_enable="YES"
sysrc mysql_enable="YES"
sysrc sendmail_enable="YES"
sysrc php_fpm_enable="YES"
sysrc clamav_freshclam_enable="YES"
sysrc linux_enable="YES"

# Start services

service linux start
service mysql-server start
service php-fpm start
service sendmail start
apachectl start

# Updata virus definitions

freshclam

######
# Download and verify Nextcloud

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
# Extract Nextcloud and give `www` ownership of the directory
tar xjf /tmp/"${FILE}" -C /usr/local/www/apache24/data/
chown -R www:www /usr/local/www/apache24/data/nextcloud

# Copy and edit pre-written config files
cp -f "${PWD}"/includes/php.ini /usr/local/etc/php.ini
sed -i '' "s|MYTIMEZONE|${TIME_ZONE}|" /usr/local/etc/php.ini

cp -f "${PWD}"/includes/www.conf /usr/local/etc/php-fpm.d/

cp -f "${PWD}"/includes/httpd.conf /usr/local/etc/apache24/
sed -i '' "s|MY_IP|${MY_IP}|" /usr/local/etc/apache24/httpd.conf
cp -f "${PWD}"/includes/nextcloud.conf /usr/local/etc/apache24/Includes/
cp -f "${PWD}"/includes/002_headers.conf /usr/local/etc/apache24/modules.d/
cp -f "${PWD}"/includes/030_php-fpm.conf /usr/local/etc/apache24/modules.d/
cp -f "${PWD}"/includes/php-fpm.conf /usr/local/etc/

# Set linux compatibility mount points
cat "${PWD}"/includes/fstab >> /etc/fstab

# Create self-signed SSL certificate
OPENSSL_REQUEST="/C=${COUNTRY_CODE}/CN=${HOST_NAME}"
openssl req -x509 -nodes -days 3650 -sha512 -subj $OPENSSL_REQUEST -newkey rsa:2048 -keyout /usr/local/etc/apache24/server.key -out /usr/local/etc/apache24/server.crt

#####
# Create mySQL database
# Secure database, set mysql root password, create Nextcloud DB, user, and password
mysql -u root -e "CREATE DATABASE ${DB_NAME};"
mysql -u root -e "CREATE USER '${DB_USERNAME}'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY '${DB_PASSWORD}';"
mysql -u root -e "GRANT ALL ON nextcloud.* TO 'nextcloud'@'localhost';"
mysql -u root -e "DELETE FROM mysql.user WHERE User='';"
mysql -u root -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -u root -e "DROP DATABASE IF EXISTS test;"
mysql -u root -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
mysqladmin --user=root password "${DB_ROOT_PASSWORD}" reload
cp -f ${PWD}/includes/my.cnf /root/.my.cnf
sed -i '' "s|MYPASSWORD|${DB_ROOT_PASSWORD}|" /root/.my.cnf


# Create reference file
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

# Create Nextcloud log directory
mkdir -p /var/log/nextcloud/
chown www:www /var/log/nextcloud

# Create NextCloud data directory
mkdir -p "${DATA_DIRECTORY}"
chown www:www "${DATA_DIRECTORY}"

#####
# CLI installation and configuration of Nextcloud

sudo -u www php /usr/local/www/apache24/data/nextcloud/occ maintenance:install --database="mysql" --database-name="${DB_NAME}" --database-user="${DB_USERNAME}" --database-pass="${DB_PASSWORD}" --database-host="localhost" --admin-user="${ADMIN_USERNAME}" --admin-pass="${ADMIN_PASSWORD}" --data-dir="${DATA_DIRECTORY}"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set mysql.utf8mb4 --type boolean --value="true"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ db:add-missing-indices
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ db:convert-filecache-bigint --no-interaction
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set logtimezone --value="${TIME_ZONE}"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set default_phone_region --value="${COUNTRY_CODE}"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set log_type --value="file"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set logfile --value="/var/log/nextcloud/nextcloud.log"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set loglevel --value="2"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set logrotate_size --value="104847600"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set memcache.local --value="\OC\Memcache\APCu"
## Uncomment the following 2 lines only if DNS works properly on your network.
#sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set overwritehost --value="${HOST_NAME}"
#sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set overwrite.cli.url --value="https://${HOST_NAME}/"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set overwriteprotocol --value="https"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set htaccess.RewriteBase --value="/"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ maintenance:update:htaccess
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set trusted_domains 0 --value="${HOST_NAME}"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set trusted_domains 1 --value="${MY_IP}"

#####
# Install Nextcloud Apps
# Featured Apps (alphabetical)

sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install calendar
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install contacts
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install deck
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install mail
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install notes
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install spreed # Nextcloud Talk
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install tasks
# Antivirus for Files
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install files_antivirus
	#set correct value for path on FreeBSD and set default action
	sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:app:set files_antivirus av_path --value="/usr/local/bin/clamscan" 
	sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:app:set files_antivirus av_infected_action --value="delete"
# Document Server Community Edition
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install documentserver_community
# ONLYOFFICE
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:install onlyoffice
	# set ONLYOFFICE to accept the self-signed certificate and point it to ${MY_IP} instead of localhost
	# ${HOST_NAME} would work instead if DNS is set up correctly
	sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:app:set onlyoffice verify_peer_off --value="true"
	sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:app:set onlyoffice DocumentServerUrl --value="https://${MY_IP}/index.php/apps/documentserver_community/"

# Set Nextcloud to use sendmail (you can change this later in the GUI)
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set mail_smtpmode --value="sendmail"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set mail_sendmailmode --value="smtp"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set mail_domain --value="${HOST_NAME}"
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ config:system:set mail_from_address --value="${SERVER_EMAIL}"

# Enable external storage support (Example: mount a SMB share in Nextcloud)
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:enable files_external

## SERVER SIDE ENCRYPTION 
## Server-side encryption makes it possible to encrypt files which are uploaded to this server.
## This comes with limitations like a performance penalty, so enable this only if needed.
# sudo -u www php /usr/local/www/apache24/data/nextcloud/occ app:enable encryption
# sudo -u www php /usr/local/www/apache24/data/nextcloud/occ encryption:enable
# sudo -u www php /usr/local/www/apache24/data/nextcloud/occ encryption:disable

## Set Nextcloud to run maintenace tasks as a cron job
sudo -u www php /usr/local/www/apache24/data/nextcloud/occ background:cron
sudo -u www php -f /usr/local/www/apache24/data/nextcloud/cron.php 
crontab -u www ${PWD}/includes/www-crontab

## Restart Services

apachectl restart
service php-fpm restart

#####
#
# All done!
# Print copy of reference info to console
#
#####

clear
echo "Installation Complete!"
echo ""
cat /root/${HOST_NAME}_reference.txt
echo "These details have also been written to /root/${HOST_NAME}_reference.txt"
