#!/bin/sh

#
# Install Nextcloud on FreeBSD/HardenedBSD
#
# Last update: 2023-07-31
# https://github.com/theGeeBee/NextCloudOnFreeBSD/
#

#
# Check for root privileges
#
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run with root privileges."
   echo "Type 'su' to switch to root and remain in this directory."
   exit 1
fi

# Load config settings
CONFIG_FILE="${PWD}/install.conf"

if [ -f "$CONFIG_FILE" ]; then
    . $CONFIG_FILE
else
    echo "Config file '$CONFIG_FILE' not found. Please create the config file by running pre-install.sh and try again."
    exit 1
fi

#
# Set `pkg` to use LATEST (optional)
#
mkdir -p /usr/local/etc/pkg/repos
echo "FreeBSD: { enabled: no }" > /usr/local/etc/pkg/repos/FreeBSD.conf
cp /etc/pkg/FreeBSD.conf /usr/local/etc/pkg/repos/nextcloud.conf
sed -i '' "s|quarterly|latest|" /usr/local/etc/pkg/repos/nextcloud.conf

#
# Install `pkg`, update repository, upgrade existing packages
#
echo "Installing pkg and updating repositories"
pkg bootstrap -y
pkg update
pkg upgrade -y

# Install required packages
xargs pkg install -y < "${PWD}/includes/requirements.txt"

# Download virus definitions
freshclam

#
# Download and verify Nextcloud
#
clear
echo "Downloading Nextcloud v${NEXTCLOUD_VERSION}..."
FILE="latest-${NEXTCLOUD_VERSION}.tar.bz2"
if ! fetch -o /tmp "https://download.nextcloud.com/server/releases/${FILE}" "https://download.nextcloud.com/server/releases/${FILE}".asc https://nextcloud.com/nextcloud.asc
then
	echo "Failed to download Nextcloud"
	exit 1
fi
gpg --import /tmp/nextcloud.asc
if ! gpg --verify "/tmp/${FILE}.asc"
then
	echo "GPG Signature Verification Failed!"
	echo "The Nextcloud download is corrupt."
	exit 1
fi

# Check if HBSD is present in uname string
hbsd_test=$(uname -a | grep -o 'HBSD')

# Set `sysctl` values (necessary for `redis`)
sysctl kern.ipc.somaxconn=1024
echo "kern.ipc.somaxconn=1024" >> /etc/sysctl.conf

#
# Enable services
#
sysrc sendmail_enable="YES"
sysrc apache24_enable="YES"
sysrc mysql_enable="YES"
sysrc php_fpm_enable="YES"
sysrc redis_enable="YES"
sysrc clamav_clamd_enable="YES"
sysrc clamav_freshclam_enable="YES"

#
# Start services
#
service sendmail start
service redis start
apachectl start
service mysql-server start
service php-fpm start
service clamav-clamd onestart

# Update virus definitions again to report update to daemon
freshclam --quiet

# Add user `www` to group `redis`
pw usermod www -G redis

# Extract Nextcloud and give `www` ownership of the directory
tar xjf "/tmp/${FILE}" -C "${WWW_DIR}/"
chown -R www:www "${WWW_DIR}/nextcloud"

# Create self-signed SSL certificate
mkdir -p "${SSL_DIRECTORY}"
chown www:www "${SSL_DIRECTORY}"
OPENSSL_REQUEST="/C=${COUNTRY_CODE}/CN=${HOST_NAME}"
openssl req -x509 -nodes -days 3652 -sha512 -subj "$OPENSSL_REQUEST" -newkey rsa:2048 -keyout "${SSL_DIRECTORY}/nextcloud.key" -out "${SSL_DIRECTORY}/nextcloud.crt"

#
# Copy pre-writting config files and edit in place
#
sed -i '' "s|IP_ADDRESS|${IP_ADDRESS}|" "${PWD}/includes/httpd.conf"
sed -i '' "s|WWW_DIR|${WWW_DIR}|" "${PWD}/includes/httpd.conf"
sed -i '' "s|WWW_DIR|${WWW_DIR}|" "${PWD}/includes/nextcloud.conf"
sed -i '' "s|SSL_DIRECTORY|${SSL_DIRECTORY}|" "${PWD}/includes/nextcloud.conf"
sed -i '' "s|MYTIMEZONE|${TIME_ZONE}|" "${PWD}/includes/php.ini"
# Disable PHP Just-in-Time compilation for HardenedBSD support
if [ "$hbsd_test" ]
	then
		sed -i '' "s|pcre.jit=1|pcre.jit=0|" "${PWD}/inclues/php.ini"
		sed -i '' "s|opcache.jit = 1255|opcache.jit = 0|" "${PWD}/inclues/php.ini"
		sed -i '' "s|opcache.jit_buffer_size = 128M|opcache.jit_buffer_size = 0|" "${PWD}/inclues/php.ini"
	fi
cp -f "${PWD}/includes/httpd.conf" /usr/local/etc/apache24/
cp -f "${PWD}/includes/php.ini" /usr/local/etc/php.ini
cp -f "${PWD}/includes/www.conf" /usr/local/etc/php-fpm.d/
cp -f "${PWD}/includes/redis.conf" /usr/local/etc/redis.conf
cp -f "${PWD}/includes/nextcloud.conf" /usr/local/etc/apache24/Includes/
cp -f "${PWD}/includes/030_php-fpm.conf" /usr/local/etc/apache24/modules.d/
cp -f "${PWD}/includes/my.cnf" /usr/local/etc/mysql/

#
# Restart Services for modified configuration to take effect
#
apachectl restart
service php-fpm restart
service redis restart
service mysql-server restart

# Create Nextcloud log directory
mkdir -p /var/log/nextcloud/
chown www:www /var/log/nextcloud

# Create NextCloud data directory
mkdir -p "${DATA_DIRECTORY}"
chown www:www "${DATA_DIRECTORY}"

#
# Create Nextcloud database, secure database, set MariaDB root password, create Nextcloud DB, user, and password
#
mariadb -u root -e "DELETE FROM mysql.user WHERE User='';"
mariadb -u root -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mariadb -u root -e "DROP DATABASE IF EXISTS test;"
mariadb -u root -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
mariadb -u root -e "CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
mariadb -u root -e "CREATE USER '${DB_USERNAME}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
mariadb -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USERNAME}'@'localhost';"
mariadb -u root -e "FLUSH PRIVILEGES;"
mariadb-admin --user=root password "${DB_ROOT_PASSWORD}" reload

# The next two lines allow `root` to login to mysql> without a password
sed -i '' "s|MYPASSWORD|${DB_ROOT_PASSWORD}|" "${PWD}/includes/root_my.cnf"
cp -f "${PWD}/includes/root_my.cnf" /root/.my.cnf 

#
# CLI installation and configuration of Nextcloud
#
sudo -u www php "${WWW_DIR}/nextcloud/occ" maintenance:install --database="mysql" --database-name="${DB_NAME}" --database-user="${DB_USERNAME}" --database-pass="${DB_PASSWORD}" --database-host="127.0.0.1" --admin-user="${ADMIN_USERNAME}" --admin-pass="${ADMIN_PASSWORD}" --data-dir="${DATA_DIRECTORY}"
sudo -u www php "${WWW_DIR}/nextcloud/occ" db:add-missing-primary-keys
sudo -u www php "${WWW_DIR}/nextcloud/occ" db:add-missing-indices
sudo -u www php "${WWW_DIR}/nextcloud/occ" db:add-missing-columns
sudo -u www php "${WWW_DIR}/nextcloud/occ" db:convert-filecache-bigint --no-interaction
sudo -u www php "${WWW_DIR}/nextcloud/occ" maintenance:mimetype:update-db
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set default_phone_region --value="${COUNTRY_CODE}"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set logtimezone --value="${TIME_ZONE}"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set logdateformat --value="Y-m-d H:i:s T"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set log_type --value="file"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set logfile --value="/var/log/nextcloud/nextcloud.log"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set loglevel --value="2"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set logrotate_size --value="104847600"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set filelocking.enabled --value=true
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set memcache.local --value="\OC\Memcache\APCu"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set redis host --value="/var/run/redis/redis.sock"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set redis port --value=0 --type=integer
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set memcache.distributed --value="\OC\Memcache\Redis"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set memcache.locking --value="\OC\Memcache\Redis"
if [ "$USE_HOSTNAME" = "true" ]; then
	sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set trusted_domains 0 --value="${HOST_NAME}"
	sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set overwritehost --value="${HOST_NAME}"
	sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set overwrite.cli.url --value="https://${HOST_NAME}"
else
	sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set trusted_domains 0 --value="${IP_ADDRESS}"
	sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set trusted_domains 1 --value="${HOST_NAME}"
	sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set overwrite.cli.url --value="https://${IP_ADDRESS}"
fi
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set overwriteprotocol --value="https"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set htaccess.RewriteBase --value="/"
sudo -u www php "${WWW_DIR}/nextcloud/occ" maintenance:update:htaccess
# Set Nextcloud to use sendmail (you can change this later in the GUI)
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set mail_smtpmode --value="sendmail"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set mail_sendmailmode --value="smtp"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set mail_domain --value="${HOST_NAME}"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:system:set mail_from_address --value="${EMAIL_ADDRESS}"
# Disable contactsinteraction because the behaviour is unwanted, and confusing
sudo -u www php "${WWW_DIR}/nextcloud/occ" app:disable contactsinteraction
# Enable external storage support (Example: mount a SMB share in Nextcloud).
# Users are not allowed to mount external storage, but can be allowed under Settings -> Admin -> External Storage
if [ "$EXTERNAL_STORAGE" = "true" ]; then
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:enable files_external
	sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set files_external allow_user_mounting --value="no"
	sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set files_external user_mounting_backends --value="ftp,dav,owncloud,sftp,amazons3,swift,smb,\\OC\\Files\\Storage\\SFTP_Key,\\OC\\Files\\Storage\\SMB_OC"
fi

#
# Install Nextcloud Featured Apps if  (alphabetical)
#
if [ "$INSTALL_APPS" = "true" ]; then
	clear
	echo "Nextcloud is now installed, installing recommended Apps..."
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install calendar
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install contacts
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install deck
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install mail
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install notes
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install spreed # Nextcloud Talk
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install tasks
fi

#
# Install Antivirus for Files
#
clear
echo "Now installing and configuring Antivirus for File using ClamAV..."
sudo -u www php "${WWW_DIR}/nextcloud/occ" app:install files_antivirus
### set correct value for path on FreeBSD and set default action
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set files_antivirus av_mode --value="socket"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set files_antivirus av_socket --value="/var/run/clamav/clamd.sock"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set files_antivirus av_stream_max_length --value="104857600"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set files_antivirus av_infected_action --value="only_log"
sudo -u www php "${WWW_DIR}/nextcloud/occ" config:app:set activity notify_notification_virus_detected --value="1"

#
# SERVER SIDE ENCRYPTION 
# Server-side encryption makes it possible to encrypt files which are uploaded to this server.
# This comes with limitations like a performance penalty, so enable this only if needed.
#
if [ "$ENCRYPT_DATA" = "true" ]; then
	sudo -u www php "${WWW_DIR}/nextcloud/occ" app:enable encryption
	sudo -u www php "${WWW_DIR}/nextcloud/occ" encryption:enable
fi

# Set Nextcloud to run maintenace tasks as a cron job
sed -i '' "s|WWW_DIR|${WWW_DIR}|" "${PWD}/includes/www-crontab"
sudo -u www php "${WWW_DIR}/nextcloud/occ" background:cron
crontab -u www "${PWD}/includes/www-crontab"

# Create reference file
cat >> "/root/${HOST_NAME}_reference.txt" <<EOL
Nextcloud installation details:
===============================

Server address : https://${HOST_NAME} or https://${IP_ADDRESS}
Data directory : ${DATA_DIRECTORY}

Nextcloud GUI Login:
--------------------
Username : ${ADMIN_USERNAME}
Password : ${ADMIN_PASSWORD}

MariaDB Information:
------------------
Database name     : ${DB_NAME}
Database username : ${DB_USERNAME}
Database password : ${DB_PASSWORD}
DB root password  : ${DB_ROOT_PASSWORD}

EOL

#
# All done!
# Print copy of reference info to console.
#
clear
echo "Installation Complete!"
echo ""
cat "/root/${HOST_NAME}_reference.txt"
echo "These details have also been written to /root/${HOST_NAME}_reference.txt"

# Run the Nextcloud background task for the first time
sudo -u www /usr/local/bin/php -f "${WWW_DIR}/nextcloud/cron.php" &
