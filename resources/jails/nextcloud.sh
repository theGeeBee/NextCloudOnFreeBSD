#!/bin/sh
# Nextcloud VNET jail worker (root), consuming the host's immutable version plan.
# Payload: /root/cloud-installer/{runtime.json,installer/,resources/,tls/}.
# runtime.json and apache-onlyoffice.conf are PUBLIC, but root-owned/private-mode.
# Host streams ONLY phase-specific secret JSON on stdin (never an argv value):
#   prepare / publish: no input
#   database / checkpoint-ready: {"db_password":...}
#   install: {"admin_password":...,"db_password":...}
#   finish: {"apps":{"onlyoffice":{...including jwt_secret...}}}; none: no input
# The host owns serialization, immutable manifests, mounts and phase checkpoints.
# Interrupted NC table initialization requires explicit coherent checkpoint
# recovery; this worker never removes/restores application data to make a retry fit.
set +x
set +v
set -eu
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
ulimit -c 0

fail() { printf '%s\n' "Nextcloud worker: $*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'Usage: sh resources/jails/nextcloud.sh prepare|database|checkpoint-ready|install|publish|finish'
mode=$1
case "$mode" in prepare|database|checkpoint-ready|install|publish|finish) ;; *) fail 'Unknown phase.' ;; esac
[ "$(id -u)" -eq 0 ] || fail 'Run as root inside the Nextcloud jail.'
[ "$(uname -s)" = FreeBSD ] || fail 'The selected FreeBSD target is required.'
[ "$(sysctl -n security.jail.jailed)" = 1 ] || fail 'Refusing to run outside a jail.'
command -v mdo >/dev/null 2>&1 || fail 'The FreeBSD base mdo utility is required.'

PAYLOAD=/root/cloud-installer
RUNTIME=$PAYLOAD/runtime.json
TEMPLATES=$PAYLOAD/resources/templates/nextcloud
BOOTSTRAP=$PAYLOAD/resources/jails/nextcloud-bootstrap.php
APP=/usr/local/www/nextcloud
STATE=/var/db/cloud-installer
HELPER=/usr/local/libexec/cloud-nextcloud-bootstrap.php
CRON_HELPER=$PAYLOAD/resources/jails/nextcloud-cron-fence.php
stage=
cron_fenced=0
antivirus_active=0
cleanup() {
    result=$?
    if [ "$cron_fenced" = 1 ]; then
        # Never reopen scheduling on failure/cancellation, including a partially
        # successful activation. The host also stops the owned jail on failure.
        sysrc cron_enable=NO < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 || :
        service cron onestop < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 || :
    fi
    if [ "$antivirus_active" = 1 ]; then
        sysrc clamav_clamd_enable=NO clamav_freshclam_enable=NO < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 || :
        service clamav_freshclam onestop < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 || :
        service clamav_clamd onestop < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 || :
    fi
    [ -z "$stage" ] || rm -rf "$stage"
    return "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || fail 'A required private-mode input is missing or is a symlink.'
    case "$(stat -f '%u:%Lp' "$1")" in 0:600|0:400) ;; *) fail 'Private-mode inputs must be root-owned mode 0600 or 0400.' ;; esac
    [ "$(stat -f '%z' "$1")" -le "${2:-65536}" ] || fail 'Input exceeds the size limit.'
}

private_file "$RUNTIME"
[ -d "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ] || fail 'Missing payload directory.'
[ "$(stat -f '%u:%Lp' "$PAYLOAD")" = 0:700 ] || fail 'The payload directory must be root-owned mode 0700.'
[ -f "$BOOTSTRAP" ] || fail 'Incomplete installer payload.'
[ -f "$PAYLOAD/resources/jails/versions.sh" ] && [ ! -L "$PAYLOAD/resources/jails/versions.sh" ] \
    || fail 'The trusted version helper is missing.'
case "$(stat -f '%u:%Lp' "$PAYLOAD/resources/jails/versions.sh")" in
    0:400|0:444|0:555|0:600|0:644|0:700|0:755) ;;
    *) fail 'The version helper must be root-owned and not writable by other users.' ;;
esac
. "$PAYLOAD/resources/jails/versions.sh"
version_load nextcloud
version_environment
for directory in "$APP" /var/nc-data /var/db/mysql /var/log/mysql /var/log /var/nc-tmp; do
    [ -d "$directory" ] && [ ! -L "$directory" ] || fail "Missing persistent directory: $directory"
done

# All ordinary helper/occ/package/service calls explicitly avoid consuming the
# host's secret pipe. Only the dedicated secret-input helpers inherit it.
json() { /usr/local/bin/php -d display_errors=0 -d log_errors=0 "$BOOTSTRAP" "$@" < /dev/null; }
occ() { mdo -u www /usr/local/bin/php "$APP/occ" --no-interaction "$@"; }
render() {
    template=$1
    if [ "$version_office_backend" = none ]; then
        case "$template" in https.conf|external.conf) template=${template%.conf}-none.conf ;; esac
    fi
    json render "$TEMPLATES/$template" > "$stage/$1"
}
require_phase() { [ -f "$STATE/nextcloud-$1" ] || fail "Complete the $1 phase before $mode."; }
installed_check() {
    mdo -u www /usr/local/bin/php -d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 \
        "$HELPER" installed-check 3< "$RUNTIME" < /dev/null >> "$STATE/nextcloud-install.log" 2>&1 \
        || fail "Nextcloud is not a complete matching instance; inspect $STATE/nextcloud-install.log (root-only)."
}

optional_app_state() {
    occ app:list --output=json < /dev/null > "$stage/apps.json" 2>> "$STATE/nextcloud-finish.log" \
        || fail 'Native app inventory failed; inspect the private finish log.'
    occ config:app:get "$1" installed_version --default-value= < /dev/null > "$stage/installed-version" 2>> "$STATE/nextcloud-finish.log" \
        || fail 'Native app installation status failed; inspect the private finish log.'
    json app-state "$1" "$stage/apps.json" "$stage/installed-version"
}

app_progress() {
    # Persist intent before occ can mutate the database. A failed/uncertain app
    # migration must not turn into an automatic retry after host/process loss.
    /usr/local/bin/python3 -c '
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    fd = os.open(path.name + ".new", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(fd, "wb") as stream:
        stream.write((sys.argv[2] + "\n").encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(path.name + ".new", path.name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)
finally:
    os.close(directory)
' "$@" < /dev/null
}

install_optional_apps() {
    for app_id in $selected_apps; do
        progress=$STATE/nextcloud-app-$app_id
        if [ -e "$progress" ] || [ -L "$progress" ]; then
            private_file "$progress" 32
            [ "$(cat "$progress")" = complete ] \
                || fail "Uncertain $app_id installation; explicit recovery is required. No app was replayed."
        fi
        app_state=$(optional_app_state "$app_id") \
            || fail "Uncertain native $app_id status; inspect the private finish log."
        if [ -f "$progress" ]; then
            [ "$app_state" != missing ] || fail "Completed $app_id disappeared; explicit recovery is required."
        fi
        case "$app_state" in
            enabled) ;; # Includes app:install's already-installed exit-1 case.
            disabled|missing)
                # Keep this marker on error, signal or power loss. A disabled app
                # or installed_version alone cannot prove our migration completed.
                app_progress "$progress" running
                if [ "$app_state" = missing ]; then
                    occ app:install "$app_id" < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 \
                        || fail "Native $app_id installation failed; inspect the private finish log. Explicit recovery is required."
                else
                    occ app:enable "$app_id" < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 \
                        || fail "Native $app_id enable failed; inspect the private finish log. Explicit recovery is required."
                fi
                [ "$(optional_app_state "$app_id")" = enabled ] \
                    || fail "Native $app_id did not report completed installation/enabling."
                ;;
            *) fail 'Invalid native app state.' ;;
        esac
        app_progress "$progress" complete
    done
}

configure_antivirus() {
    # security/clamav is installed ONLY by the prepare phase's locked pkg plan.
    # Reviewed FreeBSD ports 2026-10-18: clamav_clamd / clamav_freshclam rc scripts,
    # clamav account, /usr/local/etc/{clamd,freshclam}.conf and /var/*/clamav.
    antivirus_active=1
    sysrc clamav_clamd_enable=NO clamav_freshclam_enable=NO < /dev/null
    for scanner_service in clamav_freshclam clamav_clamd; do
        if service "$scanner_service" onestatus < /dev/null >/dev/null 2>&1; then
            service "$scanner_service" onestop < /dev/null
        fi
        if service "$scanner_service" onestatus < /dev/null >/dev/null 2>&1; then
            fail 'Antivirus service did not stop; scheduling remains closed.'
        fi
    done
    id clamav < /dev/null >/dev/null
    # clamd creates/chowns its socket AFTER dropping privileges. Keep its own
    # group rather than grant the scanner www's application/data permissions.
    pw groupmod clamav -m www < /dev/null
    install -d -o clamav -g clamav -m 750 /var/db/clamav /var/log/clamav
    install -d -o clamav -g clamav -m 750 /var/run/clamav
    cat > "$stage/clamd.conf" <<'EOF'
User clamav
DatabaseDirectory /var/db/clamav
PidFile /var/run/clamav/clamd.pid
LocalSocket /var/run/clamav/clamd.sock
LocalSocketGroup clamav
LocalSocketMode 660
FixStaleSocket yes
StreamMaxLength 100M
LogFile /var/log/clamav/clamd.log
LogFileMaxSize 10M
LogRotate yes
EOF
    cat > "$stage/freshclam.conf" <<'EOF'
DatabaseOwner clamav
DatabaseDirectory /var/db/clamav
DatabaseMirror database.clamav.net
DNSDatabaseInfo current.cvd.clamav.net
ScriptedUpdates yes
Checks 12
PidFile /var/run/clamav/freshclam.pid
NotifyClamd /usr/local/etc/clamd.conf
UpdateLogFile /var/log/clamav/freshclam.log
LogFileMaxSize 10M
LogRotate yes
EOF
    install -o root -g clamav -m 640 "$stage/clamd.conf" /usr/local/etc/clamd.conf
    install -o root -g clamav -m 640 "$stage/freshclam.conf" /usr/local/etc/freshclam.conf
    # Native freshclam uses HTTPS for database.clamav.net and DNS TXT metadata.
    # Its signed CVD/CDIFF protocol and TLS checks are not replaced with fetch.
    /usr/local/bin/freshclam --config-file=/usr/local/etc/freshclam.conf < /dev/null
    service clamav_clamd onestart < /dev/null
    attempt=0
    until [ -S /var/run/clamav/clamd.sock ] && service clamav_clamd onestatus < /dev/null >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 120 ] || fail 'ClamAV socket did not become ready.'
        sleep 1
    done
    [ "$(stat -f '%Su:%Sg:%Lp' /var/run/clamav/clamd.sock)" = clamav:clamav:660 ] \
        || fail 'Unexpected ClamAV socket ownership or permissions.'
    service clamav_freshclam onestart < /dev/null
    service clamav_freshclam onestatus < /dev/null >/dev/null 2>&1
}

antivirus_app_config() {
    occ config:app:set files_antivirus av_mode --value=socket < /dev/null
    occ config:app:set files_antivirus av_socket --value=/var/run/clamav/clamd.sock < /dev/null
    occ config:app:set files_antivirus av_infected_action --value=only_log < /dev/null
    occ config:app:set files_antivirus av_stream_max_length --value=104857600 --type=integer < /dev/null
}
start_service() { service "$1" status < /dev/null >/dev/null 2>&1 || service "$1" start < /dev/null; }

close_cron() {
    cron_fenced=1
    sysrc cron_enable=NO < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1
    if service cron onestatus < /dev/null >/dev/null 2>&1; then
        service cron onestop < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1
    fi
    if service cron onestatus < /dev/null >/dev/null 2>&1; then
        fail 'Cron daemon did not stop; scheduling remains disabled.'
    fi
}

cron_check() {
    [ -f "$CRON_HELPER" ] && [ ! -L "$CRON_HELPER" ] || fail 'Missing trusted cron fence helper.'
    case "$(stat -f '%u:%Lp' "$CRON_HELPER")" in
        0:400|0:444|0:600|0:644) ;;
        *) fail 'The cron fence helper must be root-owned and not writable by other users.' ;;
    esac
    /usr/local/bin/php -d display_errors=0 -d log_errors=0 -d zend.exception_ignore_args=1 \
        "$CRON_HELPER" "$@" < /dev/null
}

cron_closed() {
    [ "$(sysrc -n cron_enable < /dev/null)" = NO ] || fail 'Cron boot fence changed.'
    set -- closed "$$"
    if [ "$antivirus_active" = 1 ]; then set -- "$@" --antivirus; fi
    cron_check "$@" >> "$STATE/nextcloud-finish.log" 2>&1 \
        || fail 'Scheduled writers did not close; inspect the private finish log.'
}

initialize_state() {
    [ ! -L "$STATE" ] || fail 'State directory must not be a symlink.'
    install -d -o root -g wheel -m 700 "$STATE"
    if [ ! -d "$STATE/nextcloud-started" ]; then
        [ "$mode" = prepare ] || fail 'Run prepare first.'
        [ ! -e /root/.my.cnf ] || fail 'Unexpected root database client configuration.'
        for directory in "$APP" /var/nc-data /var/db/mysql; do
            [ -z "$(find "$directory" -mindepth 1 -maxdepth 1 ! -name .zfs -print)" ] \
                || fail "Unowned existing storage; refusing to adopt it: $directory"
        done
        mkdir "$STATE/nextcloud-started"
    fi
    # Pin public inputs before package bootstrap. The host additionally pins
    # package/code/config inputs in its manifest; do not silently reconfigure.
    if [ -f "$STATE/nextcloud-runtime.sha256" ]; then
        [ "$(sha256 -q "$RUNTIME")" = "$(cat "$STATE/nextcloud-runtime.sha256")" ] \
            || fail 'Public runtime changed; resume requires the original immutable configuration.'
    else
        sha256 -q "$RUNTIME" > "$STATE/nextcloud-runtime.sha256.new"
        mv "$STATE/nextcloud-runtime.sha256.new" "$STATE/nextcloud-runtime.sha256"
    fi
    for diagnostic in database-init.log nextcloud-install.log nextcloud-publish.log nextcloud-finish.log; do
        [ -e "$STATE/$diagnostic" ] || install -o root -g wheel -m 600 /dev/null "$STATE/$diagnostic"
        [ -f "$STATE/$diagnostic" ] && [ ! -L "$STATE/$diagnostic" ] && [ "$(stat -f '%u:%Lp' "$STATE/$diagnostic")" = 0:600 ] \
            || fail 'Diagnostics must be root-owned regular mode-0600 files.'
    done
}

start_database_cache() {
    # Preserve the ports rc initialization: mariadb-install-db --basedir=...
    # --datadir=... --force, with the default root Unix-socket authentication.
    # A failed rc initialization is retained for inspection, never reset.
    start_service mysql-server >> "$STATE/database-init.log" 2>&1 \
        || fail "MariaDB initialization/start failed; inspect $STATE/database-init.log (root-only)."
    attempt=0
    until mariadb-admin --no-defaults --protocol=socket --socket=/var/run/mysql/mysql.sock -u root ping < /dev/null >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 60 ] || fail "MariaDB did not become ready; inspect $STATE/database-init.log (root-only) and /var/log/mysql."
        sleep 1
    done
    start_service redis
    attempt=0
    until [ "$(redis-cli -s /var/run/redis/private/nextcloud.sock ping < /dev/null 2>/dev/null || true)" = PONG ]; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 30 ] || fail 'Redis did not become ready; inspect /var/log/redis.'
        sleep 1
    done
}

prepare() {
    # Base-jail rc may already have started cron. Keep it persistently disabled
    # through fresh provisioning and every interrupted pre-finish restart.
    close_cron
    # Markers acknowledge completed effects, never merely attempted effects.
    # Re-entering prepare after installation cannot reinstall packages or replace
    # code/config, and cannot put a published instance back behind a challenge vhost.
    if [ -f "$STATE/nextcloud-prepared" ]; then
        json validate
        json code-check
        start_database_cache
        if [ -f "$STATE/nextcloud-installed" ]; then installed_check; fi
        printf '%s\n' 'Nextcloud prepare already complete.'
        return
    fi

    # Base flua has already validated public versions, environment and the full
    # lock before any mutations. PHP validates the remaining public settings once
    # the single locked package transaction has supplied the selected interpreter.
    # install -d applies -m only to the leaf; missing public ancestors must
    # not inherit this worker's private umask (mysql/www need to traverse etc).
    (umask 022; install -d -m 755 /usr/local/etc/pkg/repos)
    cat > /usr/local/etc/pkg/repos/cloud-nextcloud.conf <<EOF
FreeBSD-ports: {
  url: "pkg+https://pkg.FreeBSD.org/\${ABI}/${repository}",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
EOF
    chmod 644 /usr/local/etc/pkg/repos/cloud-nextcloud.conf
    if [ ! -f "$STATE/nextcloud-packages" ]; then
        umask 022
        pkg bootstrap -y -r FreeBSD-ports < /dev/null
        pkg update -r FreeBSD-ports < /dev/null
        umask 077
        version_packages_install
        touch "$STATE/nextcloud-packages"
    fi
    json validate
    [ "$(json get repository)" = "$repository" ] || fail 'Repository selection does not match runtime.json.'
    stage=$(mktemp -d "$PAYLOAD/.nextcloud-work.XXXXXX")
    install -d -o root -g wheel -m 755 /usr/local/libexec /usr/local/etc/php-fpm.d /usr/local/etc/mysql/conf.d
    install -o root -g www -m 640 "$BOOTSTRAP" "$HELPER"
    # Outside DocumentRoot and the upstream updater's code tree. The manager
    # verifies these exact public bytes before querying each private FPM socket.
    install -o root -g www -m 640 "$PAYLOAD/resources/jails/runtime-inventory.php" /usr/local/libexec/cloud-runtime-inventory.php
    # User/backup operations must not add executable-tree entries after the
    # immutable first-readiness enrollment baseline has been sealed.
    install -o root -g www -m 640 "$PAYLOAD/resources/jails/maintenance.php" /usr/local/libexec/cloud-nextcloud-maintenance.php
    install -d -o www -g www -m 750 /var/log/nextcloud
    install -d -o root -g www -m 750 /var/log/php-fpm
    install -d -o redis -g redis -m 750 /var/log/redis /var/db/redis
    chown mysql:mysql /var/db/mysql /var/log/mysql
    chmod 750 /var/db/mysql /var/log/mysql
    chown www:www /var/nc-data
    chmod 750 /var/nc-data
    chown root:www /var/nc-tmp
    chmod 750 /var/nc-tmp
    install -d -o www -g www -m 700 /var/nc-tmp/uploads /var/nc-tmp/php-sessions /var/nc-tmp/nextcloud
    pw groupmod redis -m www
    for log in /var/log/php-fpm/php-error.log /var/log/nextcloud/cron.log; do
        [ -e "$log" ] || install -o www -g www -m 640 /dev/null "$log"
    done
    install -d -o root -g wheel -m 755 /usr/local/etc/newsyslog.conf.d /usr/local/etc/rc.d
    install -o root -g wheel -m 555 "$TEMPLATES/mysql-flush-logs" /usr/local/libexec/cloud-mysql-flush-logs
    install -o root -g wheel -m 644 "$TEMPLATES/newsyslog.conf" /usr/local/etc/newsyslog.conf.d/cloud-nextcloud.conf
    install -o root -g wheel -m 555 "$TEMPLATES/cloud_php_dirs" /usr/local/etc/rc.d/cloud_php_dirs
    sysrc cloud_php_dirs_enable=YES php_fpm_enable=NO php_fpm_umask=0027 mysql_enable=YES redis_enable=YES
    sysrc apache24_enable=YES sendmail_enable=NONE cron_enable=NO
    service cloud_php_dirs start < /dev/null

    # Discover the installed package's php.ini-production and compiled config paths;
    # never fall back to an empty php.ini or copy development defaults.
    php_base=$(pkg query '%Fp' "$version_php_package" | awk '/\/php\.ini-production$/ { print }')
    php_ini=$(/usr/local/bin/php-config --ini-path)/php.ini
    php_scan=$(/usr/local/bin/php-config --ini-dir)
    [ -f "$php_base" ] && [ ! -L "$php_base" ] || fail 'PHP package production defaults were not found.'
    case "$php_ini:$php_scan" in /usr/local/etc/php.ini:/usr/local/etc/php) ;; *) fail 'Unexpected PHP configuration paths; review the installed package layout.' ;; esac
    install -d -o root -g wheel -m 755 "$php_scan"
    [ -e "$php_ini" ] || install -o root -g wheel -m 644 "$php_base" "$php_ini"
    for template in php.ini my.cnf redis.conf httpd.conf challenge.conf; do render "$template"; done
    for config in php-fpm.conf www.conf; do
        case "$config" in php-fpm.conf) base=/usr/local/etc/php-fpm.conf.default ;; www.conf) base=/usr/local/etc/php-fpm.d/www.conf.default ;; esac
        [ -f "$base" ] || fail 'Missing packaged PHP-FPM production defaults.'
        template=$config
        if [ "$version_office_backend" = none ] && [ "$config" = www.conf ]; then template=www-none.conf; fi
        json patch-ini "$TEMPLATES/$template" "$base" > "$stage/$config"
    done
    install -m 644 "$stage/php.ini" "$php_scan/zz-cloud-nextcloud.ini"
    install -m 644 "$stage/php-fpm.conf" /usr/local/etc/php-fpm.conf
    install -m 644 "$stage/www.conf" /usr/local/etc/php-fpm.d/www.conf
    # Retain the package my.cnf/server.cnf and load our last-sorted overrides.
    grep -q '^!includedir /usr/local/etc/mysql/conf.d/' /usr/local/etc/mysql/my.cnf \
        || fail 'MariaDB package no longer includes its conf.d directory.'
    install -m 644 "$stage/my.cnf" /usr/local/etc/mysql/conf.d/zz-cloud-nextcloud.cnf
    install -m 640 -o root -g redis "$stage/redis.conf" /usr/local/etc/redis.conf
    install -m 644 "$stage/httpd.conf" /usr/local/etc/apache24/httpd.conf
    install -m 644 "$stage/challenge.conf" /usr/local/etc/apache24/cloud-vhost.conf
    install -d -m 755 /usr/local/www/cloud-acme /usr/local/www/cloud-acme/empty \
        /usr/local/www/cloud-acme/.well-known /usr/local/www/cloud-acme/.well-known/acme-challenge
    apachectl configtest < /dev/null
    php-fpm -t < /dev/null
    start_database_cache

    if [ ! -f "$STATE/nextcloud-code-ready" ]; then
        [ ! -e "$APP/config/config.php" ] || fail 'Application config appeared before code preparation completed; inspect the retained state.'
        # Keep the authenticated archive across an interrupted copy into the app
        # mount. Replaying that copy is permitted only before installation/data.
        release=$STATE/nextcloud-release.tar.bz2
        if [ ! -f "$STATE/nextcloud-release.sha256" ]; then
            archive="nextcloud-${version_nextcloud}.tar.bz2"
            fetch -o "$stage/$archive" "https://download.nextcloud.com/server/releases/$archive" < /dev/null
            fetch -o "$stage/$archive.asc" "https://download.nextcloud.com/server/releases/$archive.asc" < /dev/null
            fetch -o "$stage/nextcloud.asc" https://nextcloud.com/nextcloud.asc < /dev/null
            mkdir -m 700 "$stage/gnupg"
            gpg --homedir "$stage/gnupg" --batch --no-tty --import "$stage/nextcloud.asc" < /dev/null >/dev/null 2>&1
            gpg --homedir "$stage/gnupg" --batch --no-tty --status-fd 1 --verify "$stage/$archive.asc" "$stage/$archive" \
                < /dev/null > "$stage/signature.status" 2> "$stage/signature.log" || fail 'Nextcloud archive signature verification failed.'
            # Pinned primary key; VALIDSIG's final field also identifies a primary
            # key when a signing subkey was used (nextcloud.com/install/).
            awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && ($3 == "28806A878AE423A28372792ED75899B9A724937A" || $12 == "28806A878AE423A28372792ED75899B9A724937A") { valid=1 } END { exit !valid }' \
                "$stage/signature.status" || fail 'Archive was not signed by the pinned Nextcloud release key.'
            install -o root -g wheel -m 600 "$stage/$archive" "$release"
            sha256 -q "$release" > "$STATE/nextcloud-release.sha256.new"
            mv "$STATE/nextcloud-release.sha256.new" "$STATE/nextcloud-release.sha256"
        fi
        [ "$(sha256 -q "$release")" = "$(cat "$STATE/nextcloud-release.sha256")" ] || fail 'Retained authenticated archive changed.'
        [ -z "$(find /var/nc-data -mindepth 1 -maxdepth 1 ! -name .zfs -print)" ] || fail 'Data appeared before code preparation; refusing to overwrite code.'
        tar -xjf "$release" --strip-components 1 --no-same-owner --no-same-permissions -C "$APP"
        json code-check
        chown -R www:www "$APP"
        chmod 750 "$APP/config"
        install -d -o www -g www -m 750 "$APP/custom_apps"
        touch "$STATE/nextcloud-code-ready"
    else
        json code-check
    fi
    # Only challenge HTTP is reachable. No FPM service or uninstalled app vhost.
    start_service apache24
    newsyslog -n -f /usr/local/etc/newsyslog.conf.d/cloud-nextcloud.conf < /dev/null
    touch "$STATE/nextcloud-prepared"
    printf '%s\n' 'Nextcloud prepare complete.'
}

database() {
    require_phase prepared
    json validate
    start_database_cache
    /usr/local/bin/php -d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 \
        "$BOOTSTRAP" database >> "$STATE/database-init.log" 2>&1 \
        || fail "Database phase failed; inspect $STATE/database-init.log (root-only)."
    touch "$STATE/nextcloud-database"
    printf '%s\n' 'Nextcloud database complete.'
}

install_nextcloud() {
    require_phase database
    json validate
    start_database_cache
    if [ ! -f "$STATE/nextcloud-installed" ]; then
        [ ! -e "$STATE/nextcloud-published" ] && [ ! -e "$STATE/nextcloud-finished" ] \
            || fail 'Publication occurred without the installed marker; refusing fresh-install repair.'
    fi
    # Root retains stdin from the host and opens ONLY the public runtime on fd3.
    # FreeBSD mdo preserves both descriptors when switching to www.
    mdo -u www /usr/local/bin/php -d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 \
        "$HELPER" install 3< "$RUNTIME" >> "$STATE/nextcloud-install.log" 2>&1 \
        || fail "Nextcloud installation failed; inspect $STATE/nextcloud-install.log (root-only). Partial tables require explicit host checkpoint recovery."
    installed_check
    chmod 600 "$APP/config/config.php"
    if [ ! -f "$STATE/nextcloud-installed" ]; then
        # Stay inside the host's pre-publication initialization checkpoint boundary.
        # Retry only the native idempotent MIME step, never all app repairs. Keep
        # the original install helper's credential/identity checks on every replay.
        mdo -u www /usr/local/bin/php -d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 \
            "$HELPER" mimetype-repair 3< "$RUNTIME" < /dev/null >> "$STATE/nextcloud-install.log" 2>&1 \
            || fail "Nextcloud mimetype repair failed; inspect $STATE/nextcloud-install.log (root-only). Publication remains blocked."
    fi
    touch "$STATE/nextcloud-installed"
    printf '%s\n' 'Nextcloud install complete.'
}

checkpoint_ready() {
    require_phase database
    json validate
    start_database_cache
    # Read-only application/database check. The host next stops the whole jail
    # and atomically snapshots app, data, database and database-log datasets.
    mdo -u www /usr/local/bin/php -d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 \
        "$HELPER" checkpoint-ready 3< "$RUNTIME" >> "$STATE/database-init.log" 2>&1 \
        || fail "Initialization checkpoint requires a pristine app and empty Nextcloud database; inspect $STATE/database-init.log (root-only)."
    printf '%s\n' 'Nextcloud initialization checkpoint ready.'
}

publish() {
    require_phase installed
    json validate
    installed_check
    if [ -f "$STATE/nextcloud-published" ]; then
        start_service php_fpm
        start_service apache24
        printf '%s\n' 'Nextcloud publish already complete.'
        return
    fi
    stage=$(mktemp -d "$PAYLOAD/.nextcloud-work.XXXXXX")
    tls_mode=$(json get tls_mode)
    hostname=$(json get public_hostname)
    json system-config > "$stage/system.json"
    occ config:import < "$stage/system.json" >> "$STATE/nextcloud-publish.log" 2>&1
    occ maintenance:update:htaccess < /dev/null >> "$STATE/nextcloud-publish.log" 2>&1
    if [ -s "$PAYLOAD/tls/ca.pem" ]; then
        private_file "$PAYLOAD/tls/ca.pem" 1048576
        # certctl/package bootstrap may leave the public certificate parent 0700;
        # occ runs as www and must be able to traverse both public directories.
        install -d -m 755 /usr/local/share/certs /usr/local/share/certs/cloud-installer
        install -m 644 "$PAYLOAD/tls/ca.pem" /usr/local/share/certs/cloud-installer/ca.pem
        certctl rehash < /dev/null
        occ security:certificates:import /usr/local/share/certs/cloud-installer/ca.pem < /dev/null >> "$STATE/nextcloud-publish.log" 2>&1
    fi
    php-fpm -t < /dev/null
    sysrc php_fpm_enable=YES
    start_service php_fpm
    case "$tls_mode" in
        acme)
            start_service apache24
            acme_email=$(json get acme_email)
            certbot certonly --webroot --webroot-path /usr/local/www/cloud-acme \
                --preferred-challenges http --non-interactive --agree-tos --keep-until-expiring \
                --config-dir /usr/local/etc/letsencrypt --work-dir /var/db/letsencrypt \
                --logs-dir /var/log/letsencrypt --cert-name "$hostname" --email "$acme_email" -d "$hostname" < /dev/null
            install -m 555 "$TEMPLATES/certbot-deploy" /usr/local/libexec/cloud-certbot-deploy
            install -d -m 755 /etc/cron.d
            install -m 644 "$TEMPLATES/certbot-cron" /etc/cron.d/cloud-certbot
            render https.conf
            ;;
        provided)
            private_file "$PAYLOAD/tls/privkey.pem" 1048576
            private_file "$PAYLOAD/tls/fullchain.pem" 1048576
            install -d -m 700 /usr/local/etc/cloud-tls
            install -m 600 "$PAYLOAD/tls/fullchain.pem" /usr/local/etc/cloud-tls/fullchain.pem
            install -m 600 "$PAYLOAD/tls/privkey.pem" /usr/local/etc/cloud-tls/privkey.pem
            render https.conf
            ;;
        external)
            # TLS exists only at the external proxy. It must preserve Host,
            # X-Forwarded-Proto: https and the WebSocket Upgrade/Connection headers.
            render external.conf
            ;;
    esac
    if [ "$tls_mode" = external ]; then vhost=external.conf; else vhost=https.conf; fi
    install -m 644 "$stage/$vhost" /usr/local/etc/apache24/cloud-vhost.conf
    apachectl configtest < /dev/null
    start_service apache24
    service apache24 graceful < /dev/null
    chmod 600 "$APP/config/config.php"
    touch "$STATE/nextcloud-published"
    printf '%s\n' 'Nextcloud publish complete.'
}

finish() {
    close_cron
    antivirus_active=0
    require_phase published
    cron_closed
    cron_table=$(cron_check table "$TEMPLATES/www-crontab") \
        || fail 'Unexpected www crontab; no schedule was changed.'
    json validate
    selected_apps=$(json apps)
    stage=$(mktemp -d "$PAYLOAD/.nextcloud-work.XXXXXX")
    if printf '%s\n' "$selected_apps" | grep -Fxq files_antivirus; then
        # Do not put this function in an || condition: POSIX sh would suppress
        # errexit inside it and could continue after a signature/service error.
        configure_antivirus >> "$STATE/nextcloud-finish.log" 2>&1
    else
        [ "$?" -eq 1 ] || fail 'Cannot inspect selected Nextcloud apps.'
    fi
    # Selected connector installation starts after exact scanner selection.
    if [ "$version_office_backend" != none ]; then
        connector_label=ONLYOFFICE
        [ "$version_office_backend" != eurooffice ] || connector_label=Euro-Office
        [ "$version_office_backend" != collabora ] || connector_label=Collabora
        private_file "$PAYLOAD/apache-onlyoffice.conf"
        private_file "$PAYLOAD/connector.json" 65536
        # Verify the signed downloaded connector's exact selected version before
        # native installation/migrations. This call cannot consume the JWT pipe.
        mdo -u www /usr/local/bin/php -d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 \
            "$HELPER" connector-install 3< "$RUNTIME" 4< "$PAYLOAD/connector.json" < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 \
            || fail "Selected signed $connector_label installation failed; inspect $STATE/nextcloud-finish.log (root-only). Retain the original connector release."
        mdo -u www /usr/local/bin/php -d log_errors=0 -d error_log=/dev/null -d display_errors=0 -d zend.exception_ignore_args=1 \
            "$HELPER" connector-import 3< "$RUNTIME" >> "$STATE/nextcloud-finish.log" 2>&1 \
            || fail "$connector_label input/import failed; inspect $STATE/nextcloud-finish.log (root-only)."
    fi
    install_optional_apps
    if [ "$antivirus_active" = 1 ]; then
        antivirus_app_config >> "$STATE/nextcloud-finish.log" 2>&1
    fi
    # CLI app/config changes do not invalidate the running FPM master's APCu
    # application/route caches. Without a restart, newly enabled callbacks can
    # still return404 even though occ sees the app. Clear both pools before the
    # real conversion/callback check; never work around it by accepting failure.
    service php_fpm restart < /dev/null
    if [ "$version_office_backend" != none ]; then
        install -m 600 "$PAYLOAD/apache-onlyoffice.conf" /usr/local/etc/apache24/cloud-onlyoffice.conf
    fi
    apachectl configtest < /dev/null
    service apache24 graceful < /dev/null
    if [ "$version_office_backend" = onlyoffice ]; then
        occ onlyoffice:documentserver --check < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 \
            || fail "ONLYOFFICE connection check failed; inspect $STATE/nextcloud-finish.log (root-only)."
    elif [ "$version_office_backend" = eurooffice ]; then
        occ eurooffice:documentserver --check < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 \
            || fail "Euro-Office connection check failed; inspect $STATE/nextcloud-finish.log (root-only)."
    elif [ "$version_office_backend" = collabora ]; then
        code_internal="http://$(json get onlyoffice_ip):8081/collabora/"
        code_callback=$(json get storage_url)
        # Explicit install action. Never call activation from Verify: it writes
        # discovery-derived configuration and can reset callback autodetection.
        occ richdocuments:activate-config --wopi-url "$code_internal" --callback-url "$code_callback" < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 \
            || fail "Collabora activation failed; inspect $STATE/nextcloud-finish.log (root-only)."
        code_public=$(json get public_url)
        [ "$(occ config:app:get richdocuments wopi_url < /dev/null)" = "$code_internal" ] \
            && [ "$(occ config:app:get richdocuments wopi_callback_url < /dev/null)" = "$code_callback" ] \
            && [ "$(occ config:app:get richdocuments public_wopi_url < /dev/null)" = "${code_public%/}" ] \
            && [ "$(occ config:app:get richdocuments wopi_allowlist < /dev/null)" = "$(json get onlyoffice_ip)/32" ] \
            || fail "Collabora discovery/configuration postcondition differs; scheduling remains closed."
    fi
    occ background:cron < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1
    cron_closed
    mdo -u www /usr/local/bin/php -f "$APP/cron.php" < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1 \
        || fail 'Initial background run failed; inspect the private finish log.'
    # Prune the only two writable code-tree paths; retain executable bits.
    # Repeating this after an interrupted permission pass is harmless.
    find "$APP" \( -path "$APP/config" -o -path "$APP/custom_apps" \) -prune -o \
        -exec chown -h root:www {} +
    find "$APP" \( -path "$APP/config" -o -path "$APP/custom_apps" \) -prune -o \
        \( -type d -o -type f \) -exec chmod u=rwX,g=rX,o= {} +
    chmod 750 "$APP/config" "$APP/custom_apps"
    chmod 600 "$APP/config/config.php"
    installed_check
    cron_closed
    current_table=$(cron_check table "$TEMPLATES/www-crontab") \
        || fail 'Unexpected www crontab; scheduling remains disabled.'
    [ "$current_table" = "$cron_table" ] || fail 'The www crontab changed during finish.'
    case "$current_table" in
        absent) crontab -u www "$TEMPLATES/www-crontab" < /dev/null ;;
        present) ;; # Retain the exact existing native spool unchanged on Resume.
        *) fail 'Invalid crontab observation.' ;;
    esac
    [ "$(cron_check table "$TEMPLATES/www-crontab")" = present ] \
        || fail 'Installed www crontab did not match the source template.'
    sysrc cron_enable=YES < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1
    if [ "$antivirus_active" = 1 ]; then
        sysrc clamav_clamd_enable=YES clamav_freshclam_enable=YES < /dev/null >> "$STATE/nextcloud-finish.log" 2>&1
    fi
    start_service cron
    service cron onestatus < /dev/null >/dev/null 2>&1 \
        || fail 'Cron activation failed.'
    touch "$STATE/nextcloud-finished"
    cron_fenced=0
    antivirus_active=0
    printf '%s\n' 'Nextcloud finish complete.'
}

if [ "$mode" != prepare ] || [ -f "$STATE/nextcloud-packages" ]; then version_packages_check; fi
initialize_state
case "$mode" in install) install_nextcloud ;; checkpoint-ready) checkpoint_ready ;; *) "$mode" ;; esac
