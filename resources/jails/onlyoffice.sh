#!/bin/sh

# Host: selected thick FreeBSD VNET jail, mounted persistent filesystems,
# PF isolation and hostname resolution already established. Invoke once with
# {"jwt_secret":"<64 hex characters>"} on stdin; never stage a credential bundle.
# Payload: /root/cloud-installer/{installer,resources}, public runtime.json,
# optional tls/ca.pem and fonts/. Owned, matching incomplete attempts can resume.
set +x
set +v
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
LC_ALL=C
export LC_ALL
export PYTHONDONTWRITEBYTECODE=1
umask 077
ulimit -c 0

fail() {
	printf '%s\n' "ONLYOFFICE: $*" >&2
	exit 1
}

[ "$#" -eq 0 ] || fail "This worker takes no arguments; the host supplies public runtime.json and JWT stdin."
[ "$(uname -s)" = FreeBSD ] || fail "The selected FreeBSD target is required."
[ "$(id -u)" -eq 0 ] || fail "Run as root inside the ONLYOFFICE jail."
[ "$(sysctl -n security.jail.jailed)" = 1 ] || fail "This worker must run inside a jail."
ifconfig lo0 inet | awk '$1 == "inet" && $2 == "127.0.0.1" {found=1} END {exit !found}' \
	|| fail "A VNET jail with its own loopback is required."

PAYLOAD=/root/cloud-installer
RUNTIME="${PAYLOAD}/runtime.json"
STATE=/var/db/cloud-installer-onlyoffice
OO_ETC=/usr/local/etc/onlyoffice/documentserver
OO_WWW=/usr/local/www/onlyoffice/documentserver
REPO_CONF=/usr/local/etc/pkg/repos/zz-onlyoffice-installer.conf
OFFICE="${PAYLOAD}/installer/office.py"

[ -d "$PAYLOAD" ] && [ ! -L "$PAYLOAD" ] && [ "$(stat -f '%u:%Lp' "$PAYLOAD")" = 0:700 ] \
	|| fail "The payload directory must be root-owned mode 0700."
[ -f "$PAYLOAD/resources/jails/versions.sh" ] && [ ! -L "$PAYLOAD/resources/jails/versions.sh" ] \
	|| fail "The trusted version helper is missing."
case "$(stat -f '%u:%Lp' "$PAYLOAD/resources/jails/versions.sh")" in
	0:400|0:444|0:555|0:600|0:644|0:700|0:755) ;;
	*) fail "The version helper must be root-owned and not writable by other users." ;;
esac
. "$PAYLOAD/resources/jails/versions.sh"
version_load onlyoffice
version_environment
version_private_file "$PAYLOAD/fonts-unavailable" 600 1048576
awk 'length($0) > 256 || $0 !~ /^[A-Za-z0-9][A-Za-z0-9_+.-]*$/ || seen[$0]++ {exit 1}' \
	"$PAYLOAD/fonts-unavailable" || fail "Invalid host-selected unavailable font inventory."

# lockf owns the lock for the entire child lifetime and releases it on failure.
# stdin stays a pipe, inherited only until the renderer consumes it below.
if [ "${CLOUD_OFFICE_LOCKED:-}" != "$STATE" ]; then
	exec lockf -t 0 /var/run/cloud-installer-onlyoffice.lock \
		env CLOUD_OFFICE_LOCKED="$STATE" /bin/sh "$0"
fi
unset CLOUD_OFFICE_LOCKED
exec 3<&0
exec </dev/null

[ -f "$RUNTIME" ] && [ ! -L "$RUNTIME" ] || fail "A regular public runtime.json is required."
case "$(stat -f '%u:%Lp' "$RUNTIME")" in
	0:600|0:400) ;;
	*) fail "runtime.json must be root-owned and mode 0600 or 0400." ;;
esac

# flua/libucl are in FreeBSD base, so no host Python or pip bootstrap is needed.
# Read only public enums/address before jail Python exists; the strict JSON
# loader subsequently validates URLs/topology and rejects every unknown key.
[ -x /usr/libexec/flua ] || fail "FreeBSD base flua is required."
settings=$(/usr/libexec/flua - "$RUNTIME" <<'LUA'
local ok, result = pcall(function()
    local parser = require("ucl").parser()
    assert(parser:parse_file(arg[1]))
    local value = parser:get_object()
    local allowed = {public_hostname=true, public_url=true, storage_url=true,
        nextcloud_ip=true, onlyoffice_ip=true, repository=true, tls_mode=true,
        font_profile=true, additional_fonts=true, accept_microsoft_fonts=true, versions=true}
    for key in pairs(value) do assert(allowed[key]) end
    assert(value.repository == "latest" or value.repository == "quarterly")
    local profile = value.font_profile or "comprehensive"
    assert(profile == "standard" or profile == "comprehensive")
    assert(value.accept_microsoft_fonts == nil or type(value.accept_microsoft_fonts) == "boolean")
    assert(type(value.onlyoffice_ip) == "string" and value.onlyoffice_ip:match("^%d+%.%d+%.%d+%.%d+$"))
    return value.repository .. " " .. profile .. " " .. tostring(value.accept_microsoft_fonts == true)
        .. " " .. value.onlyoffice_ip
end)
if not ok then os.exit(1) end
print(result)
LUA
) || fail "Cannot read public office settings. Credentials must arrive only on stdin."
read -r repository font_profile accept_microsoft_fonts onlyoffice_ip <<EOF
$settings
EOF
healthcheck_url="http://${onlyoffice_ip}:8081/healthcheck"

# Mount IDs work even when enforce_statfs hides mount listings in the jail.
root_device=$(stat -f '%d' /)
for path in /var/db/onlyoffice /usr/local/www/onlyoffice/Data /var/log; do
	[ -d "$path" ] && [ ! -L "$path" ] || fail "Missing persistent directory: $path"
	[ "$(stat -f '%d' "$path")" != "$root_device" ] || fail "Mount the persistent filesystem at $path first."
done

# Bind owned state to public configuration, implementation, font policy and CA.
# Custom font contents get their own immutable SHA256 manifest after bootstrap.
fingerprint_input=
for path in "$RUNTIME" "$OFFICE" "${PAYLOAD}/installer/office_config.py" \
	"${PAYLOAD}/installer/version_runtime.py" "$VERSION_LOCK" "$VERSION_DEPENDENCIES" "${PAYLOAD}/fonts-unavailable" \
	"${PAYLOAD}/resources/jails/versions.sh" \
	"${PAYLOAD}/resources/jails/onlyoffice.sh" "${PAYLOAD}/resources/packages/fonts.txt" \
	"${PAYLOAD}/resources/templates/onlyoffice/nginx.conf" \
	"${PAYLOAD}/resources/templates/onlyoffice/proxy.conf" \
	"${PAYLOAD}/resources/templates/onlyoffice/supervisord.conf"; do
	[ -f "$path" ] && [ ! -L "$path" ] || fail "The complete installer/resources payload is required."
	digest=$(sha256 -q "$path") || fail "Cannot fingerprint the payload."
	fingerprint_input="${fingerprint_input}${digest}"
done
if [ -e "${PAYLOAD}/tls/ca.pem" ] || [ -L "${PAYLOAD}/tls/ca.pem" ]; then
	[ -f "${PAYLOAD}/tls/ca.pem" ] && [ ! -L "${PAYLOAD}/tls/ca.pem" ] || fail "CA must be a regular certificate bundle."
	digest=$(sha256 -q "${PAYLOAD}/tls/ca.pem") || fail "Cannot fingerprint the CA."
	fingerprint_input="${fingerprint_input}${digest}"
fi
if [ -e "${PAYLOAD}/plugins.json" ] || [ -L "${PAYLOAD}/plugins.json" ]; then
	version_private_file "${PAYLOAD}/plugins.json" 600 4194304
	digest=$(sha256 -q "${PAYLOAD}/plugins.json") || fail "Cannot fingerprint the selected plugin lock."
	fingerprint_input="${fingerprint_input}${digest}"
fi
fingerprint=$(printf '%s' "$fingerprint_input" | sha256 -q)
owner="cloud-installer-onlyoffice-v2 ${fingerprint}"
if [ -e "$STATE" ] || [ -L "$STATE" ]; then
	[ -d "$STATE" ] && [ ! -L "$STATE" ] && [ "$(stat -f '%u:%Lp' "$STATE")" = 0:700 ] \
		|| fail "Refusing unowned or nonprivate installation state."
	[ -f "${STATE}/owner" ] && [ ! -L "${STATE}/owner" ] \
		&& [ "$(stat -f '%u:%Lp' "${STATE}/owner")" = 0:600 ] \
		&& [ "$(cat "${STATE}/owner")" = "$owner" ] \
		|| fail "State belongs to another configuration or payload; refusing adoption."
else
	for path in /var/db/onlyoffice /usr/local/www/onlyoffice/Data; do
		[ -z "$(find "$path" -mindepth 1 -maxdepth 1 ! -name .zfs -print)" ] \
			|| fail "Unowned ONLYOFFICE data must be empty."
	done
	for path in /usr/local/etc/onlyoffice /usr/local/etc/nginx/nginx.conf \
		/usr/local/etc/supervisord.conf /var/log/onlyoffice "$REPO_CONF" \
		/usr/local/share/fonts/cloud-custom /usr/local/etc/newsyslog.conf.d/onlyoffice-nginx.conf; do
		[ ! -e "$path" ] && [ ! -L "$path" ] || fail "Existing unowned service configuration found."
	done
	if [ -x /usr/local/sbin/pkg ]; then
		installed_origins=$(pkg query '%o')
		if printf '%s\n' "$installed_origins" | grep -Eq '^(www/onlyoffice-documentserver|www/nginx(-devel)?|sysutils/py-supervisor)$'; then
			fail "ONLYOFFICE, nginx and Supervisor must not already be installed."
		fi
	fi
	listeners=$(sockstat -46l -P tcp -p 8000,8081,8126)
	printf '%s\n' "$listeners" | awk 'NR > 1 {busy=1} END {exit busy}' || fail "An ONLYOFFICE TCP port is busy."
	listeners=$(sockstat -46l -P udp -p 8125)
	printf '%s\n' "$listeners" | awk 'NR > 1 {busy=1} END {exit busy}' || fail "The metrics UDP port is busy."
	mkdir -m 700 "$STATE"
	printf '%s\n' "$owner" > "${STATE}/owner.new"
	mv "${STATE}/owner.new" "${STATE}/owner"
fi

render_parent=
snapshot_parent=
cleanup() {
	[ -z "$render_parent" ] || rm -rf "$render_parent"
	[ -z "$snapshot_parent" ] || rm -rf "$snapshot_parent"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
# Recover only transient directories created inside the verified owned state.
# This also removes a staged local.json left by an untrappable SIGKILL/reboot.
for path in "${STATE}"/render.* "${STATE}"/snapshot.*; do
	[ -e "$path" ] || continue
	[ -d "$path" ] && [ ! -L "$path" ] || fail "Unexpected transient state entry."
	rm -rf "$path"
done

seen_gap=false
for step in packages securelink fonts configured complete; do
	if [ "$step" = complete ]; then marker="${STATE}/complete"; else marker="${STATE}/${step}.done"; fi
	if [ -e "$marker" ]; then
		[ -f "$marker" ] && [ ! -L "$marker" ] && [ "$seen_gap" = false ] || fail "Inconsistent resume markers."
	else
		seen_gap=true
	fi
done

office_verify() {
	set -- "$1" --runtime "$RUNTIME" --state "$STATE"
	if [ -f "${PAYLOAD}/tls/ca.pem" ]; then set -- "$@" --ca-file "${PAYLOAD}/tls/ca.pem"; fi
	python3 "$OFFICE" "$@"
}

verify_packages() {
	version_packages_check
	installed=$(pkg query '%n|%v|%o') || fail "Cannot read installed packages."
	[ -n "$installed" ] || fail "An empty package inventory is invalid."
	installed=$(printf '%s\n' "$installed" | sort)
	[ "$installed" = "$(cat "${STATE}/packages.installed")" ] || fail "Installed package versions changed."
}

healthcheck() {
	attempt=0
	until [ "$(fetch -q -T 10 -o - "$healthcheck_url" 2>/dev/null)" = true ]; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 60 ] || fail "nginx healthcheck failed; inspect private service logs."
		sleep 2
	done
	for process in ds:docservice ds:metrics; do
		status=$(supervisorctl -c /usr/local/etc/supervisord.conf status "$process" 2>/dev/null) \
			|| fail "An ONLYOFFICE process is not running."
		printf '%s\n' "$status" | awk -v name="$process" '$1 == name && $2 == "RUNNING" {ok=1} END {exit !ok}' \
			|| fail "Both native ONLYOFFICE processes must be RUNNING."
	done
	service supervisord status >/dev/null 2>&1 || fail "Supervisor is not running."
	service nginx status >/dev/null 2>&1 || fail "nginx is not running."
	[ "$(sysrc -n supervisord_enable)" = YES ] && [ "$(sysrc -n supervisord_user)" = root ] \
		&& [ "$(sysrc -n nginx_enable)" = YES ] || fail "Owned service boot settings changed."
}

# Successful retries are verification-only: no pkg update, helper, regeneration,
# rewritten configuration, log/state snapshot or service restart.
if [ -f "${STATE}/complete" ]; then
	verify_packages
	office_verify verify <&3 || fail "Completed configuration or font verification failed."
	exec 3<&-
	nginx -t >/dev/null 2>&1 || fail "nginx configuration validation failed."
	healthcheck
	printf '%s\n' "ONLYOFFICE jail already complete; verification passed."
	exit 0
fi

LOGS=$(mktemp -d "${STATE}/attempt.XXXXXX")
if [ ! -f "${STATE}/rc.conf.before" ]; then
	cp -p /etc/rc.conf "${STATE}/rc.conf.before.new"
	mv "${STATE}/rc.conf.before.new" "${STATE}/rc.conf.before"
fi

if [ ! -f "${STATE}/packages.done" ]; then
	cat > "${LOGS}/repository.conf" <<EOF
FreeBSD-ports: {
  url: "pkg+https://pkg.FreeBSD.org/\${ABI}/${repository}",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
EOF
	if [ -e "$REPO_CONF" ]; then
		cmp -s "${LOGS}/repository.conf" "$REPO_CONF" || fail "Owned repository configuration changed."
	else
		(umask 022; install -d -o root -g wheel -m 755 /usr/local/etc/pkg/repos)
		install -S -o root -g wheel -m 644 "${LOGS}/repository.conf" "$REPO_CONF"
	fi
	# Only the base stub accepts bootstrap's repository option. A resumed
	# package phase may already have full pkg, even without packages.done.
	if [ ! -e /usr/local/sbin/pkg ] && [ ! -L /usr/local/sbin/pkg ]; then
		(umask 022; pkg bootstrap -y -r FreeBSD-ports) > "${LOGS}/bootstrap.log" 2>&1 \
			|| fail "Package bootstrap failed; inspect private attempt logs."
	fi
	[ -x /usr/local/sbin/pkg ] || fail "The native package manager is missing or not executable."
	pkg -N > "${LOGS}/pkg-check.log" 2>&1 \
		|| fail "The native package manager is not usable; inspect private attempt logs."
	pkg update -r FreeBSD-ports > "${LOGS}/update.log" 2>&1 || fail "Package catalog update failed."
	pkg rquery -U -r FreeBSD-ports '%dn' onlyoffice-documentserver > "${LOGS}/office-dependencies" 2> "${LOGS}/dependencies.log" \
		|| fail "Cannot inspect ONLYOFFICE dependencies."
	if { grep -qx webfonts "${LOGS}/office-dependencies" || grep -q '^webfonts|' "$VERSION_LOCK"; } \
		&& [ "$accept_microsoft_fonts" != true ]; then
		fail "The repository's ONLYOFFICE package requires Microsoft webfonts. Review docs/fonts.md and explicitly accept its EULA in host configuration."
	fi
	# Host selection includes every dependency and available font. Preserve its
	# absence report and lock; never rediscover a different font/package set here.
	for name in fonts-unavailable packages-plan; do
		if [ "$name" = packages-plan ]; then input=$VERSION_LOCK; else input=$PAYLOAD/fonts-unavailable; fi
		if [ -e "${STATE}/$name" ]; then
			cmp -s "$input" "${STATE}/$name" || fail "Owned package/font plan changed."
		else
			install -S -o root -g wheel -m 600 "$input" "${STATE}/$name"
		fi
	done
	if [ -s "${STATE}/fonts-unavailable" ]; then
		printf '%s\n' "Optional font packages unavailable in the selected repository:" >&2
		cat "${STATE}/fonts-unavailable" >&2
	fi
	(version_packages_install) > "${LOGS}/install.log" 2>&1 \
		|| fail "Exact locked package installation failed; inspect private attempt logs and retain the original lock, repository and artifact."
	installed=$(pkg query '%n|%v|%o') || fail "Cannot record installed packages."
	[ -n "$installed" ] || fail "An empty package inventory is invalid."
	printf '%s\n' "$installed" | sort > "${STATE}/packages.installed.new"
	if [ -f "${STATE}/packages.installed" ]; then
		cmp -s "${STATE}/packages.installed.new" "${STATE}/packages.installed" || fail "Owned package inventory changed."
		rm "${STATE}/packages.installed.new"
	else
		mv "${STATE}/packages.installed.new" "${STATE}/packages.installed"
	fi
	touch "${STATE}/packages.done"
fi
verify_packages
python3 "$OFFICE" check-runtime --runtime "$RUNTIME" > "${LOGS}/runtime.log" 2>&1 || fail "Public runtime validation failed."
ifconfig -a inet | awk -v ip="$onlyoffice_ip" '$1 == "inet" && $2 == ip {found=1} END {exit !found}' \
	|| fail "The configured ONLYOFFICE address is not assigned to this jail."

# The host-selected native profile embeds conversion and memory state: no extra database, queue or
# converter daemon. Check the native layout before modifying any package file.
for path in "${OO_ETC}/local.json" "${OO_ETC}/nginx/ds.conf" "${OO_ETC}/nginx/ds-ssl.conf" \
	"${OO_ETC}/nginx/includes/ds-docservice.conf" "${OO_ETC}/nginx/includes/http-common.conf" \
	"${OO_ETC}/supervisor/ds.conf" "${OO_ETC}/supervisor/ds-docservice.conf" "${OO_ETC}/supervisor/ds-metrics.conf"; do
	[ -f "$path" ] && [ ! -L "$path" ] || fail "The reviewed package layout changed."
done
for path in /usr/local/bin/documentserver-update-securelink.sh \
	/usr/local/bin/documentserver-generate-allfonts.sh /usr/local/bin/documentserver-flush-cache.sh \
	"${OO_WWW}/server/DocService/docservice" "${OO_WWW}/server/Metrics/metrics" \
	"${OO_WWW}/server/tools/allfontsgen" "${OO_WWW}/server/tools/allthemesgen" \
	"${OO_WWW}/server/FileConverter/bin/x2t" "${OO_WWW}/npm/json"; do
	[ -x "$path" ] || fail "A required native helper or binary is missing."
done
for path in /var/db/onlyoffice/documentserver/App_Data/cache/files \
	/var/db/onlyoffice/documentserver/App_Data/docbuilder /usr/local/www/onlyoffice/Data \
	/var/log/onlyoffice/documentserver/docservice /var/log/onlyoffice/documentserver/metrics \
	/var/log/onlyoffice/documentserver/converter; do
	install -d -o onlyoffice -g onlyoffice -m 755 "$path"
done
if [ ! -d "${STATE}/backups" ]; then
	[ ! -e "${STATE}/securelink.done" ] && [ ! -e "${STATE}/configuration.json" ] || fail "Original package backup is missing."
	snapshot_parent=$(mktemp -d "${STATE}/snapshot.XXXXXX")
	cp -Rp "$OO_ETC" "${snapshot_parent}/package-config.before"
	cp -p /usr/local/etc/nginx/nginx.conf "${snapshot_parent}/nginx.conf.before"
	cp -p /usr/local/etc/supervisord.conf "${snapshot_parent}/supervisord.conf.before"
	mv "$snapshot_parent" "${STATE}/backups"
	snapshot_parent=
fi

if [ ! -f "${STATE}/securelink.done" ]; then
	# A helper may have completed just before interruption. Preserve its secret
	# when BOTH frontends and local.json already agree; never rotate on resume.
	if ! python3 "$OFFICE" check-securelink > "${LOGS}/securelink-check.log" 2>&1; then
		[ ! -e "${STATE}/configuration.json" ] || fail "Refusing to regenerate an already-rendered secure-link credential."
		# The native helper edits files in place. Recover a torn pre-render write
		# from the immutable vendor snapshot before retrying this owned step.
		for name in local.json nginx/ds.conf nginx/ds-ssl.conf; do
			install -S -o root -g wheel -m 600 "${STATE}/backups/package-config.before/${name}" "${OO_ETC}/${name}"
		done
		# The port's --restart parser double-shifts; use the supported environment.
		(umask 022; RESTART_CONDITION=false sh -e /usr/local/bin/documentserver-update-securelink.sh) \
			> "${LOGS}/securelink.log" 2>&1 || fail "Secure-link helper failed."
	fi
	python3 "$OFFICE" check-securelink > "${LOGS}/securelink-check.log" 2>&1 || fail "Secure-link secrets do not match."
	chown root:onlyoffice "${OO_ETC}/local.json"
	chmod 640 "${OO_ETC}/local.json"
	chmod 600 "${OO_ETC}/nginx/ds.conf" "${OO_ETC}/nginx/ds-ssl.conf"
	touch "${STATE}/securelink.done"
else
	python3 "$OFFICE" check-securelink > "${LOGS}/securelink-check.log" 2>&1 || fail "Owned secure-link configuration changed."
fi

if [ ! -f "${STATE}/fonts.json" ]; then
	python3 "$OFFICE" install-fonts --runtime "$RUNTIME" --state "$STATE" > "${LOGS}/custom-fonts.log" 2>&1 \
		|| fail "Custom font validation/copy failed; inspect private state."
	(umask 022; fc-cache -f) > "${LOGS}/font-cache.log" 2>&1 || fail "Fontconfig cache generation failed."
	# -e exposes native generator failures that the vendor wrapper otherwise
	# masks; true suppresses its obsolete converter/service restart branch.
	(umask 022; sh -e /usr/local/bin/documentserver-generate-allfonts.sh true) > "${LOGS}/fonts.log" 2>&1 \
		|| fail "ONLYOFFICE font generation failed."
	# Native 9.4.0_4 argument loops do not advance. Inherit restart suppression
	# without arguments, as for secure-link generation; never spin on --restart.
	(umask 022; RESTART_CONDITION=false sh -e /usr/local/bin/documentserver-flush-cache.sh) > "${LOGS}/cache.log" 2>&1 \
		|| fail "ONLYOFFICE cache generation failed."
	fc-list --format '%{file}\t%{family}\t%{style}\n' > "${STATE}/fontconfig.tsv" 2> "${LOGS}/fontconfig.log" \
		|| fail "Font inventory failed."
	python3 "$OFFICE" inventory-fonts --runtime "$RUNTIME" --state "$STATE" > "${LOGS}/font-inventory.log" 2>&1 \
		|| fail "Required core fonts or generated font outputs are missing."
fi
python3 "$OFFICE" verify-fonts --runtime "$RUNTIME" --state "$STATE" > "${LOGS}/font-verification.log" 2>&1 \
	|| fail "Owned font inputs or inventory changed."
[ -f "${STATE}/fonts.done" ] || touch "${STATE}/fonts.done"

if [ ! -f "${STATE}/configured.done" ]; then
	render_parent=$(mktemp -d "${STATE}/render.XXXXXX")
	staging="${render_parent}/files"
	set -- prepare --runtime "$RUNTIME" --package-etc "$OO_ETC" --staging "$staging" \
		--pristine-etc "${STATE}/backups/package-config.before" --state "$STATE"
	if [ -f "${PAYLOAD}/tls/ca.pem" ]; then set -- "$@" --ca-file "${PAYLOAD}/tls/ca.pem"; fi
	python3 "$OFFICE" "$@" <&3 > "${LOGS}/render.log" 2>&1 || fail "Rendering failed; inspect private state."
	exec 3<&-
	install -S -o root -g onlyoffice -m 640 "${staging}/local.json" "${OO_ETC}/local.json"
	install -S -o root -g wheel -m 600 "${staging}/ds.conf" "${OO_ETC}/nginx/ds.conf"
	install -S -o root -g wheel -m 644 "${staging}/ds-docservice.conf" "${OO_ETC}/nginx/includes/ds-docservice.conf"
	for name in ds ds-docservice ds-metrics; do
		install -S -o root -g wheel -m 600 "${staging}/supervisor-${name}.conf" "${OO_ETC}/supervisor/${name}.conf"
	done
	if [ -f "${staging}/nextcloud-ca.pem" ]; then
		install -S -o root -g wheel -m 644 "${staging}/nextcloud-ca.pem" "${OO_ETC}/nextcloud-ca.pem"
	fi
	install -S -o root -g wheel -m 644 "${staging}/nginx.conf" /usr/local/etc/nginx/nginx.conf
	install -S -o root -g wheel -m 600 "${staging}/supervisord.conf" /usr/local/etc/supervisord.conf
	install -d -o root -g wheel -m 755 /var/run/supervisor /usr/local/etc/newsyslog.conf.d
	install -S -o root -g wheel -m 644 "${staging}/nginx-newsyslog.conf" /usr/local/etc/newsyslog.conf.d/onlyoffice-nginx.conf
	rm -rf "$render_parent"
	render_parent=
	office_verify verify-deployed > "${LOGS}/deployed.log" 2>&1 || fail "Deployed configuration verification failed."
	touch "${STATE}/configured.done"
else
	office_verify verify <&3 > "${LOGS}/deployed.log" 2>&1 || fail "Owned configuration verification failed."
	exec 3<&-
fi
nginx -t > "${LOGS}/nginx.log" 2>&1 || fail "nginx configuration validation failed."
if [ -f "${PAYLOAD}/plugins.json" ]; then
	# The reviewed package gives onlyoffice ownership of this static parent.
	# Reserve the plugin namespace against service-account directory replacement;
	# do not recursively change cache, application-data or generated-file ownership.
	[ -d "$OO_WWW" ] && [ ! -L "$OO_WWW" ] || fail "Unsafe document-server directory."
	office_uid=$(id -u onlyoffice)
	office_gid=$(id -g onlyoffice)
	case "$(stat -f '%u:%g:%Lp' "$OO_WWW")" in
		"${office_uid}:${office_gid}:755"|"0:${office_gid}:755") ;;
		*) fail "Unexpected document-server directory ownership or mode." ;;
	esac
	chown root:onlyoffice "$OO_WWW"
fi
newsyslog -n -f /usr/local/etc/newsyslog.conf.d/onlyoffice-nginx.conf > "${LOGS}/rotation.log" 2>&1 \
	|| fail "Log rotation configuration validation failed."
sysrc supervisord_enable=YES supervisord_user=root nginx_enable=YES > "${LOGS}/rc.log" 2>&1
# Starting a stopped service is resumable; a running owned service is preserved.
if ! service supervisord status >/dev/null 2>&1; then
	service supervisord start > "${LOGS}/supervisor.log" 2>&1 || fail "Supervisor failed to start."
fi
if ! service nginx status >/dev/null 2>&1; then
	service nginx start > "${LOGS}/nginx-start.log" 2>&1 || fail "nginx failed to start."
fi
healthcheck
touch "${STATE}/complete"
printf '%s\n' "ONLYOFFICE jail ready; font versions and SHA256 inventory are in private worker state."
