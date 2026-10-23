#!/bin/sh
# Trusted common worker functions. Only public validated scalars cross from UCL
# into shell variables; runtime.json and packages.lock are never shell programs.

# Do not inherit pkg environment overrides (ABI, repositories, signature/TLS
# exceptions) from the operator. The base shim is used only for pkg bootstrap.
pkg() {
    if [ -x /usr/local/sbin/pkg ]; then
        /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/local/sbin/pkg -C /dev/null "$@"
    else
        /usr/bin/env -i PATH="$PATH" LC_ALL=C /usr/sbin/pkg "$@"
    fi
}

version_private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || fail 'Missing regular version payload input.'
    [ "$(stat -f '%u:%Lp' "$1")" = "0:$2" ] || fail 'Version payload ownership or mode changed.'
    [ "$(stat -f '%z' "$1")" -le "$3" ] || fail 'Version payload exceeds the size limit.'
}

version_load() {
    case "$(stat -f '%u:%Lp' "$RUNTIME")" in
        0:600|0:400) ;;
        *) fail 'runtime.json must be root-owned and private-mode.' ;;
    esac
    [ -f "$RUNTIME" ] && [ ! -L "$RUNTIME" ] && [ "$(stat -f '%z' "$RUNTIME")" -le 65536 ] \
        || fail 'Invalid public runtime input.'
    VERSION_LOCK=$PAYLOAD/packages.lock
    VERSION_DEPENDENCIES=$PAYLOAD/packages.dependencies
    VERSION_CONNECTOR=$PAYLOAD/connector.json
    version_private_file "$VERSION_LOCK" 600 1048576
    version_private_file "$VERSION_DEPENDENCIES" 600 1048576
    [ -x /usr/libexec/flua ] || fail 'FreeBSD base flua is required to validate the version plan.'
    version_settings=$(/usr/libexec/flua - "$RUNTIME" "$VERSION_LOCK" "$VERSION_DEPENDENCIES" "$1" <<'LUA'
local ok, result = pcall(function()
    local parser = require("ucl").parser()
    assert(parser:parse_file(arg[1]))
    local runtime = parser:get_object()
    assert(type(runtime) == "table")
    assert(runtime.repository == "latest" or runtime.repository == "quarterly")
    local v = runtime.versions
    assert(type(v) == "table")
    local keys = {"nextcloud", "onlyoffice", "connector", "php", "database", "freebsd_release",
        "architecture", "php_package", "plan_sha256", "packages_sha256", "dependencies_sha256", "connector_sha256"}
    local none = v.office_backend == "none"
    local vm = v.office_backend == "eurooffice" or v.office_backend == "collabora"
    if none then
        assert(arg[4] == "nextcloud")
        assert(runtime.onlyoffice_ip == nil and runtime.storage_url == nil)
        keys = {"nextcloud", "php", "database", "freebsd_release", "architecture", "php_package",
            "plan_sha256", "packages_sha256", "dependencies_sha256", "office_backend"}
    elseif vm then
        assert(arg[4] == "nextcloud")
        assert(v.connector_app == (v.office_backend == "eurooffice" and "eurooffice" or "richdocuments"))
        keys = {"nextcloud", "php", "database", "freebsd_release", "architecture", "php_package",
            "plan_sha256", "packages_sha256", "dependencies_sha256", "connector", "connector_app", "connector_sha256", "office_backend"}
    end
    local allowed = {}
    for _, key in ipairs(keys) do
        allowed[key] = true
        assert(type(v[key]) == "string" and #v[key] <= 128)
    end
    for key in pairs(v) do assert(allowed[key]) end
    local function numeric(value)
        return value:match("^%d+%.[%d.]+$") and not value:find("..", 1, true)
            and not value:match("%.$")
    end
    assert(v.nextcloud:match("^%d+%.%d+%.%d+$"))
    if not none and not vm then
        assert(v.onlyoffice:match("^%d+%.%d+%.%d+$"))
    end
    if not none then
        assert(v.connector:match("^%d+%.%d+%.%d+$"))
        assert(#v.connector_sha256 == 64 and v.connector_sha256:match("^[a-f0-9]+$"))
    end
    assert(numeric(v.php) and numeric(v.database))
    assert(v.freebsd_release:match("^%d+%.%d+%-RELEASE$"))
    assert(v.architecture:match("^[a-z][a-z0-9_]*$"))
    assert(v.php_package:match("^php%d+$"))
    for _, key in ipairs({"plan_sha256", "packages_sha256", "dependencies_sha256"}) do
        assert(#v[key] == 64 and v[key]:match("^[a-f0-9]+$"))
    end
    local file = assert(io.open(arg[2], "rb"))
    local text = assert(file:read("*a"))
    file:close()
    assert(#text > 0 and #text <= 1048576 and text:sub(-1) == "\n")
    local previous, names = nil, {}
    for line in text:gmatch("([^\n]*)\n") do
        local name, version, origin, checksum = line:match("^([^|]+)|([^|]+)|([^|]+)|([^|]+)$")
        assert(name and #name <= 256 and #version <= 256 and #origin <= 256 and #checksum <= 256)
        assert(name:match("^[A-Za-z0-9][A-Za-z0-9_+%.%-]*$"))
        assert(version:match("^[A-Za-z0-9%._+][A-Za-z0-9%.+_,~:%-]*$"))
        assert(origin:match("^[A-Za-z0-9][A-Za-z0-9_+%.%-]*/[A-Za-z0-9][A-Za-z0-9_+%.%-]*$"))
        assert(checksum:match("^%d+%$[A-Za-z0-9]+$") or (#checksum == 64 and checksum:match("^[a-fA-F0-9]+$")))
        assert(not names[name] and (not previous or previous < line))
        names[name], previous = {version=version, origin=origin}, line
    end
    file = assert(io.open(arg[3], "rb"))
    text = assert(file:read("*a"))
    file:close()
    assert(#text <= 1048576 and (#text == 0 or text:sub(-1) == "\n"))
    local edges = {}
    previous = nil
    for line in text:gmatch("([^\n]*)\n") do
        local owner, name, version, origin = line:match("^([^|]+)|([^|]+)|([^|]+)|([^|]+)$")
        assert(owner and names[owner] and names[name])
        assert(names[name].version == version and names[name].origin == origin)
        local edge = owner .. "|" .. name
        assert(not edges[edge] and (not previous or previous < line))
        edges[edge], previous = true, line
    end
    local function upstream(version)
        return version and version:gsub(",%d+$", ""):gsub("_%d+$", "")
    end
    if arg[4] == "nextcloud" then
        assert(names[v.php_package] and upstream(names[v.php_package].version) == v.php)
    elseif arg[4] == "onlyoffice" then
        assert(names["onlyoffice-documentserver"] and upstream(names["onlyoffice-documentserver"].version) == v.onlyoffice)
    else
        error("Unknown worker group")
    end
    local values = {runtime.repository}
    for _, key in ipairs(keys) do values[#values + 1] = v[key] end
    return (vm and (v.office_backend .. " ") or none and "none " or "") .. table.concat(values, " ")
end)
if not ok then os.exit(1) end
print(result)
LUA
    ) || fail 'Invalid public versions or package lock; retain the original plan and installer artifact.'
    version_office_backend=onlyoffice
    if [ "${version_settings%% *}" = none ]; then
        version_settings=${version_settings#* }
        read -r repository version_nextcloud version_php version_database version_release \
            version_architecture version_php_package version_plan_sha256 version_packages_sha256 \
            version_dependencies_sha256 version_office_backend <<EOF
$version_settings
EOF
    elif [ "${version_settings%% *}" = eurooffice ] || [ "${version_settings%% *}" = collabora ]; then
        version_settings=${version_settings#* }
        read -r repository version_nextcloud version_php version_database version_release \
            version_architecture version_php_package version_plan_sha256 version_packages_sha256 \
            version_dependencies_sha256 version_connector version_connector_app version_connector_sha256 version_office_backend <<EOF
$version_settings
EOF
    else
        read -r repository version_nextcloud version_onlyoffice version_connector version_php version_database \
        version_release version_architecture version_php_package version_plan_sha256 version_packages_sha256 version_dependencies_sha256 version_connector_sha256 <<EOF
$version_settings
EOF
    fi
    if [ "$version_office_backend" != none ]; then
        version_private_file "$VERSION_CONNECTOR" 600 65536
        [ "$(sha256 -q "$VERSION_CONNECTOR")" = "$version_connector_sha256" ] \
            || fail 'connector.json differs from the immutable runtime digest; restore the original signed release record.'
    fi
    [ "$(sha256 -q "$VERSION_LOCK")" = "$version_packages_sha256" ] \
        || fail 'packages.lock differs from the immutable runtime digest; restore the original staged lock.'
    [ "$(sha256 -q "$VERSION_DEPENDENCIES")" = "$version_dependencies_sha256" ] \
        || fail 'packages.dependencies differs from the immutable runtime digest; restore the original staged dependency lock.'
}

version_environment() {
    [ "$(uname -s)" = FreeBSD ] || fail 'The selected FreeBSD target is required.'
    [ "$(uname -m)" = "$version_architecture" ] || fail 'The jail architecture differs from the selected target.'
    version_kernel=$(uname -r) || fail 'Cannot read the running kernel release.'
    version_userland=$(freebsd-version -u) || fail 'Cannot read the jail userland release.'
    for version_actual in "$version_kernel" "$version_userland"; do
        case "$version_actual" in
            "$version_release") ;;
            "$version_release"-p*)
                version_patch=${version_actual#"$version_release"-p}
                case "$version_patch" in ''|*[!0-9]*) fail 'Expected a stable patch of the selected FreeBSD release.' ;; esac
                ;;
            *) fail 'Kernel and jail userland must match the selected FreeBSD release; retain the original target.' ;;
        esac
    done
}

version_packages_check() {
    version_packages_inventory
    while IFS='|' read -r version_name version_value version_origin version_checksum; do
        version_installed=$(pkg query '%v|%o' "$version_name" < /dev/null) \
            || fail "Selected package is missing: $version_name. Resume requires the original package lock."
        [ "$version_installed" = "$version_value|$version_origin" ] \
            || fail "Installed package differs from the lock: $version_name. Automatic upgrades/downgrades are refused."
    done < "$VERSION_LOCK"
}

version_packages_inventory() {
    version_inventory=$(pkg query -a '%n|%v|%o' < /dev/null) || fail 'Cannot inspect installed package versions.'
    printf '%s\n' "$version_inventory" | awk -F '|' '
        NR == FNR {selected[$1]=1; next}
        # Thick pkgbase jails inherit the signed base-release package database.
        # Require both the reserved base name and its matching origin; this is
        # not permission for unselected ports or automatic OS upgrades.
        NF != 3 {exit 1}
        $1 ~ /^FreeBSD-[A-Za-z0-9_+.-]+$/ && $3 == "base/" $1 {next}
        $1 != "pkg" && !($1 in selected) {exit 1}
    ' "$VERSION_LOCK" - || fail 'Installed application packages outside the selected closure are refused; only bootstrap pkg and identified pkgbase packages may be extra.'
}

# Call only after signed pkg bootstrap/catalog update. Verify the entire closure
# before either install invocation; never resolve roots against a newer catalog.
version_packages_install() {
    version_packages_inventory
    set --
    while IFS='|' read -r version_name version_value version_origin version_checksum; do
        # Extended %u is the catalog's archive sum; legacy %X is not that sum.
        # Empty inline iteration selects pkg_printf without emitting any edges.
        version_remote=$(pkg rquery -U -r FreeBSD-ports '%n|%v|%o|%u%d%{%|%}' "$version_name" < /dev/null) \
            || fail "Exact package unavailable: $version_name-$version_value. Retain the original artifact and repository; do not change the lock."
        [ "$version_remote" = "$version_name|$version_value|$version_origin|$version_checksum" ] \
            || fail "Repository drift for $version_name-$version_value. Restore the original repository/artifact; do not change the lock."
        version_remote_dependencies=$(pkg rquery -U -r FreeBSD-ports '%dn|%dv|%do' "$version_name" < /dev/null) \
            || fail "Cannot verify exact dependencies for $version_name; retain the original repository and lock."
        version_remote_dependencies=$(printf '%s' "$version_remote_dependencies" | LC_ALL=C sort)
        version_expected_dependencies=$(awk -F '|' -v name="$version_name" '$1 == name {print $2 "|" $3 "|" $4}' "$VERSION_DEPENDENCIES")
        [ "$version_remote_dependencies" = "$version_expected_dependencies" ] \
            || fail "Repository dependency drift for $version_name. Restore the original repository/artifact; do not change the lock."
        version_installed=$(printf '%s\n' "$version_inventory" | awk -F '|' -v name="$version_name" '$1 == name {print $2 "|" $3}')
        [ -z "$version_installed" ] || [ "$version_installed" = "$version_value|$version_origin" ] \
            || fail "Installed package differs from the lock: $version_name. Automatic upgrades/downgrades are refused."
        set -- "$@" "$version_name-$version_value"
    done < "$VERSION_LOCK"
    [ "$#" -gt 0 ] || fail 'An empty package lock cannot be installed.'
    # pkg 2.8.4 needs -y for a successful dry-run status; retain -n.
    (umask 022; pkg install -n -y -U -r FreeBSD-ports "$@" < /dev/null) \
        || fail 'Locked package preflight failed; retain the original lock and repository.'
    (umask 022; pkg install -y -U -r FreeBSD-ports "$@" < /dev/null) \
        || fail 'Locked package installation failed; resume only with the original lock and repository.'
    version_packages_check
}
