"""Pure configuration rendering for the private native ONLYOFFICE VNET jail.

Importing this module does not provision anything. The host uses
``connector_settings(config)`` and ``apache_proxy(config)`` for the Nextcloud
payload; neither function needs access to a Nextcloud installation. The
``prepare`` CLI reads public runtime.json, package files, and a JWT-only JSON
object on stdin. It writes a new private staging directory, removed on error.
Deployment and service lifecycle belong to resources/jails/onlyoffice.sh.
"""

import argparse
from collections.abc import Mapping
import configparser
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import struct
import sys
import tempfile
from urllib.parse import urlsplit

if __package__:
    from . import office_config
    from .version_runtime import validate_runtime_versions
else:
    # Direct-path execution is supported from any cwd, including a jail payload.
    # Python already puts the script directory on sys.path for this invocation.
    import office_config
    from version_runtime import validate_runtime_versions


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "resources/templates/onlyoffice"
PACKAGE_ETC = Path("/usr/local/etc/onlyoffice/documentserver")
CA_DESTINATION = str(PACKAGE_ETC / "nextcloud-ca.pem")
NGINX_PORT = 8081
DOCSERVICE_PORT = 8000
RUNTIME_KEYS = (
    "public_hostname", "public_url", "storage_url", "nextcloud_ip", "onlyoffice_ip",
    "repository", "tls_mode", "font_profile", "additional_fonts", "accept_microsoft_fonts",
    "versions",
)
REQUIRED_FONT_FAMILIES = (
    "DejaVu Sans", "Liberation Sans", "Arimo", "Caladea", "Carlito", "FreeSans",
    "Noto Sans", "Noto Serif", "Noto Sans Mono",
)
FONT_DESTINATION = Path("/usr/local/share/fonts/cloud-custom")
FONT_ROOTS = (Path("/usr/local/share/fonts"),
              Path("/usr/local/www/onlyoffice/documentserver/core-fonts"),
              Path("/usr/local/www/onlyoffice/Data/custom-fonts"))
GENERATED_FONTS = tuple(Path("/usr/local/www/onlyoffice/documentserver") / name for name in (
    "sdkjs/common/AllFonts.js", "server/FileConverter/bin/AllFonts.js",
    "server/FileConverter/bin/font_selection.bin"))


def validate_runtime(config):
    """Validate public office settings, optionally retaining an in-memory JWT.

    Host callers may pass their larger in-memory configuration. The file loader
    is stricter: no credential (including JWT) is permitted in runtime.json.
    """
    if not isinstance(config, Mapping):
        raise ValueError("The runtime must be a JSON object")
    config = dict(config)
    config.setdefault("public_url", f'https://{config.get("public_hostname", "")}/')
    config.setdefault("storage_url", (f'http://{config.get("nextcloud_ip", "")}/'
                                     if config.get("tls_mode") == "external" else config["public_url"]))
    config.setdefault("font_profile", "comprehensive")
    config.setdefault("additional_fonts", False)
    config.setdefault("accept_microsoft_fonts", False)
    if any(not isinstance(config.get(key), str) for key in RUNTIME_KEYS[:-3]):
        raise ValueError("The runtime is missing a required office string field")
    config["versions"] = validate_runtime_versions(config.get("versions"))
    result = {key: config[key] for key in RUNTIME_KEYS}
    hostname = result["public_hostname"]
    label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    if (len(hostname) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", hostname)
            or re.fullmatch(r"[0-9.]+", hostname)):
        raise ValueError("public_hostname must be a DNS hostname without a port")
    private_networks = tuple(ipaddress.IPv4Network(net) for net in
                             ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    for key in ("nextcloud_ip", "onlyoffice_ip"):
        try:
            address = ipaddress.IPv4Address(result[key])
        except ipaddress.AddressValueError:
            raise ValueError("Jail addresses must be private IPv4 addresses") from None
        if not any(address in network for network in private_networks):
            raise ValueError("Jail addresses must be RFC1918 IPv4 addresses")
    if result["nextcloud_ip"] == result["onlyoffice_ip"]:
        raise ValueError("Nextcloud and ONLYOFFICE require distinct jail addresses")
    if "jwt_secret" in config:
        result["jwt_secret"] = validate_jwt(config["jwt_secret"])
    if result["repository"] not in ("latest", "quarterly"):
        raise ValueError("repository must be latest or quarterly")
    if result["tls_mode"] not in ("acme", "provided", "external"):
        raise ValueError("tls_mode must be acme, provided or external")
    public_url = office_config.public_base_url(result["public_url"])
    if urlsplit(public_url).hostname.lower() != hostname.lower():
        raise ValueError("The public URL must use public_hostname")
    result["public_url"] = public_url
    # External TLS terminates at the edge, while callbacks use the private HTTP
    # Nextcloud backend. Public scheme/authority never come from that backend.
    storage_url = result["storage_url"]
    if result["tls_mode"] == "external":
        if storage_url != f'http://{result["nextcloud_ip"]}/':
            raise ValueError("External TLS storage_url must use the private HTTP Nextcloud backend")
    else:
        storage_url = office_config.public_base_url(storage_url)
        if urlsplit(storage_url).hostname.lower() != hostname.lower():
            raise ValueError("Direct TLS storage_url must use the public HTTPS hostname")
        result["storage_url"] = storage_url
    if result["font_profile"] not in ("standard", "comprehensive"):
        raise ValueError("font_profile must be standard or comprehensive")
    additional = result["additional_fonts"]
    if not isinstance(additional, bool) and not (
            isinstance(additional, str) and additional.startswith("/")
            and not re.search(r"[\x00-\x1f\x7f]", additional)):
        raise ValueError("additional_fonts must be a boolean or a public absolute directory path")
    if type(result["accept_microsoft_fonts"]) is not bool:
        raise ValueError("Microsoft font license consent must be an explicit boolean")
    return result


def validate_jwt(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise ValueError("jwt_secret must contain 64 hexadecimal characters")
    return value


def read_credentials(stream):
    """Consume only the office credential; reject bundles, extra data and keys."""
    text = stream.read(4097)
    if len(text) > 4096:
        raise ValueError("Credential input is too large")
    value = strict_json(text)
    if not isinstance(value, dict) or set(value) != {"jwt_secret"}:
        raise ValueError("Expected a JWT-only JSON object on stdin")
    return {"jwt_secret": validate_jwt(value["jwt_secret"])}


def strict_json(text):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique_pairs)


def connector_settings(config):
    """Return an occ config:import object, containing only connector settings."""
    config = validate_runtime(config)
    base_url = config["public_url"]
    return {"apps": {"onlyoffice": {
        "DocumentServerUrl": base_url + "onlyoffice/",
        "DocumentServerInternalUrl": f'http://{config["onlyoffice_ip"]}:{NGINX_PORT}/',
        "StorageUrl": config["storage_url"],
        "jwt_secret": validate_jwt(config.get("jwt_secret")),
        "jwt_header": "AuthorizationJWT",
        "verify_peer_off": "false",
    }}}


def apache_proxy(config):
    """Render the scoped Apache include, independently of backend TLS mode."""
    config = validate_runtime(config)
    template = (TEMPLATES / "proxy.conf").read_text()
    proxy = office_config.proxy_config(template, config["public_url"], NGINX_PORT)
    old_backend = f"http://127.0.0.1:{NGINX_PORT}/"
    if proxy.count(old_backend) != 2:
        raise ValueError("Unexpected Apache ONLYOFFICE proxy template")
    return proxy.replace(old_backend, f'http://{config["onlyoffice_ip"]}:{NGINX_PORT}/')


def local_configuration(original, config):
    """Preserve vendor overrides and the helper-generated secure-link secret."""
    config = validate_runtime(config)
    secret = original.get("storage", {}).get("fs", {}).get("secretString")
    if not isinstance(secret, str) or not secret or secret == "verysecretstring":
        raise ValueError("Run the secure-link helper before rendering local.json")
    # The callback resolves to Nextcloud's private IP. PF on the host is the
    # destination boundary; metadata addresses remain forbidden by the app.
    rendered = office_config.local_config(original, validate_jwt(config.get("jwt_secret")), True)
    rendered["services"]["CoAuthoring"].setdefault("server", {})["port"] = DOCSERVICE_PORT
    return rendered


def nginx_frontend(original, config):
    config = validate_runtime(config)
    listener = f'{config["onlyoffice_ip"]}:{NGINX_PORT}'
    if re.findall(r"(?m)^\s*listen\s+([^;]+);", original) == [listener]:
        return original  # An interrupted, already-owned rendering attempt.
    rendered = office_config.nginx_frontend(original, NGINX_PORT)
    # Change ONLY the frontend listener: vendor localhost upstreams are correct
    # in this true-VNET jail and must not be redirected to the Nextcloud jail.
    return rendered.replace(f"listen 127.0.0.1:{NGINX_PORT};",
                            f'listen {config["onlyoffice_ip"]}:{NGINX_PORT};', 1)


def supervisor_program(original, name):
    """Keep native commands/environment while enabling bounded child logs.

    Source: FreeBSD ports www/onlyoffice-documentserver/files/ds-{docservice,
    metrics}.conf and Supervisor 4.3 configuration documentation. The vendor
    sets all four rotation fields to zero; no signalling/restart is needed
    for Supervisor's own per-process rotation.
    """
    locations = {"docservice": "DocService/docservice", "metrics": "Metrics/metrics"}
    binary = "/usr/local/www/onlyoffice/documentserver/server/" + locations[name]
    expected_command = binary + (" ./config/config.js" if name == "metrics" else "")
    parsed = configparser.ConfigParser(interpolation=None)
    parsed.read_string(original)
    section = f"program:{name}"
    if parsed.sections() != [section]:
        raise ValueError("Unexpected ONLYOFFICE Supervisor program layout")
    program = parsed[section]
    if (program.get("command") != expected_command or program.get("user") != "onlyoffice"
            or program.get("directory") != str(Path(binary).parent)):
        raise ValueError("Unexpected ONLYOFFICE Supervisor command or user")
    if name == "docservice" and (
            "NODE_ENV=production-freebsd" not in program.get("environment", "")
            or f"NODE_CONFIG_DIR={PACKAGE_ETC}" not in program.get("environment", "")):
        raise ValueError("Unexpected native DocService environment")
    for stream, filename in (("stdout", "out.log"), ("stderr", "err.log")):
        if program.get(f"{stream}_logfile") != f"/var/log/onlyoffice/documentserver/{name}/{filename}":
            raise ValueError("Unexpected ONLYOFFICE Supervisor log path")
        for field, value in (("maxbytes", "10MB"), ("backups", "5")):
            key = f"{stream}_logfile_{field}"
            original, count = re.subn(rf"(?m)^{key}\s*=\s*[0-9]+\s*$",
                                      f"{key}={value}", original)
            if count != 1:
                raise ValueError("Unexpected ONLYOFFICE Supervisor rotation layout")
    return original


def render_files(config, original, frontend, internal, programs, group, ca_pem=None):
    """Render jail files in memory. No commands, network access or deployment."""
    config = validate_runtime(config)
    local = local_configuration(original, config)
    links = re.findall(r"(?m)^\s*set\s+\$secure_link_secret\s+([^;]+);", frontend)
    if len(links) != 1 or links[0].strip().strip('"\'') != local["storage"]["fs"]["secretString"]:
        raise ValueError("nginx and local.json secure-link secrets must match")
    group_config = configparser.ConfigParser(interpolation=None)
    group_config.read_string(group)
    if (group_config.sections() != ["group:ds"]
            or group_config["group:ds"].get("programs") != "docservice,metrics"
            or set(programs) != {"docservice", "metrics"}):
        raise ValueError("Expected the native ds:docservice and ds:metrics group")

    supervisor = (TEMPLATES / "supervisord.conf").read_text()
    if ("pidfile=/var/run/supervisor/supervisord.pid" not in supervisor
            or supervisor.count("; ONLYOFFICE_CA_ENV") != 1):
        raise ValueError("Unexpected Supervisor root template")
    supervisor = supervisor.replace("logfile=/var/log/supervisord.log\n",
                                    "logfile=/var/log/supervisord.log\n"
                                    "logfile_maxbytes=10MB\nlogfile_backups=5\n")
    nginx = (TEMPLATES / "nginx.conf").read_text()
    if nginx.count("worker_processes auto;\n") != 1:
        raise ValueError("Unexpected nginx root template")
    nginx = nginx.replace("worker_processes auto;\n", "worker_processes auto;\n"
                          "pid /var/run/nginx.pid;\n"
                          "error_log /var/log/onlyoffice/documentserver/nginx.error.log;\n")
    files = {
        "local.json": json.dumps(local, indent=2) + "\n",
        "ds.conf": nginx_frontend(frontend, config),
        "ds-docservice.conf": office_config.restrict_nginx_internal(internal),
        "nginx.conf": nginx,
        "supervisor-ds.conf": group,
        # The stock sample sends SIGHUP; explicitly reopen nginx logs with
        # SIGUSR1 instead. Supervisor rotates its logs itself, without restart.
        "nginx-newsyslog.conf": (
            "# nginx log reopening; child logs are rotated by Supervisor.\n"
            "/var/log/onlyoffice/documentserver/nginx.error.log "
            "root:wheel 640 7 10240 @T00 BJ /var/run/nginx.pid SIGUSR1\n"),
        "healthcheck-url": f'http://{config["onlyoffice_ip"]}:{NGINX_PORT}/healthcheck\n',
        "onlyoffice-ip": config["onlyoffice_ip"] + "\n",
    }
    for name in ("docservice", "metrics"):
        files[f"supervisor-ds-{name}.conf"] = supervisor_program(programs[name], name)
    if ca_pem is not None:
        if config["tls_mode"] != "provided" or "PRIVATE KEY" in ca_pem:
            raise ValueError("The optional CA must be a certificate bundle for provided TLS")
        try:
            ssl.create_default_context().load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError):
            raise ValueError("Invalid Nextcloud CA certificate bundle") from None
        files["nextcloud-ca.pem"] = ca_pem
        supervisor = supervisor.replace("; ONLYOFFICE_CA_ENV",
                                        f'environment=NODE_EXTRA_CA_CERTS="{CA_DESTINATION}"')
    files["supervisord.conf"] = supervisor
    return files


def load_runtime(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536:
        raise ValueError("runtime.json must be a private regular file")
    value = strict_json(path.read_text())
    if not isinstance(value, dict) or set(value) - set(RUNTIME_KEYS):
        raise ValueError("runtime.json may contain only public office settings")
    return validate_runtime(value)


def write_private(path, text):
    """Exclusive and private from creation, with no partial file on failure."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink()
        raise


def remember(path, value):
    """Persist nonsecret resume evidence once; a changed plan is never adopted."""
    path = Path(path)
    text = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or path.read_text() != text):
            raise ValueError("Installer-owned resume evidence does not match")
    else:
        # A crash cannot leave a half-written marker that looks committed.
        with tempfile.TemporaryDirectory(prefix="evidence-", dir=path.parent) as directory:
            temporary = Path(directory) / "value"
            write_private(temporary, text)
            os.link(temporary, path)  # Atomic and exclusive, unlike replace().


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def securelink_matches(package):
    """Check both helper-managed frontends against the backend without printing it."""
    package = Path(package)
    original = strict_json((package / "local.json").read_text())
    secret = original.get("storage", {}).get("fs", {}).get("secretString")
    if not isinstance(secret, str) or not secret or secret == "verysecretstring":
        return False
    for name in ("ds.conf", "ds-ssl.conf"):
        text = (package / "nginx" / name).read_text()
        links = re.findall(r"(?m)^\s*set\s+\$secure_link_secret\s+([^;]+);", text)
        # The native TLS template has multiple server blocks (three in 9.4.0_4).
        # The helper updates every directive; all must agree with the backend.
        if not links or any(link.strip().strip('\"\'') != secret for link in links):
            return False
    return True


def deployment_paths(package=PACKAGE_ETC, system_etc=Path("/usr/local/etc")):
    package, system_etc = Path(package), Path(system_etc)
    paths = {"local.json": package / "local.json", "ds.conf": package / "nginx/ds.conf",
             "ds-docservice.conf": package / "nginx/includes/ds-docservice.conf",
             "nextcloud-ca.pem": package / "nextcloud-ca.pem",
             "nginx.conf": system_etc / "nginx/nginx.conf",
             "supervisord.conf": system_etc / "supervisord.conf",
             "nginx-newsyslog.conf": system_etc / "newsyslog.conf.d/onlyoffice-nginx.conf"}
    for name in ("ds", "ds-docservice", "ds-metrics"):
        paths[f"supervisor-{name}.conf"] = package / f"supervisor/{name}.conf"
    return paths


def prepare(args, credentials=None):
    """Read inputs completely before creating a private, exclusive staging dir."""
    config = load_runtime(args.runtime)
    config.update(read_credentials(sys.stdin) if credentials is None else credentials)
    config = validate_runtime(config)
    validate_jwt(config.get("jwt_secret"))
    package = Path(args.package_etc)
    pristine = Path(getattr(args, "pristine_etc", None) or package)
    if {path.name for path in (package / "supervisor").glob("*.conf")} != {
            "ds.conf", "ds-docservice.conf", "ds-metrics.conf"}:
        raise ValueError("Unexpected ONLYOFFICE Supervisor include files")
    files = render_files(
        config, json.loads((package / "local.json").read_text()),
        (package / "nginx/ds.conf").read_text(),
        (pristine / "nginx/includes/ds-docservice.conf").read_text(),
        {name: (pristine / f"supervisor/ds-{name}.conf").read_text()
         for name in ("docservice", "metrics")},
        (pristine / "supervisor/ds.conf").read_text(),
        Path(args.ca_file).read_text() if args.ca_file else None,
    )
    if getattr(args, "state", None):
        state = Path(args.state)
        remember(state / "credential-sha256.json", hashlib.sha256(config["jwt_secret"].encode()).hexdigest())
        remember(state / "configuration.json", {
            name: hashlib.sha256(contents.encode()).hexdigest()
            for name, contents in files.items() if name in deployment_paths()})
    staging = Path(args.staging)
    staging.mkdir(mode=0o700)
    try:
        for name, contents in files.items():
            write_private(staging / name, contents)
    except BaseException:
        shutil.rmtree(staging)
        raise


def font_file_info(path):
    """Validate an untrusted supplied sfnt/collection, without executing a parser.

    A signature/table-boundary check is an input filter, not a full font parser.
    The package's font engine still determines which glyphs/styles are usable.
    """
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111 or info.st_size < 12:
            raise ValueError("Custom fonts must be non-executable regular font files")
        header = stream.read(12)
        expected = {".ttf": (b"\x00\x01\x00\x00", b"true"), ".otf": (b"OTTO",), ".ttc": (b"ttcf",)}
        if header[:4] not in expected.get(path.suffix.lower(), ()):
            raise ValueError("Unrecognized custom font format or signature")
        if header[:4] == b"ttcf":
            count = struct.unpack(">I", header[8:12])[0]
            if header[4:8] not in (b"\x00\x01\x00\x00", b"\x00\x02\x00\x00") or not 0 < count <= 65535:
                raise ValueError("Invalid font collection header")
            if 12 + 4 * count > info.st_size:
                raise ValueError("Truncated font collection")
            offsets = struct.unpack(f">{count}I", stream.read(4 * count))
        else:
            offsets = (0,)
        for offset in offsets:
            if offset + 12 > info.st_size:
                raise ValueError("Truncated font header")
            stream.seek(offset)
            sfnt = stream.read(12)
            count = struct.unpack(">H", sfnt[4:6])[0]
            if (sfnt[:4] not in (b"\x00\x01\x00\x00", b"true", b"OTTO")
                    or not count or offset + 12 + count * 16 > info.st_size):
                raise ValueError("Invalid font table directory")
        stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        return {"size": info.st_size, "sha256": digest.hexdigest()}


def custom_font_plan(config, source):
    source = Path(source)
    enabled = bool(config["additional_fonts"])
    if source.is_symlink() or (source.exists() and not source.is_dir()):
        raise ValueError("The custom font source must be a real directory")
    files = []
    if source.exists():
        for path in sorted(source.rglob("*")):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("Symlinks are forbidden in custom fonts")
            if stat.S_ISDIR(info.st_mode):
                continue
            relative = path.relative_to(source).as_posix()
            if not relative.isprintable():
                raise ValueError("Custom font paths must not contain control characters")
            files.append(dict(path=relative, **font_file_info(path)))
    if enabled != bool(files):
        raise ValueError("Custom font input does not match additional_fonts")
    return {"enabled": enabled, "files": files}


def install_custom_fonts(config, source, state, destination=FONT_DESTINATION):
    source, state, destination = Path(source), Path(state), Path(destination)
    plan = custom_font_plan(config, source)
    marker = state / "custom-fonts.json"
    if not marker.exists() and (destination.exists() or destination.is_symlink()):
        raise ValueError("Refusing an unowned custom font destination")
    remember(marker, plan)
    if not plan["enabled"]:
        if destination.exists() or destination.is_symlink():
            raise ValueError("Unexpected custom font destination")
        return
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError("Custom font destination must be a real directory")
    destination.mkdir(mode=0o755, exist_ok=True)
    if destination.stat().st_mode & 0o777 != 0o755:
        destination.chmod(0o755)  # The worker deliberately uses umask 077.
    expected = {item["path"]: item for item in plan["files"]}
    for path in destination.rglob("*"):
        if path.is_symlink():
            raise ValueError("Unexpected symlink in owned custom fonts")
        if path.is_dir():
            continue
        if path.name.startswith(".cloud-font-") and path.is_file():
            path.unlink()  # Interrupted atomic copy inside this owned directory.
        elif path.relative_to(destination).as_posix() not in expected:
            raise ValueError("Unexpected file in owned custom fonts")
    for item in plan["files"]:
        target = destination / item["path"]
        for parent in reversed(target.relative_to(destination).parents):
            directory = destination / parent
            directory.mkdir(mode=0o755, exist_ok=True)
            if directory.stat().st_mode & 0o777 != 0o755:
                directory.chmod(0o755)
        if target.exists():
            if font_file_info(target) != {key: item[key] for key in ("size", "sha256")}:
                raise ValueError("An installed custom font changed")
            continue
        fd, name = tempfile.mkstemp(prefix=".cloud-font-", dir=target.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as output, os.fdopen(os.open(
                    source / item["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as input_stream:
                current = os.fstat(input_stream.fileno())
                if not stat.S_ISREG(current.st_mode) or current.st_mode & 0o111:
                    raise ValueError("A supplied font changed during copying")
                shutil.copyfileobj(input_stream, output, 1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            if sha256_file(temporary) != item["sha256"]:
                raise ValueError("A supplied font changed during copying")
            temporary.chmod(0o644)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)


def font_paths(roots=FONT_ROOTS):
    # Package/core fonts can use the wider set supported by ONLYOFFICE. User
    # input deliberately accepts just sfnt TTF/OTF/TTC, with checked signatures.
    extensions = {".ttf", ".otf", ".ttc", ".otc", ".tte", ".woff", ".woff2"}
    return sorted({path for root in roots if root.exists() for path in root.rglob("*")
                   if path.suffix.lower() in extensions and path.is_file()})


def verify_custom_fonts(config, source, state, destination=FONT_DESTINATION):
    destination = Path(destination)
    plan = strict_json((Path(state) / "custom-fonts.json").read_text())
    if plan != custom_font_plan(config, source):
        raise ValueError("Supplied fonts changed since installation")
    if not plan["enabled"]:
        if destination.exists() or destination.is_symlink():
            raise ValueError("Unexpected custom font destination")
        return
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("Custom font destination must remain a real directory")
    expected = {item["path"]: item for item in plan["files"]}
    found = set()
    for path in (destination, *destination.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            if info.st_mode & 0o777 != 0o755:
                raise ValueError("Custom font directories must remain mode 0755")
            continue
        relative = path.relative_to(destination).as_posix()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o777 != 0o644 or relative not in expected:
            raise ValueError("Unexpected custom font file or permissions")
        if font_file_info(path) != {key: expected[relative][key] for key in ("size", "sha256")}:
            raise ValueError("An installed custom font changed")
        found.add(relative)
    if found != set(expected):
        raise ValueError("An installed custom font is missing")


def font_inventory(config, state, roots=FONT_ROOTS, generated=GENERATED_FONTS):
    state = Path(state)
    faces = {}
    families = set()
    # fc-list emits LF record separators, but family/style metadata may contain
    # Unicode NEL or other characters that str.splitlines() also treats as lines.
    # Preserve those values (and embedded CR) instead of inventing broken records.
    records = (state / "fontconfig.tsv").read_bytes().decode("utf-8")
    for line in records.removesuffix("\n").split("\n"):
        path, family, style = line.split("\t", 2)
        faces.setdefault(path, []).append({"family": family, "style": style})
        families.update(family.split(","))
    if not set(REQUIRED_FONT_FAMILIES) <= families:
        raise ValueError("Required core font families are missing from fontconfig")
    for path in generated:
        if not path.is_file() or not path.stat().st_size:
            raise ValueError("ONLYOFFICE font helper did not produce all required outputs")
        if path.suffix == ".js" and any(name not in path.read_text() for name in REQUIRED_FONT_FAMILIES):
            raise ValueError("ONLYOFFICE did not register required core font families")
    packages = []
    for line in (state / "packages.installed").read_text().splitlines():
        name, version, origin = line.split("|", 2)
        packages.append({"name": name, "version": version, "origin": origin})
    if not packages:
        raise ValueError("An empty package inventory is not valid")
    files = [{"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size,
              "faces": faces.get(str(path), [])} for path in font_paths(roots)]
    if not files:
        raise ValueError("No usable font files were found")
    return {"profile": config["font_profile"], "packages": sorted(packages, key=lambda item: item["name"]),
            "unavailable_optional": (state / "fonts-unavailable").read_text().splitlines(),
            "fonts": files, "generated": {str(path): sha256_file(path) for path in generated}}


def verify_font_inventory(state, roots=FONT_ROOTS):
    inventory = strict_json((Path(state) / "fonts.json").read_text())
    if {str(path) for path in font_paths(roots)} != {item["path"] for item in inventory["fonts"]}:
        raise ValueError("The installed font file set changed")
    hashes = {item["path"]: item["sha256"] for item in inventory["fonts"]}
    hashes.update(inventory["generated"])
    for name, digest in hashes.items():
        if not hmac.compare_digest(sha256_file(name), digest):
            raise ValueError("An installed font or generated font registry changed")


def verify_configuration(args, config):
    package, state = Path(args.package_etc), Path(args.state)
    if not securelink_matches(package):
        raise ValueError("Secure-link configuration no longer matches")
    paths = deployment_paths(package, args.system_etc)
    hashes = strict_json((state / "configuration.json").read_text())
    if set(hashes) != set(paths) - ({"nextcloud-ca.pem"} if not args.ca_file else set()):
        raise ValueError("Incomplete configuration inventory")
    for name, digest in hashes.items():
        path = paths[name]
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022
                or not hmac.compare_digest(sha256_file(path), digest)):
            raise ValueError("An installed ONLYOFFICE configuration changed")
    local = strict_json((package / "local.json").read_text())
    expected = local_configuration(local, config)
    if local != expected:
        raise ValueError("Installed JWT, callback or TLS settings do not match")
    if (package / "local.json").stat().st_mode & 0o777 != 0o640:
        raise ValueError("local.json must remain mode 0640")
    if {path.name for path in (package / "supervisor").glob("*.conf")} != {
            "ds.conf", "ds-docservice.conf", "ds-metrics.conf"}:
        raise ValueError("Unexpected Supervisor include files")


def verify(args):
    config = load_runtime(args.runtime)
    state = Path(args.state)
    if args.command == "verify-deployed":
        local = strict_json((Path(args.package_etc) / "local.json").read_text())
        config["jwt_secret"] = validate_jwt(local["services"]["CoAuthoring"]["secret"]["inbox"]["string"])
    else:
        config.update(read_credentials(sys.stdin))
    binding = strict_json((state / "credential-sha256.json").read_text())
    if not hmac.compare_digest(binding, hashlib.sha256(config["jwt_secret"].encode()).hexdigest()):
        raise ValueError("The credential does not match this owned installation")
    verify_configuration(args, config)
    verify_custom_fonts(config, args.font_source, state)
    verify_font_inventory(state)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("prepare")
    render.add_argument("--runtime", default="/root/cloud-installer/runtime.json")
    render.add_argument("--package-etc", default=str(PACKAGE_ETC))
    render.add_argument("--staging", required=True)
    render.add_argument("--ca-file")
    render.add_argument("--pristine-etc")
    render.add_argument("--state")
    link = commands.add_parser("check-securelink")
    link.add_argument("--package-etc", default=str(PACKAGE_ETC))
    for name in ("install-fonts", "inventory-fonts", "verify-fonts", "verify", "verify-deployed"):
        command = commands.add_parser(name)
        command.add_argument("--runtime", default="/root/cloud-installer/runtime.json")
        command.add_argument("--state", required=True)
        command.add_argument("--font-source", default="/root/cloud-installer/fonts")
        if name in ("verify", "verify-deployed"):
            command.add_argument("--package-etc", default=str(PACKAGE_ETC))
            command.add_argument("--system-etc", default="/usr/local/etc")
            command.add_argument("--ca-file")
    check = commands.add_parser("check-runtime")
    check.add_argument("--runtime", default="/root/cloud-installer/runtime.json")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare(args)
        elif args.command == "check-securelink":
            if not securelink_matches(args.package_etc):
                raise ValueError("Secure-link secrets do not match")
        elif args.command in ("verify", "verify-deployed"):
            verify(args)
        else:
            config = load_runtime(args.runtime)
            if args.command == "install-fonts":
                install_custom_fonts(config, args.font_source, args.state)
            elif args.command == "inventory-fonts":
                remember(Path(args.state) / "fonts.json", font_inventory(config, args.state))
            elif args.command == "verify-fonts":
                verify_custom_fonts(config, args.font_source, args.state)
                verify_font_inventory(args.state)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, configparser.Error, struct.error):
        # A malformed private input must not produce a traceback with secrets.
        parser.exit(1, "ONLYOFFICE validation failed; check public settings, private state and package layout.\n")


if __name__ == "__main__":
    main()
