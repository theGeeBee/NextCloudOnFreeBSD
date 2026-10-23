"""Pure configuration validation and deployment planning (no host changes)."""

from dataclasses import asdict, dataclass, field, fields
import ipaddress
import json
import re
from pathlib import Path


SCHEMA_VERSION = 2
STATE_DIR = Path("/var/db/cloud-installer")
PRIVATE_RANGES = tuple(ipaddress.ip_network(value) for value in
                       ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

COMPREHENSIVE_FONT_ESTIMATE = (
    "Comprehensive fonts are optional. Dated estimate (2026-10-18, FreeBSD:15:amd64): "
    "about 2 GiB download / 4 GiB additional installed space over standard; "
    "not an exact cost for this selection. Allow extra font-index, package-cache and snapshot headroom. "
    "Microsoft webfonts and their required license consent are separate in both profiles."
)


PLUGIN_CHOICES = (
    ("highlightcode", "Highlight code", "code highlighting"),
    ("mendeley", "Mendeley", "external bibliography service; account/API setup"),
    ("ocr", "OCR", "browser-side recognition; external language/engine downloads"),
    ("photoeditor", "Photo editor", "browser-side image editing"),
    ("speech", "Speech", "speech provider/browser voice availability"),
    ("thesaurus", "Thesaurus", "external thesaurus service; API setup"),
    ("translator", "Translator", "external translation service"),
    ("wordpress", "WordPress", "OAuth credentials/content through ONLYOFFICE proxy; account setup"),
    ("youtube", "YouTube", "external video service"),
    ("zotero", "Zotero", "external bibliography service; account/API setup"),
)
DEFAULT_ONLYOFFICE_PLUGINS = ",".join(slug for slug, _, _ in PLUGIN_CHOICES if slug != "wordpress")


NEXTCLOUD_APP_CHOICES = (
    ("calendar", "Calendar"), ("contacts", "Contacts"), ("deck", "Deck"),
    ("files_antivirus", "Antivirus + ClamAV (log-only)"), ("mail", "Mail"),
    ("notes", "Notes"), ("spreed", "Talk"), ("tasks", "Tasks"),
)
DEFAULT_NEXTCLOUD_APPS = ",".join(slug for slug, _ in NEXTCLOUD_APP_CHOICES)
ANTIVIRUS_MEMORY_MB = 3072  # Signature-reload planning headroom, not an enforced limit.
QUOTA_FIELDS = ("data_quota_gib", "database_quota_gib", "temporary_quota_gib",
                "office_quota_gib", "logs_quota_gib", "system_quota_gib")
OFFICE_BACKENDS = ("onlyoffice", "eurooffice", "collabora", "none")
OFFICE_LABELS = {"onlyoffice": "ONLYOFFICE", "eurooffice": "Euro-Office",
                 "collabora": "Collabora CODE", "none": "Nextcloud only — no integrated document server"}
OFFICE_APP_IDS = frozenset(("onlyoffice", "eurooffice", "richdocuments",
                            "richdocumentscode", "richdocumentscode_arm64"))
NATIVE_OFFICE_FIELDS = ("onlyoffice_hostname", "ssh_onlyoffice_port", "font_profile",
                        "accept_microsoft_fonts", "additional_fonts_dir", "onlyoffice_min",
                        "onlyoffice_exact", "onlyoffice_plugins")
NO_OFFICE_FIELDS = NATIVE_OFFICE_FIELDS + ("onlyoffice_bridge", "office_memory_mb", "office_quota_gib")


def require_native_backend(config, operation):
    """Fence native-only adapters; absent selection retains the historical contract."""
    backend = getattr(config, "office_backend", "") or "onlyoffice"
    if backend != "onlyoffice":
        raise ValueError(f"{operation} is not yet supported for {OFFICE_LABELS.get(backend, 'this office_backend')}")


def validate_nextcloud_apps(value):
    """Empty is legacy omission; 'none' preserves an explicit empty selection."""
    if type(value) is not str:
        raise ValueError("nextcloud_apps must be str")
    if value in ("", "none"):
        return ()
    selected = value.split(",")
    known = {slug for slug, _ in NEXTCLOUD_APP_CHOICES}
    if any(slug not in known for slug in selected) or selected != sorted(set(selected)):
        raise ValueError("nextcloud_apps must be distinct known app IDs in alphabetical order, or none")
    return tuple(selected)


def validate_additional_nextcloud_apps(value):
    """Public App Store IDs only; native occ checks availability/compatibility."""
    if type(value) is not str:
        raise ValueError("additional_nextcloud_apps must be str")
    if not value:
        return ()
    selected = value.split(",")
    if (selected != sorted(set(selected))
            or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", slug)
                   or slug in ("none", "onlyoffice") for slug in selected)):
        raise ValueError("additional_nextcloud_apps must be distinct lowercase App Store IDs in alphabetical order (not onlyoffice or none)")
    return tuple(selected)


def validate_plugin_selection(value: str) -> tuple[str, ...]:
    """Validate the canonical public selection without discovery or side effects."""
    if type(value) is not str:
        raise ValueError("onlyoffice_plugins must be str")
    if not value:
        return ()
    selected = value.split(",")
    known = {slug for slug, _, _ in PLUGIN_CHOICES}
    if any(slug not in known for slug in selected):
        raise ValueError("onlyoffice_plugins must contain known plugin slugs without whitespace")
    if len(set(selected)) != len(selected):
        raise ValueError("onlyoffice_plugins must not contain duplicates")
    if selected != sorted(selected):
        raise ValueError("onlyoffice_plugins must be in alphabetical order")
    return tuple(selected)


@dataclass
class Config:
    schema_version: int = SCHEMA_VERSION
    instance: str = "cloud"
    pool: str = "zroot"
    public_hostname: str = ""
    nextcloud_hostname: str = ""
    onlyoffice_hostname: str = ""
    admin_username: str = "admin"
    admin_email: str = ""
    timezone: str = "UTC"
    repository: str = "latest"
    external_interface: str = ""
    ingress_address: str = ""
    dns_address: str = ""
    private_network: str = "10.77.0.0/29"
    nextcloud_bridge: str = "bridge240"
    onlyoffice_bridge: str = "bridge241"
    dns_server: str = ""
    management_network: str = ""
    management_port: int = 22
    http_port: int = 80
    https_port: int = 443
    public_https_port: int = 443
    tls_mode: str = "acme"
    proxy_networks: str = ""
    acme_email: str = ""
    certificate_file: str = ""
    private_key_file: str = ""
    ca_file: str = ""
    jail_ssh: bool = False
    ssh_username: str = "cloudop"
    ssh_key_file: str = ""
    ssh_nextcloud_port: int = 2201
    ssh_onlyoffice_port: int = 2202
    ssh_shell: str = "sh"
    ssh_admin: bool = False
    font_profile: str = "comprehensive"
    accept_microsoft_fonts: bool = False
    additional_fonts_dir: str = ""
    data_quota_gib: int = 100
    database_quota_gib: int = 20
    temporary_quota_gib: int = 10
    office_quota_gib: int = 10
    logs_quota_gib: int = 5
    system_quota_gib: int = 32
    host_reserved_mb: int = 2048
    office_memory_mb: int = 3072
    php_budget_mb: int = 1536
    php_memory_mb: int = 512
    db_buffer_mb: int = 768
    redis_memory_mb: int = 128
    upload_max_mb: int = 1024
    # Empty additions are omitted on serialization to preserve schema-2 digests.
    freebsd_release: str = ""
    architecture: str = ""
    nextcloud_min: str = ""
    onlyoffice_min: str = ""
    nextcloud_exact: str = ""
    onlyoffice_exact: str = ""
    onlyoffice_plugins: str = ""
    nextcloud_apps: str = ""
    additional_nextcloud_apps: str = ""
    storage_policy: str = ""
    office_backend: str = ""
    office_vm_cpus: int = 0
    office_vm_disk_gib: int = 0
    version_families: dict[str, str] = field(default_factory=dict)

    @property
    def backend(self):
        return self.office_backend or "onlyoffice"

    @property
    def has_office(self):
        return self.backend != "none"

    @property
    def native_office(self):
        return self.backend == "onlyoffice"

    @property
    def jails(self):
        return (self.nextcloud_jail, self.onlyoffice_jail) if self.native_office else (self.nextcloud_jail,)

    @property
    def bridges(self):
        return (self.nextcloud_bridge, self.onlyoffice_bridge) if self.has_office else (self.nextcloud_bridge,)

    def require_native_backend(self, operation):
        require_native_backend(self, operation)

    def require_jail_backend(self, operation):
        """Fresh-install adapters; native-only maintenance uses its own fence."""
        if self.backend not in OFFICE_BACKENDS:
            raise ValueError(f'{operation}: unknown office backend')

    @property
    def selected_nextcloud_apps(self):
        standard = validate_nextcloud_apps(self.nextcloud_apps)
        additional = validate_additional_nextcloud_apps(self.additional_nextcloud_apps)
        if set(standard) & set(additional):
            raise ValueError("additional_nextcloud_apps overlaps nextcloud_apps")
        return tuple(sorted(standard + additional))

    @property
    def antivirus(self):
        return "files_antivirus" in self.selected_nextcloud_apps

    @property
    def antivirus_memory_mb(self):
        return ANTIVIRUS_MEMORY_MB if self.antivirus else 0

    @property
    def selected_onlyoffice_plugins(self):
        return validate_plugin_selection(self.onlyoffice_plugins)

    @property
    def release(self):
        from .versions import defaults
        if getattr(self, "_legacy_target", None):
            return self._legacy_target.split("/")[0]
        return self.freebsd_release or defaults()["freebsd_release"]

    @property
    def arch(self):
        from .versions import defaults
        if getattr(self, "_legacy_target", None):
            return self._legacy_target.split("/")[1]
        return self.architecture or defaults()["architecture"]

    @property
    def nextcloud_jail(self):
        return self.instance + "nc"

    @property
    def onlyoffice_jail(self):
        return self.instance + "oo"

    @property
    def dataset_root(self):
        return f"{self.pool}/cloud-installer/instances/{self.instance}"

    @property
    def mount_root(self):
        return f"/srv/cloud-installer/instances/{self.instance}"

    @property
    def bastille_root(self):
        return "/srv/cloud-installer/bastille"

    @property
    def bastille_dataset(self):
        return f"{self.pool}/cloud-installer/bastille"

    @property
    def nextcloud_host(self):
        return self.nextcloud_hostname or self.nextcloud_jail

    @property
    def onlyoffice_host(self):
        return self.onlyoffice_hostname or self.onlyoffice_jail

    @property
    def public_url(self):
        port = "" if self.public_https_port == 443 else f":{self.public_https_port}"
        return f"https://{self.public_hostname}{port}/"

    @property
    def storage_url(self):
        return f"http://{self.nextcloud_ip}/" if self.tls_mode == "external" else f"https://{self.public_hostname}/"

    @property
    def callback_port(self):
        return 80 if self.tls_mode == "external" else 443

    @property
    def trusted_proxy_networks(self):
        return [str(ipaddress.IPv4Network(value.strip(), strict=False))
                for value in self.proxy_networks.split(",") if value.strip()]

    @property
    def ingress_ports(self):
        ports = [self.http_port] if self.tls_mode == "external" else [self.http_port, self.https_port]
        if self.jail_ssh:
            ports.append(self.ssh_nextcloud_port)
            if self.native_office:
                ports.append(self.ssh_onlyoffice_port)
        return ports

    @property
    def network(self):
        return ipaddress.IPv4Network(self.private_network, strict=True)

    @property
    def nextcloud_gateway(self):
        return str(self.network.network_address + 1)

    @property
    def nextcloud_ip(self):
        return str(self.network.network_address + 2)

    @property
    def onlyoffice_gateway(self):
        return str(self.network.network_address + 5)

    @property
    def onlyoffice_ip(self):
        return str(self.network.network_address + 6)

    @property
    def nextcloud_network(self):
        return str(ipaddress.ip_network(self.nextcloud_gateway + "/30", strict=False))

    @property
    def onlyoffice_network(self):
        return str(ipaddress.ip_network(self.onlyoffice_gateway + "/30", strict=False))

    @property
    def php_children(self):
        # Conservative initial ceiling, not a claim about measured worker RSS.
        return self.php_budget_mb // self.php_memory_mb

    @property
    def php_callback_children(self):
        if not self.has_office:
            return 0
        return 2 if self.php_children >= 4 else 1

    @property
    def memory_budget_mb(self):
        # Include non-buffer database overhead, Apache, OPcache and base daemons.
        return (self.host_reserved_mb + (self.office_memory_mb if self.has_office else 0) + self.php_budget_mb
                + self.db_buffer_mb + self.redis_memory_mb + 640 + self.antivirus_memory_mb)

    @property
    def total_quota_gib(self):
        # Legacy admission accounting only; not a capacity bound for optional
        # caps (or uncapped legacy data). Optional plans never use this total.
        return (self.data_quota_gib + self.database_quota_gib + self.temporary_quota_gib
                + 2 * self.office_quota_gib + 3 * self.logs_quota_gib + self.system_quota_gib + 4)

    def validate(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name == "version_families":
                from .versions import validate_families
                self.version_families = validate_families(value)
                continue
            if type(value) is not field.type:
                raise ValueError(f"{field.name} must be {field.type.__name__}")
            if isinstance(value, str) and any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError(f"{field.name} contains a control character")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("Unsupported configuration schema")
        if self.backend not in OFFICE_BACKENDS:
            raise ValueError("office_backend must be onlyoffice, eurooffice, collabora or none")
        if self.backend not in ("eurooffice", "collabora") and (self.office_vm_cpus or self.office_vm_disk_gib):
            raise ValueError("VM CPU/disk allocation applies only to VM office backends")
        if not 0 <= self.office_vm_cpus <= 256 or not 0 <= self.office_vm_disk_gib <= 1_000_000:
            raise ValueError("VM CPU/disk allocation is outside the supported configuration range")
        if not self.native_office and (self.onlyoffice_plugins or self.additional_fonts_dir
                                       or self.onlyoffice_min or self.onlyoffice_exact):
            raise ValueError("Native ONLYOFFICE plugins, custom fonts and version constraints require onlyoffice")
        if not self.native_office:
            if self.storage_policy != "optional":
                raise ValueError("Alternative profiles require optional storage policy (no quotas by default)")
            defaults = {field.name: field.default for field in fields(self)}
            irrelevant = NO_OFFICE_FIELDS if not self.has_office else NATIVE_OFFICE_FIELDS
            for name in irrelevant:
                # Dataclass defaults preserve old callers; zero is the new-wizard
                # no-allocation value. Nondefault irrelevant requests must not be
                # silently discarded by canonical serialization.
                allowed = (defaults[name], 0) if name in ("office_memory_mb", "office_quota_gib") else (defaults[name],)
                if name == "onlyoffice_bridge":
                    allowed += ("",)
                if getattr(self, name) not in allowed:
                    raise ValueError(f"{name} is not applicable to the selected office_backend")
        validate_plugin_selection(self.onlyoffice_plugins)
        _ = self.selected_nextcloud_apps  # Validate both selections and their disjoint union.
        from .versions import constraints, load_policy
        constraints(self, load_policy())
        # Bastille -B names host epairs e0a_<jail>; IFNAMSIZ permits 15
        # characters. Bastille 1.4.4 also rejects '-' and '_' in VNET jail names.
        if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", self.instance):
            raise ValueError("Instance: use 1–8 lowercase letters/digits, starting with a letter (Bastille VNET naming rules)")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,62}", self.pool):
            raise ValueError("Select an existing ZFS pool name, not a dataset or filesystem path")
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", self.public_hostname):
            raise ValueError("Enter a lowercase fully qualified DNS hostname, without scheme, port or path")
        if re.fullmatch(r"[0-9.]+", self.public_hostname):
            raise ValueError("Use a DNS hostname, not an IPv4 address, for HTTPS and document integration")
        for hostname in ((self.nextcloud_host, self.onlyoffice_host) if self.native_office else (self.nextcloud_host,)):
            if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", hostname):
                raise ValueError("Jail hostnames must be lowercase DNS hostnames, optionally fully qualified")
        if self.native_office and (self.nextcloud_host == self.onlyoffice_host or self.onlyoffice_host == self.public_hostname):
            raise ValueError("The jail hostnames must be distinct; ONLYOFFICE cannot use Nextcloud's public hostname")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}", self.admin_username):
            raise ValueError("Invalid administrator username")
        for name in ("admin_email", "acme_email"):
            value = getattr(self, name)
            if name == "admin_email" or self.tls_mode == "acme":
                local, separator, domain = value.partition("@")
                label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                if (not separator or len(value) > 254 or len(local) > 64
                        or not re.fullmatch(r"[A-Za-z0-9_+%\-]+(?:\.[A-Za-z0-9_+%\-]+)*", local)
                        or not re.fullmatch(rf"(?:{label}\.)+{label}", domain)
                        or not re.search(r"[A-Za-z]", domain.rsplit(".", 1)[-1])):
                    raise ValueError(f"Enter a valid {name}")
        if not re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", self.timezone):
            raise ValueError("Invalid timezone name")
        if self.repository not in ("latest", "quarterly"):
            raise ValueError("Repository must be latest or quarterly")
        if not re.fullmatch(r"[a-z][a-z0-9]{0,13}", self.external_interface):
            raise ValueError("Invalid external interface")
        for name in self.bridges:
            if not re.fullmatch(r"bridge[0-9]{1,4}", name):
                raise ValueError("Private bridges must be named bridge followed by a number")
        if len({self.external_interface, *self.bridges}) != len(self.bridges) + 1:
            raise ValueError("External interface and both bridges must be different")
        maximum_prefix = 29 if self.has_office else 30
        if not 16 <= self.network.prefixlen <= maximum_prefix or not any(self.network.subnet_of(net) for net in PRIVATE_RANGES):
            raise ValueError(f"Use a non-overlapping RFC1918 IPv4 network between /16 and /{maximum_prefix}")
        if not self.has_office and self.network.prefixlen != 30:
            raise ValueError("Nextcloud-only requires exactly one private /30; no office addresses are reserved")
        for name in ("ingress_address", "dns_server"):
            value = ipaddress.IPv4Address(getattr(self, name))
            if value.is_loopback or value.is_multicast or value.is_unspecified or value.is_link_local or value in self.network:
                raise ValueError(f"{name} must be a reachable address outside the jail network")
        if self.dns_address:
            address = ipaddress.IPv4Address(self.dns_address)
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address in self.network:
                raise ValueError("Expected DNS address must be the host/router ingress address, not a jail or special-use address")
        management = ipaddress.IPv4Network(self.management_network, strict=False)
        if management.overlaps(self.network):
            raise ValueError("Management network overlaps the private jail network")
        if not 1 <= self.management_port <= 65535:
            raise ValueError("Management SSH port is invalid")
        if self.management_port in (80, 443):
            raise ValueError("SSH and Nextcloud cannot share the ingress ports")
        if self.tls_mode not in ("acme", "provided", "external"):
            raise ValueError("TLS mode must be acme, provided or external (HTTPS proxy, HTTP jail)")
        for name in ("http_port", "https_port", "public_https_port", "ssh_nextcloud_port", "ssh_onlyoffice_port"):
            if not 1 <= getattr(self, name) <= 65535:
                raise ValueError(f"Invalid {name}")
        if len(set(self.ingress_ports + [self.management_port])) != len(self.ingress_ports) + 1:
            raise ValueError("Instance ingress ports and host management SSH must be distinct")
        if self.tls_mode == "acme" and self.http_port != 80:
            raise ValueError("ACME HTTP-01 requires host ingress port 80; use a separate host address or another TLS mode")
        if self.tls_mode == "external":
            if not self.trusted_proxy_networks or len(self.trusted_proxy_networks) > 32:
                raise ValueError("External TLS requires the explicit IPv4 addresses/CIDRs of the trusted reverse proxies")
            if len(set(self.trusted_proxy_networks)) != len(self.trusted_proxy_networks):
                raise ValueError("Trusted proxy networks must be distinct after CIDR normalization")
            for value in self.trusted_proxy_networks:
                network = ipaddress.IPv4Network(value)
                if (network.prefixlen < 24 or network.overlaps(self.network) or network.is_multicast
                        or network.is_loopback or network.is_link_local or network.network_address.is_unspecified):
                    raise ValueError("Use narrow proxy networks (/24–/32) outside the private jail network; prefer individual /32 addresses")
        elif self.proxy_networks:
            raise ValueError("Trusted proxy networks apply only to external TLS mode")
        for name in ("certificate_file", "private_key_file", "ca_file"):
            value = getattr(self, name)
            if value and (not Path(value).is_absolute() or ".." in Path(value).parts):
                raise ValueError(f"{name} must be an absolute path without parent traversal")
        if self.tls_mode == "provided" and not (self.certificate_file and self.private_key_file):
            raise ValueError("Provided HTTPS needs a certificate chain and matching private key")
        if self.font_profile not in ("standard", "comprehensive"):
            raise ValueError("Font profile must be standard or comprehensive")
        if self.ssh_shell not in ("sh", "zsh"):
            raise ValueError("SSH login shell must be sh or zsh")
        if self.ssh_admin and not self.jail_ssh:
            raise ValueError("SSH administrative access requires jail SSH to be enabled")
        if self.jail_ssh:
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,15}", self.ssh_username) or self.ssh_username in ("root", "operator", "www", "mysql", "redis", "onlyoffice", "nobody", "daemon", "bin", "sshd", "mailnull", "ftp", "bind", "proxy"):
                raise ValueError("Choose a dedicated non-system SSH username")
            if not self.ssh_key_file:
                raise ValueError("Optional jail SSH requires an authorized public-key file")
        for value in (self.ssh_key_file, self.additional_fonts_dir):
            if value and (not Path(value).is_absolute() or ".." in Path(value).parts):
                raise ValueError("Public-key/font paths must be absolute without parent traversal")
        if self.storage_policy not in ("", "optional"):
            raise ValueError("Storage policy must be empty (legacy) or optional")
        if self.storage_policy == "optional":
            for name in QUOTA_FIELDS:
                if not 0 <= getattr(self, name) <= 1_000_000:
                    raise ValueError(f"{name} must be 0 (no quota) or a positive GiB cap up to 1000000")
            if 0 < self.system_quota_gib < len(self.jails):
                raise ValueError("A jail-root cap must allow at least 1 GiB for each of the two jails (total at least 2 GiB)" if self.native_office else
                                 "A jail-root cap must allow at least 1 GiB for each selected jail")
        else:
            if not 1 <= self.data_quota_gib <= 1_000_000:
                raise ValueError("data_quota_gib must be a positive GiB quota")
            for name in ("database_quota_gib", "temporary_quota_gib", "office_quota_gib", "logs_quota_gib"):
                if not 1 <= getattr(self, name) <= 1_000_000:
                    raise ValueError(f"{name} must be a positive GiB quota")
            if self.system_quota_gib < 24:
                raise ValueError("Reserve at least 24 GiB quota for jail roots, base releases and package caches")
        if self.host_reserved_mb < 1024 or (self.has_office and self.office_memory_mb < 2048):
            raise ValueError("Reserve at least 1 GiB for the host and 2 GiB for ONLYOFFICE; larger deployments need more")
        if not 512 <= self.php_memory_mb <= 4096 or not 2 <= self.php_children <= 128:
            raise ValueError("PHP needs at least 512 MiB/request and a budget for 2–128 workers")
        if not 256 <= self.db_buffer_mb <= 1048576 or not 64 <= self.redis_memory_mb <= 32768:
            raise ValueError("Database buffer or Redis budget is outside the supported range")
        if (not 32 <= self.upload_max_mb <= 16384
                or (self.temporary_quota_gib and self.upload_max_mb > self.temporary_quota_gib * 1024 // 2)):
            raise ValueError("Upload chunk limit must be 32–16384 MiB and leave temporary-storage headroom")
        return self

    def validate_provisioning(self):
        # Keep legacy schema-2 state readable for inspection/removal. Only new
        # planning/provisioning needs the revised capacity floor; locked resumes
        # still require their original artifact, not a silent budget rewrite.
        self.validate()
        if set(self.selected_nextcloud_apps) & OFFICE_APP_IDS:
            raise ValueError("Office connectors and embedded servers cannot be installer-managed additional apps; select an office_backend")
        if self.native_office and self.storage_policy != "optional" and self.font_profile == "comprehensive" and self.system_quota_gib < 32:
            raise ValueError("Comprehensive fonts require at least 32 GiB for jail roots/releases/cache (16 GiB per thick jail); increase the allowance or choose standard fonts")
        if self.has_office and self.php_children < 3:
            raise ValueError("New deployments need at least 3 PHP workers: 2 web and 1 office callback; increase the PHP budget without exceeding host memory")
        return self

    def to_dict(self):
        value = asdict(self)
        # Registry JSON sorts nested keys. Preserve the historical outer field
        # order, but canonicalize this map before computing an immutable digest.
        if value["version_families"]:
            value["version_families"] = dict(sorted(value["version_families"].items()))
        for key in ("freebsd_release", "architecture", "nextcloud_min", "onlyoffice_min", "nextcloud_exact", "onlyoffice_exact", "onlyoffice_plugins", "nextcloud_apps", "additional_nextcloud_apps", "storage_policy", "office_backend", "office_vm_cpus", "office_vm_disk_gib", "version_families"):
            if not value[key]:
                value.pop(key)
        if not self.native_office:
            for key in NO_OFFICE_FIELDS if not self.has_office else NATIVE_OFFICE_FIELDS:
                value.pop(key, None)
        return value

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2) + "\n"

    @classmethod
    def from_json(cls, text):
        value = json.loads(text)
        if not isinstance(value, dict) or set(value) - {field.name for field in fields(cls)}:
            raise ValueError("Unknown configuration fields (secrets belong in the separate secret file)")
        backend = value.get("office_backend", "") or "onlyoffice"
        if backend not in ("eurooffice", "collabora") and any(key in value for key in ("office_vm_cpus", "office_vm_disk_gib")):
            raise ValueError("VM CPU/disk recipe fields apply only to VM office backends")
        if backend in ("none", "eurooffice", "collabora"):
            forbidden = NO_OFFICE_FIELDS if backend == "none" else NATIVE_OFFICE_FIELDS
            if any(key in value for key in forbidden):
                raise ValueError("Remove office-only/native-only recipe fields for the selected office_backend")
            if value.get("storage_policy", "optional") != "optional":
                raise ValueError("New alternative profiles require optional storage policy (no quotas by default)")
            value.setdefault("storage_policy", "optional")
            if backend == "none":
                value.setdefault("private_network", "10.77.0.0/30")
        if value.get("storage_policy") == "optional":
            for name in QUOTA_FIELDS:
                value.setdefault(name, 0)
        config = cls(**value)
        if not config.version_families and not any(key in value for key in ("freebsd_release", "architecture", "nextcloud_min", "onlyoffice_min", "nextcloud_exact", "onlyoffice_exact")):
            from .versions import load_policy
            config._legacy_target = load_policy()["legacy_target"]
        return config.validate()


@dataclass(frozen=True)
class Dataset:
    name: str
    mountpoint: str
    jail: str = ""
    target: str = ""
    quota_gib: int = 0
    recordsize: str = "128K"
    executable: bool = False

    @property
    def properties(self):
        result = {"mountpoint": self.mountpoint, "compression": "lz4", "atime": "off",
                  "dedup": "off", "sync": "standard", "primarycache": "all", "recordsize": self.recordsize,
                  "setuid": "on" if self.executable and not self.jail else "off",
                  "exec": "on" if self.executable else "off"}
        if self.quota_gib:
            result["quota"] = f"{self.quota_gib}G"
        return result


def datasets(config):
    """Flat storage children avoid implicit parent mountpoints or delegated ZFS."""
    c = config.validate()
    root, mount = c.dataset_root, c.mount_root
    result = [
        Dataset(root, mount, quota_gib=0 if c.storage_policy == "optional" else c.total_quota_gib - c.system_quota_gib, executable=True),
        Dataset(root + "/nc-app", mount + "/nc-app", c.nextcloud_jail, "/usr/local/www/nextcloud", 0 if c.storage_policy == "optional" else 4, executable=True),
        Dataset(root + "/nc-data", mount + "/nc-data", c.nextcloud_jail, "/var/nc-data", c.data_quota_gib),
        Dataset(root + "/nc-database", mount + "/nc-database", c.nextcloud_jail, "/var/db/mysql", c.database_quota_gib, "16K"),
        Dataset(root + "/nc-db-logs", mount + "/nc-db-logs", c.nextcloud_jail, "/var/log/mysql", c.logs_quota_gib),
        Dataset(root + "/nc-logs", mount + "/nc-logs", c.nextcloud_jail, "/var/log", c.logs_quota_gib),
        Dataset(root + "/nc-tmp", mount + "/nc-tmp", c.nextcloud_jail, "/var/nc-tmp", c.temporary_quota_gib),
    ]
    if c.native_office:
        result.extend([
        Dataset(root + "/office-runtime", mount + "/office-runtime", c.onlyoffice_jail, "/var/db/onlyoffice", c.office_quota_gib),
        Dataset(root + "/office-data", mount + "/office-data", c.onlyoffice_jail, "/usr/local/www/onlyoffice/Data", c.office_quota_gib),
        Dataset(root + "/office-logs", mount + "/office-logs", c.onlyoffice_jail, "/var/log", c.logs_quota_gib),
        ])
    elif c.has_office:
        result.append(Dataset(root + "/office-vm", mount + "/office-vm", quota_gib=c.office_quota_gib))
    return result


def storage_summary(config):
    c = config
    if c.storage_policy == "optional":
        caps = [f"{name.removesuffix('_quota_gib')} {getattr(c, name)} GiB"
                for name in QUOTA_FIELDS if getattr(c, name)]
        selection = "operator caps: " + ", ".join(caps) if caps else "no installer quotas"
        return (f"Storage: {selection}; no installer-imposed instance-parent or nc-app ceiling. "
                "Uncapped datasets have no local quota; selected caps are not a full growth bound. "
                "No space reservations are created or capacity guaranteed. Pool/ancestor limits still apply. "
                "Data and snapshots can exhaust storage and disrupt all services; monitor usage and retain free headroom.")
    return f"Storage: shared/bounded; planned capacity {c.total_quota_gib} GiB including jail roots."


def deployment_plan(config):
    c = config.validate_provisioning()
    dns = (f"External frontend DNS: {c.dns_address or 'proxy-managed A/AAAA; no required host-IP match'}"
           if c.tls_mode == "external" else
           f"Expected DNS A address: {c.dns_address or c.ingress_address} (router WAN address when behind NAT)")
    from .versions import constraints, load_policy
    versions = constraints(c, load_policy())
    lines = [f"Host: FreeBSD {c.release}; {c.arch}; Bastille thick VNET jails; jail base {c.release}",
             f"Versions requested: Nextcloud >= {versions['nextcloud_min']} (exact: {versions['nextcloud_exact'] or 'none'})" +
             (f"; ONLYOFFICE >= {versions['onlyoffice_min']} (exact: {versions['onlyoffice_exact'] or 'none'})" if c.native_office else ""),
              "Static plan only: availability and compatibility must resolve successfully before provisioning.",
              "Configured version families: " + (", ".join(f"{key} {value}" for key, value in sorted(c.version_families.items())) or "none (reviewed policy ranges apply)"),
             f"Login: {c.public_url} (administrator {c.admin_username})",
             f"HTTPS: {c.tls_mode}; package branch: {c.repository}",
             f"Ingress: {c.external_interface} {c.ingress_address} ports {c.ingress_ports} -> isolated instance jails",
             dns,
             f"SSH: {c.management_network} -> host TCP {c.management_port}; other inbound traffic denied",
             f"IPv6: not configured for jails; host inbound IPv6 denied by managed policy",
             f"{c.nextcloud_jail} ({c.nextcloud_host}): {c.nextcloud_ip}/30 via {c.nextcloud_gateway} on {c.nextcloud_bridge}",
             *([f"{c.onlyoffice_jail} ({c.onlyoffice_host}): {c.onlyoffice_ip}/30 via {c.onlyoffice_gateway} on {c.onlyoffice_bridge}",
                f"Internal flows: NC -> ONLYOFFICE TCP 8081; ONLYOFFICE -> NC TCP {c.callback_port}"] if c.native_office else
               [f"Profile: {OFFICE_LABELS[c.backend]}; one Nextcloud jail.",
                "No office runtime, connector, office network, proxy or callback allowance.",
                "An administrator may install a compatible connector and configure an external server manually later."] if not c.has_office else
               [f"Profile: {OFFICE_LABELS[c.backend]}; one Nextcloud jail plus one dedicated Alpine/bhyve/Docker VM (not a Bastille jail).",
                f"Planned private VM endpoint: {c.onlyoffice_ip}/30 via {c.onlyoffice_gateway} on {c.onlyoffice_bridge}.",
                 f"Internal flows: NC -> office TCP 8081; office -> NC TCP {c.callback_port}; host -> guest provisioning SSH only.",
                 "Native end-to-end acceptance is pending; do not treat this plan as production readiness."]),
             f"Proxy trust: {c.trusted_proxy_networks or 'none'}; jail SSH: {'enabled, key-only' if c.jail_ssh else 'disabled'}",
             *([f"Fonts: {c.font_profile}; additional font directory: {c.additional_fonts_dir or 'none'}",
             f"Required Microsoft webfonts license consent: {'accepted by operator' if c.accept_microsoft_fonts else 'NOT accepted — installation cannot proceed'}",
             f"ONLYOFFICE plugins requested for installation: {', '.join(c.selected_onlyoffice_plugins) or 'none'}; no autostart."] if c.native_office else []),
             f"Nextcloud apps via occ: {', '.join(c.selected_nextcloud_apps) or 'none (legacy omission or explicit none)'}; native app-manager checks, no force.",
             ("Mail: NC jail outbound public TCP 993/465/587 only; no inbound mail listener. Configure accounts in Mail; system notification SMTP remains disabled."
              if "mail" in c.selected_nextcloud_apps else "Mail mailbox egress: disabled."),
             (f"Antivirus: log-only (not upload blocking/deletion); private clamd socket; {c.antivirus_memory_mb} MiB extra planning allowance. Scan stream limit 100 MiB; not all content is covered."
              if c.antivirus else "Antivirus: not selected."),
             "Talk uses existing HTTPS; external TURN may be needed for client NAT. No local TURN/HPB or new media ports.",
             *(["External plugin providers may receive selected content when invoked; accounts/API keys are configured separately. Installation does not establish service functionality.",
                "EasyBib is discontinued/unavailable; Macros is built-in, not a standalone plugin."] if c.native_office else []),
             f"Egress: DNS to {c.dns_server}, HTTP/HTTPS for packages, apps and ACME",
             f"PHP-FPM: {c.php_children} workers (" +
             (f"{c.php_children - c.php_callback_children} web + {c.php_callback_children} office callback" if c.has_office else "web only") +
             f"); {c.php_memory_mb} MiB/request; {c.php_budget_mb} MiB pool budget",
             f"Memory planning total: {c.memory_budget_mb} MiB (includes host and 640 MiB service overhead)",
             "Budgets are starting estimates, not RCTL limits; monitor real workload/ARC memory use.",
             "Email delivery is disabled until an SMTP relay/egress policy is configured; " +
             ("database backup/restore is available from the menu." if c.native_office else "native-only upgrade/maintenance/backup operations are unsupported for this profile."),
             storage_summary(c),
             "No existing datasets are destroyed or adopted during installation.",
             "Datasets (host mount -> jail mount):"]
    for dataset in datasets(c):
        target = f" -> {dataset.jail}:{dataset.target}" if dataset.jail else ""
        quota = f"{dataset.quota_gib} GiB" if dataset.quota_gib else "no local quota"
        lines.append(f"  {dataset.name}: {dataset.mountpoint}{target} [{quota}, {dataset.recordsize}]")
    if c.native_office and c.font_profile == "comprehensive":
        lines.append(COMPREHENSIVE_FONT_ESTIMATE)
    lines.extend(["A private configuration/secret store will be created under " + str(STATE_DIR) + ".",
                  f"PF/NAT, IPv4 forwarding, {'two private bridges' if c.has_office else 'one private bridge'} and boot configuration will change.",
                  "Only this installer's managed PF/Bastille resources may be extended; unrelated deployments are never adopted.",
                  "Completed phases are checkpointed. Resume validates configuration and resources before replaying safe phases."])
    if c.has_office and not c.native_office:
        lines.append(f"VM allocation: {c.office_vm_cpus or 'not selected'} vCPU; {c.office_memory_mb} MiB total guest RAM; "
                     f"{c.office_vm_disk_gib or 'not selected'} GiB finite disk capacity (separate from optional dataset quota).")
        lines.append("Fresh-install VM adapter: pinned artifacts, owned disk, selected connector; no backend migration or native-only maintenance/backup.")
    elif not c.has_office:
        lines.append("Nextcloud-only implementation is offline-validated; native fresh-install/browser/reboot acceptance is not yet run.")
    return "\n".join(lines)
