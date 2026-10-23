"""Interactive configuration; configuration remains data, never shell code."""

from dataclasses import replace
import ipaddress
import secrets
import sys

from .config import (COMPREHENSIVE_FONT_ESTIMATE, DEFAULT_NEXTCLOUD_APPS, DEFAULT_ONLYOFFICE_PLUGINS, NEXTCLOUD_APP_CHOICES,
                     Config, OFFICE_BACKENDS, OFFICE_LABELS, PLUGIN_CHOICES, QUOTA_FIELDS, deployment_plan, storage_summary,
                     validate_nextcloud_apps, validate_plugin_selection)
from .ui import TerminalUI


def ask(label, default="", convert=str, *, ui=None):
    ui = ui or TerminalUI()
    while True:
        try:
            return convert(ui.input(label, default))
        except (ValueError, TypeError) as error:
            ui.message(f"Invalid value: {error}")


def choose(label, choices, default, *, ui=None):
    return (ui or TerminalUI()).menu(label, [(choice, choice) for choice in choices], default)


def confirm(label, *, ui=None):
    return (ui or TerminalUI()).confirm(label)


def select_version_families(config, *, ui, policy=None):
    """Small version-step extension; other package choices remain JSON-only."""
    from .versions import load_policy, selected_profiles, stable_version, validate_families
    policy = load_policy() if policy is None else policy
    profiles = selected_profiles(config, policy)
    def lower(rule):
        return rule.get("exact", rule.get("min", rule.get("family")))

    profile = max(profiles, key=lambda item: stable_version(
        lower(item["applications"]["nextcloud"])))
    choices = [("nextcloud", "Nextcloud", profile["applications"]["nextcloud"], 1),
               ("php", "PHP", profile["roles"]["php"]["range"], 2),
               ("database", "Database", profile["roles"]["database"]["range"], 2)]
    if config.native_office:
        choices.append(("onlyoffice", "ONLYOFFICE", profile["applications"]["onlyoffice"], 2))
    if config.has_office:
        choices.append(("connector", "Office connector", profile["connector"]["version"], 1))
    selected = dict(config.version_families)
    ui.message("Version families select a stable major or major.minor line; '-' clears a choice. "
               "Minimums and exact pins still apply. Other roles/packages can be selected in JSON recipes.")
    for key, label, rule, components in choices:
        default = selected.get(key, rule.get("family", ".".join(lower(rule).split(".")[:components])))

        def family(value):
            if value in ("", "-"):
                return ""
            return validate_families({key: value})[key]

        value = ask(label + " version family", default, family, ui=ui)
        if value:
            selected[key] = value
        else:
            selected.pop(key, None)
    config.version_families = selected


def select_onlyoffice_plugins(value="", *, ui=None):
    ui = ui or TerminalUI()
    selected = set(validate_plugin_selection(value))
    all_plugins = {slug for slug, _, _ in PLUGIN_CHOICES}
    ui.message("Optional ONLYOFFICE plugins do not autostart. External providers may receive selected content "
               "when invoked; accounts/API keys are configured separately. Installation does not establish service functionality.\n"
               "WordPress sends OAuth credentials/tokens and article content through an ONLYOFFICE-hosted proxy.\n"
               "EasyBib is discontinued/unavailable. Macros is built-in, not a standalone plugin.")
    standard = set(DEFAULT_ONLYOFFICE_PLUGINS.split(","))
    default = "all" if selected == all_plugins else "standard" if selected == standard else "custom" if selected else "none"
    action = ui.menu("ONLYOFFICE plugins", [("none", "None"), ("standard", "Standard Docs plugins (9; Macros is built in)"), ("all", "All 10 listed plugins"),
                                           ("custom", "Choose individual plugins")], default)
    if action == "none":
        return ""
    if action == "standard":
        return DEFAULT_ONLYOFFICE_PLUGINS
    if action == "all":
        return ",".join(sorted(all_plugins))
    if action != "custom":
        raise ValueError("Unknown ONLYOFFICE plugin selection")
    while True:
        choices = [(slug, f"[{'x' if slug in selected else ' '}] {name} — {summary}")
                   for slug, name, summary in PLUGIN_CHOICES]
        choices.extend([("all", "Select all"), ("none", "Select none"), ("done", "Done")])
        action = ui.menu("Choose individual ONLYOFFICE plugins", choices, "done")
        if action == "done":
            return ",".join(sorted(selected))
        if action == "all":
            selected = set(all_plugins)
        elif action == "none":
            selected.clear()
        elif action in all_plugins:
            selected.symmetric_difference_update({action})
        else:
            raise ValueError("Unknown ONLYOFFICE plugin selection")


def select_nextcloud_apps(value, *, ui):
    selected = set(validate_nextcloud_apps(value))
    all_apps = {slug for slug, _ in NEXTCLOUD_APP_CHOICES}
    ui.message("Nextcloud installs/enables selected apps through occ; no separate app feature tests. "
               "Mail permits NC-jail outbound public TCP 993/465/587 (IMAPS/SMTP submission); "
               "configure accounts afterward. No inbound mail server or system SMTP. "
               "Talk may need external TURN for restrictive client NAT; no local TURN/HPB. "
               "Antivirus includes ClamAV and is log-only, not blocking/deletion; adds 3072 MiB RAM planning headroom.")
    default = "all" if selected == all_apps else "custom" if selected else "none"
    action = ui.menu("Nextcloud apps", [("all", "All 8 selections"), ("none", "None"),
                                      ("custom", "Choose individual apps")], default)
    if action == "all":
        return DEFAULT_NEXTCLOUD_APPS
    if action == "none":
        return "none" if value else ""
    if action != "custom":
        raise ValueError("Unknown Nextcloud app selection")
    while True:
        choices = [(slug, f"[{'x' if slug in selected else ' '}] {label}") for slug, label in NEXTCLOUD_APP_CHOICES]
        choices += [("all", "Select all"), ("none", "Select none"), ("done", "Done")]
        action = ui.menu("Choose individual Nextcloud apps", choices, "done")
        if action == "done":
            return ",".join(sorted(selected)) or "none"
        if action == "all":
            selected = set(all_apps)
        elif action == "none":
            selected.clear()
        elif action in all_apps:
            selected.symmetric_difference_update({action})
        else:
            raise ValueError("Unknown Nextcloud app selection")


def service_memory(config):
    return config.memory_budget_mb - config.host_reserved_mb


def remaining_memory(facts, registered, reserve):
    return facts["memory_mb"] - reserve - sum(service_memory(c) for c in registered)


def resource_review(facts, config, registered):
    """Describe initial allocations using the same accounting as validation."""
    remaining = remaining_memory(facts, registered, config.host_reserved_mb)
    allocated = service_memory(config)
    php = (f"PHP-FPM: {config.php_children} workers "
           + (f"({config.php_children - config.php_callback_children} web + {config.php_callback_children} office callback); "
              if config.has_office else "(web only); ") +
           f"{config.php_memory_mb} MiB/request."
           if config.php_memory_mb > 0 and config.php_children >= (3 if config.has_office else 2) else
           "PHP-FPM: invalid worker budget/limit; adjust budgets before approval.")
    return "\n".join([
        f"Initial sizing: {facts['memory_mb']} MiB detected RAM; {config.host_reserved_mb} MiB host/ZFS reserve; "
        f"{sum(service_memory(c) for c in registered)} MiB reserved by {len(registered)} other instance(s).",
        f"{remaining} MiB remains for this instance after those reservations; "
        f"selected {allocated} MiB (includes 640 MiB service overhead); {remaining - allocated} MiB left unallocated.",
        (f"{OFFICE_LABELS[config.backend]} {config.office_memory_mb} MiB; " if config.has_office else "") +
        f"MariaDB buffer {config.db_buffer_mb} MiB; "
        f"Redis {config.redis_memory_mb} MiB; PHP pool {config.php_budget_mb} MiB; antivirus {config.antivirus_memory_mb} MiB.",
        php,
        f"Upload chunk limit: {config.upload_max_mb} MiB; temporary-data quota: "
        + (f"{config.temporary_quota_gib} GiB. " if config.temporary_quota_gib else "no quota. ") +
        "Choose upload limits for your usage and storage, not CPU/RAM alone.",
        f"Pool {config.pool}: {facts['available_gib'][config.pool]} GiB currently available; "
        "retain free storage headroom for growth, package operations and snapshots.",
        storage_summary(config),
        "Budgets are conservative starting estimates, not enforced memory limits or measured workload optimization. "
        "Leave room for other host workloads and future instances; adjust the initial budgets if needed. "
        "Selected settings apply before first startup, not in a post-install tuning pass.",
    ])


def storage_inspection(facts, pool):
    """Present native facts without adding overlapping parent/child usage."""
    storage = facts.get("storage", {}).get(pool)
    if not storage:
        return (f"Pool {pool}: {facts['available_gib'][pool]} GiB currently available. "
                "Detailed native storage inspection unavailable; no ancestor/snapshot assessment shown.")

    def gib(value):
        return f"{value / (1024 ** 3):.1f} GiB"

    lines = [f"Native storage inspection: pool {pool}; health {storage['health']}; "
             f"size {gib(storage['size'])}; allocated {gib(storage['allocated'])}; free {gib(storage['free'])}.",
             "Dataset figures overlap across ancestors; do not sum them. Snapshot usage is per dataset."]
    for name, properties in sorted(storage["datasets"].items()):
        limits = "; ".join(f"{key}={gib(properties[key])}" for key in
                          ("quota", "refquota", "reservation", "refreservation") if properties[key])
        lines.append(f"  {name}: used {gib(properties['used'])}; available {gib(properties['available'])}; "
                     f"referenced {gib(properties['referenced'])}; snapshots {gib(properties['usedbysnapshots'])}; "
                     f"{limits or 'no local caps/reservations'}.")
    return "\n".join(lines)


def unused_network(facts, registered, *, prefix=29):
    occupied = [c.network for c in registered]
    for value in (facts.get("management_network"), *facts.get("networks", ())):
        if value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version == 4:
                occupied.append(network)
    address = ipaddress.IPv4Address(facts["address"])
    for block in ("10.77.0.0/16", "172.30.0.0/16", "192.168.240.0/20"):
        for candidate in ipaddress.IPv4Network(block).subnets(new_prefix=prefix):
            if address not in candidate and not any(candidate.overlaps(network) for network in occupied):
                return str(candidate)
    raise ValueError(f"No unused default private /{prefix} is available in the managed network ranges")


def used_ports(registered, address, management_port):
    ports = {management_port}
    for c in registered:
        if c.ingress_address != address:
            continue
        ports.update(c.ingress_ports)
    return ports


def next_port(start, occupied):
    for port in range(start, 65536):
        if port not in occupied:
            occupied.add(port)
            return port
    raise ValueError("No unused ingress port is available")


def vm_initial_budgets(config, available_mb, *, policy=None):
    """Pure VM allocation including three PHP workers for callback headroom.

    available_mb already excludes the shared host, other instances and selected
    app allowance. Never shrink the reviewed guest default to fit a small host.
    """
    from .versions import vm_resource_policy
    allocation = vm_resource_policy(config, policy)['defaults']
    office = allocation['memory_mb']
    php_floor = 3 * config.php_memory_mb
    minimum = office + php_floor + 256 + 64 + 640
    if available_mb < minimum:
        raise ValueError(f'Only {available_mb} MiB remains after host/registered/app budgets; '
                         f'a new VM-backed instance needs at least {minimum} MiB')
    database, redis, php = 256, 64, php_floor
    if available_mb >= office + 2048 + 256 + max(3072, php_floor) + 640:
        database, redis, php = 2048, 256, max(3072, php_floor)
    elif available_mb >= office + 768 + 128 + max(2048, php_floor) + 640:
        database, redis, php = 768, 128, max(2048, php_floor)
    return dict(office_memory_mb=office, office_vm_cpus=allocation['cpus'],
                office_vm_disk_gib=allocation['disk_gib'], db_buffer_mb=database,
                redis_memory_mb=redis, php_budget_mb=php)


def initial_config(facts, registered=(), *, nextcloud_apps="", office_backend=""):
    backend = office_backend or "onlyoffice"
    if backend not in OFFICE_BACKENDS:
        raise ValueError("Unknown office backend")
    native = backend == "onlyoffice"
    vm = backend in ('eurooffice','collabora')
    registered = tuple(registered)
    memory = facts["memory_mb"]
    first = registered[0] if registered else None
    managed = facts.get("managed_host") or {}
    host = first.host_reserved_mb if first else managed.get("host_reserved_mb", max(2048, memory // 4))
    antivirus = Config(nextcloud_apps=nextcloud_apps).antivirus_memory_mb
    remaining = remaining_memory(facts, registered, host) - antivirus
    minimum = 4544 if native else 1984  # Two 512 MiB PHP workers, DB 256, Redis 64, overhead 640.
    if remaining < minimum:
        raise ValueError(f"Only {remaining} MiB remains after host/registered/app budgets; a new instance needs at least {minimum} MiB")
    # Conservative defaults leave room for another instance on a 16 GiB host.
    vm_budgets = {}
    if vm:
        candidate = Config(office_backend=backend, freebsd_release=facts.get('freebsd_release',''),
                           architecture=facts.get('architecture',''))
        vm_budgets = vm_initial_budgets(candidate, remaining)
        office, database, redis, php = (vm_budgets[key] for key in
            ('office_memory_mb','db_buffer_mb','redis_memory_mb','php_budget_mb'))
    elif not native:
        office = 0
        if memory >= 32768 and remaining >= 6144:
            database, redis, php = 2048, 256, 3072
        elif remaining >= 3584:
            database, redis, php = 768, 128, 2048
        else:
            database, redis, php = 256, 64, 1024
    elif memory >= 32768 and remaining >= 10240:
        office, database, redis, php = 4096, 2048, 256, 3072
    elif remaining >= 6144:
        office, database, redis, php = 3072, 768, 128, 1536
    else:
        office, database, redis, php = 2048, 256, 64, 1536
    config = Config(pool=first.pool if first else managed.get("pool", facts["pools"][0]),
                    office_backend="" if native else backend,
                    onlyoffice_plugins=DEFAULT_ONLYOFFICE_PLUGINS if native else "",
                    storage_policy="optional", **{name: 0 for name in QUOTA_FIELDS},
                    freebsd_release=facts.get("freebsd_release", ""), architecture=facts.get("architecture", ""),
                    external_interface=first.external_interface if first else managed.get("external_interface", facts["interface"]),
                    ingress_address=facts["address"], dns_server=facts["dns"],
                    management_network=first.management_network if first else managed.get("management_network", facts["management_network"]),
                    management_port=first.management_port if first else managed.get("management_port", facts["ssh_port"]),
                    nextcloud_apps=nextcloud_apps,
                    host_reserved_mb=host, office_memory_mb=office, php_budget_mb=php,
                     db_buffer_mb=database, redis_memory_mb=redis)
    if vm:
        config.office_vm_cpus = vm_budgets['office_vm_cpus']
        config.office_vm_disk_gib = vm_budgets['office_vm_disk_gib']
    names = {c.instance for c in registered} | set(facts.get("reserved_instances", ()))
    for name in ("cloud", *(f"cloud{number}" for number in range(2, 1000))):
        if name not in names:
            config.instance = name
            break
    else:
        raise ValueError("Choose a new instance name; the default names are already registered")
    config.private_network = unused_network(facts, registered, prefix=29 if config.has_office else 30)
    bridges = {name for c in registered for name in c.bridges}
    bridges.update(facts.get("bridges", ()))
    bridges.update(facts.get("interfaces", ()))
    available_bridges = (f"bridge{number}" for number in range(240, 10000)
                         if f"bridge{number}" not in bridges)
    try:
        config.nextcloud_bridge = next(available_bridges)
        if config.has_office:
            config.onlyoffice_bridge = next(available_bridges)
        else:
            config.onlyoffice_bridge = ""
    except StopIteration:
        raise ValueError("No unused default bridge names are available") from None
    occupied = used_ports(registered, config.ingress_address, config.management_port)
    if any(c.ingress_address == config.ingress_address for c in registered):
        config.tls_mode = "external"
        config.http_port = next_port(8080 + len(registered) - 1, occupied)
        config.https_port = next_port(8443 + len(registered) - 1, occupied)
    else:
        occupied.update((config.http_port, config.https_port))
    config.ssh_nextcloud_port = next_port(2201, occupied)
    if config.native_office:
        config.ssh_onlyoffice_port = next_port(2202, occupied)
    return config


def configure(facts, existing=None, registered=(), *, ui=None):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError("The installer requires an interactive terminal for configuration and approval")
    ui = ui or TerminalUI()
    others = tuple(c for c in registered if existing is None or c.instance != existing.instance)
    if existing is None:
        ui.message("Choose once for this fresh installation. Nextcloud only is for no online office editing, "
                   "or for an external server you will configure manually later; no connector or server is installed. "
                   "VM choices use a dedicated Alpine/bhyve/Docker guest; native end-to-end acceptance is pending. "
                   "These fresh choices cannot later be switched by this installer.")
        backend = ui.menu("Office backend (fresh installation)", [
            ("onlyoffice", "ONLYOFFICE — native FreeBSD (default)"),
            ("eurooffice", "Euro-Office — dedicated Alpine/bhyve/Docker VM"),
            ("collabora", "Collabora CODE — dedicated Alpine/bhyve/Docker VM"),
            ("none", "Nextcloud only (no integrated office)"),
        ], "onlyoffice")
        c = initial_config(facts, others, office_backend=backend)
    else:
        c = replace(existing)
    apps_selected_early = False
    if existing is None:
        # Establish baseline capacity first, then let the operator resolve app headroom
        # before sizing. Keep the normal chooser later unless it was needed here.
        c.nextcloud_apps = DEFAULT_NEXTCLOUD_APPS
        remaining = remaining_memory(facts, others, c.host_reserved_mb)
        minimum = 4544 if c.has_office else 1984
        if c.backend in ('eurooffice','collabora'):
            from .versions import vm_resource_policy
            minimum = vm_resource_policy(c)['defaults']['memory_mb'] + 3*c.php_memory_mb + 256 + 64 + 640
        while remaining < minimum + c.antivirus_memory_mb:
            ui.message(f"Only {remaining} MiB remains after host/registered budgets. "
                        f"Selected apps need at least {minimum + c.antivirus_memory_mb} MiB including core services. "
                       "Adjust the Nextcloud apps before RAM sizing; antivirus adds 3072 MiB. "
                       "No apps will be deselected automatically.")
            c.nextcloud_apps = select_nextcloud_apps(c.nextcloud_apps, ui=ui)
            apps_selected_early = True
        c = initial_config(facts, others, nextcloud_apps=c.nextcloud_apps, office_backend=c.office_backend)
    first = others[0] if others else None
    shared_keys = ("pool", "external_interface", "management_network", "management_port", "host_reserved_mb")
    shared = {key: getattr(first, key) for key in shared_keys} if first else (facts.get("managed_host") or {})
    if shared:
        for field in shared_keys:
            setattr(c, field, shared[field])
    automatic_external = existing is None and first is not None and c.tls_mode == "external"

    def field(name, label, convert=str):
        setattr(c, name, ask(label, getattr(c, name), convert, ui=ui))

    def optional_field(name, label):
        value = ui.input(label + " ('-' clears)", getattr(c, name))
        setattr(c, name, "" if value == "-" else value)

    ui.message(f"\nNextcloud + ONLYOFFICE | FreeBSD {c.release} {c.arch} | two Bastille VNET jails per instance"
               if c.native_office else
               f"\nNextcloud + {OFFICE_LABELS[c.backend]} | FreeBSD {c.release} {c.arch} | one jail + one dedicated VM"
               if c.has_office else
               f"\nNextcloud only | FreeBSD {c.release} {c.arch} | one Bastille VNET jail per instance")
    ui.message(f"Detected {facts['memory_mb']} MiB RAM; ZFS pools: {', '.join(facts['pools'])}")
    ui.message("Use Cancel / ESC / Ctrl-C to stop. Review the complete plan before applying.")
    if shared:
        ui.message(f"Shared host settings: pool {c.pool}, uplink {c.external_interface}, "
                   f"management {c.management_network}:{c.management_port}.")
    while True:
        ui.message("\n1/7  Identity")
        field("instance", "Instance name (1–8 lowercase letters/digits, starting with a letter)")
        field("public_hostname", "Public Nextcloud DNS hostname", lambda value: value.lower())
        for name, suffix, label in (("nextcloud_hostname", "nc", "Nextcloud jail hostname"),
                                    ("onlyoffice_hostname", "oo", "ONLYOFFICE jail hostname")):
            if name == "onlyoffice_hostname" and not c.native_office:
                continue
            automatic = c.instance + suffix
            value = ui.input(label + " (short name or FQDN)", getattr(c, name) or automatic).lower()
            setattr(c, name, "" if value == automatic else value)
        field("admin_username", "Nextcloud administrator username")
        field("admin_email", "Administrator email")
        field("timezone", "IANA timezone")
        c.repository = choose("FreeBSD-ports branch", ("latest", "quarterly"), c.repository, ui=ui)
        from .versions import constraints, load_policy
        effective = constraints(c, load_policy())
        select_version_families(c, ui=ui)
        for name, label in (("nextcloud_min", "Minimum Nextcloud stable version"),
                            ("onlyoffice_min", "Minimum ONLYOFFICE stable version")):
            if name == "onlyoffice_min" and not c.native_office:
                continue
            setattr(c, name, ui.input(label, effective[name]))
        optional_field("nextcloud_exact", "Optional exact Nextcloud release (blank selects newest compatible)")
        if c.native_office:
            optional_field("onlyoffice_exact", "Optional exact ONLYOFFICE release/package version")
        c.freebsd_release, c.architecture = c.release, c.arch
        ui.message("Minimums/pins do not establish support. Discovery and compatibility must both pass before installation.")

        ui.message("\n2/7  Storage | optional GiB limits")
        if not shared:
            c.pool = choose("Existing ZFS pool", facts["pools"], c.pool, ui=ui)
        ui.message(storage_inspection(facts, c.pool))
        ui.message("Capacity figures describe the actual destination storage, not a quota recommendation or a fit guarantee. "
                   "Leave room for the selected jail bases, packages, fonts, database, uploads, updates and snapshots.")
        limits = ui.menu("Storage limits", [("none", "No installer quotas (default)"),
                                            ("caps", "Optional operator-entered caps")],
                         "caps" if any(getattr(c, name) for name in QUOTA_FIELDS) else "none")
        if limits == "none":
            # Explicit selection, never a reinterpretation of saved legacy limits.
            c.storage_policy = "optional"
            for name in QUOTA_FIELDS:
                setattr(c, name, 0)
        elif limits == "caps":
            optional = c.storage_policy == "optional"
            if not optional:
                ui.message("Saved legacy storage policy retained, including its parent/application limits.")
            for name, label in (("data_quota_gib", "Nextcloud user data"),
                                ("database_quota_gib", "MariaDB data"),
                                ("temporary_quota_gib", "Upload/temporary data"),
                                ("office_quota_gib", "Each ONLYOFFICE working-data dataset" if c.native_office else "Office VM dataset cap (must accommodate the guest disk)"),
                                 ("logs_quota_gib", "Each service/database log dataset"),
                                 ("system_quota_gib", "Combined jail-root cap")):
                if name == "office_quota_gib" and not c.has_office:
                    continue
                field(name, label + (" (GiB; 0 = no quota)" if optional else " (legacy GiB quota)"), int)
        else:
            raise ValueError("Unknown storage limits selection")
        ui.message(storage_summary(c))

        ui.message("\n3/7  Network | two private /30 networks per /29 allocation" if c.has_office else
                   "\n3/7  Network | one private /30 network")
        if not shared:
            field("external_interface", "Host uplink interface")
        field("ingress_address", "IPv4 on the host uplink (another assigned address can use separate HTTPS ports)")
        field("private_network", "Unused private IPv4 /29 block" if c.has_office else "Unused private IPv4 /30 block")
        field("nextcloud_bridge", "Unused Nextcloud bridge name")
        if c.has_office:
            field("onlyoffice_bridge", "Unused ONLYOFFICE bridge name" if c.native_office else "Unused office VM bridge name")
        field("dns_server", "DNS resolver IPv4 reachable from both jails" if c.native_office else
              "DNS resolver IPv4 reachable from the jail and office VM" if c.has_office else
              "DNS resolver IPv4 reachable from the Nextcloud jail")
        if not shared:
            field("management_network", "IPv4 CIDR allowed to SSH to the host")
            field("management_port", "Host SSH port", int)
        ui.message("Managed PF permits the selected ingress and management traffic; host inbound IPv6 is blocked.")

        ui.message("\n4/7  HTTPS and ingress")
        if automatic_external:
            if not any(item.ingress_address == c.ingress_address for item in others):
                c.tls_mode, c.http_port, c.https_port = "acme", 80, 443
            automatic_external = False
        c.tls_mode = ui.menu("HTTPS termination", [
            ("acme", "In the jail: Let's Encrypt / ACME"),
            ("provided", "In the jail: supplied certificate and private key"),
            ("external", "At an external HTTPS reverse proxy; restricted HTTP backend"),
        ], c.tls_mode)
        if c.tls_mode == "external":
            optional_field("dns_address", "Optional expected proxy IPv4 A address (blank for an IPv6-only frontend)")
        else:
            c.dns_address = ui.input("Expected public DNS A address (router WAN address when applicable)",
                                     c.dns_address or c.ingress_address)
        field("public_https_port", "Public HTTPS port used by browsers", int)
        field("http_port", "Host HTTP backend/listener port", int)
        if c.tls_mode != "external":
            field("https_port", "Host HTTPS listener port", int)
            c.proxy_networks = ""
        if c.tls_mode == "acme":
            c.acme_email = ui.input("Let's Encrypt account email", c.acme_email or c.admin_email)
            c.certificate_file = c.private_key_file = c.ca_file = ""
            ui.message("ACME requires public TCP 80 to reach this instance. Forward HTTPS to its selected listener.")
            ui.message("Let's Encrypt subscriber agreement: https://letsencrypt.org/repository/")
            if not ui.confirm("Accept that agreement for this ACME account?"):
                continue
        elif c.tls_mode == "provided":
            field("certificate_file", "Absolute path to full PEM certificate chain")
            field("private_key_file", "Absolute path to matching unencrypted PEM private key")
            optional_field("ca_file", "Optional private-CA PEM bundle (blank for normal trust)")
            c.acme_email = ""
        else:
            ui.message("The external proxy must serve HTTPS, forward this hostname to the HTTP backend, and set forwarded headers.")
            field("proxy_networks", "Trusted reverse-proxy IPv4 CIDRs, comma-separated (only these may reach HTTP)")
            c.acme_email = c.certificate_file = c.private_key_file = c.ca_file = ""

        ui.message("\n5/7  Optional jail administration")
        c.jail_ssh = ui.menu("SSH into both jails" if c.native_office else "SSH into the Nextcloud jail",
                            [("off", "Disabled"), ("on", "Enable key-only login")],
                            "on" if c.jail_ssh else "off") == "on"
        if c.jail_ssh:
            ui.message("Jail SSH ingress is limited to the host's management CIDR.")
            field("ssh_username", "Jail SSH username")
            field("ssh_key_file", "Absolute path to PUBLIC SSH key file")
            c.ssh_shell = ui.menu("Jail login shell", [("sh", "FreeBSD base sh"),
                                                      ("zsh", "zsh with local defaults")], c.ssh_shell)
            admin = ui.menu("Jail SSH privileges", [("user", "Unprivileged user"),
                                                    ("admin", "Administrator: root access through doas")],
                            "admin" if c.ssh_admin else "user")
            c.ssh_admin = False
            if admin == "admin":
                c.ssh_admin = ui.confirm("Grant the selected SSH key root administration in both jails through doas?"
                                         if c.native_office else
                                         "Grant the selected SSH key root administration in the Nextcloud jail through doas?")
            field("ssh_nextcloud_port", "Host TCP port for Nextcloud jail SSH", int)
            if c.native_office:
                field("ssh_onlyoffice_port", "Host TCP port for ONLYOFFICE jail SSH", int)
        else:
            c.ssh_key_file = ""
            c.ssh_admin = False

        ui.message("\n6/7  Document fonts and plugins" if c.native_office else "\n6/7  Nextcloud apps")
        if c.native_office:
            if not c.accept_microsoft_fonts:
                ui.message("The reviewed native ONLYOFFICE package requires Microsoft core webfonts, independently of the open-font profile.\n"
                           "Review the applicable EULA: https://corefonts.sourceforge.net/eula.htm\n"
                           "Port license information: https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/webfonts/Makefile")
                consent = ui.menu("Required Microsoft webfonts license", [
                    ("decline", "Decline; cancel this installation"),
                    ("accept", "I reviewed and accept the applicable EULA")], "decline")
                if consent != "accept":
                    raise KeyboardInterrupt
                c.accept_microsoft_fonts = True
            ui.message(COMPREHENSIVE_FONT_ESTIMATE)
            c.font_profile = ui.menu("Font packages", [("comprehensive", "Comprehensive: wider script and document coverage (~+4 GiB installed vs standard)"),
                                                       ("standard", "Standard: smaller font set (baseline)")], c.font_profile)
            optional_field("additional_fonts_dir", "Optional absolute directory of additional fonts (blank to skip)")
            c.onlyoffice_plugins = select_onlyoffice_plugins(c.onlyoffice_plugins, ui=ui)
        if not apps_selected_early:
            c.nextcloud_apps = select_nextcloud_apps(c.nextcloud_apps, ui=ui)
        apps_selected_early = False

        ui.message("\n7/7  Resource budgets | MiB")
        ui.message(resource_review(facts, c, others))
        if ui.menu("Resource budgets", [("keep", "Use these initial budgets"),
                                         ("edit", "Adjust budgets (advanced)")], "keep") == "edit":
            if not shared:
                field("host_reserved_mb", "Host and ZFS ARC reserve", int)
            for name, label in (("office_memory_mb", "ONLYOFFICE budget" if c.native_office else "Total office guest RAM"),
                                ("db_buffer_mb", "MariaDB buffer pool"), ("redis_memory_mb", "Redis limit"),
                                 ("php_memory_mb", "PHP per-request memory limit"),
                                 ("php_budget_mb", "PHP worker pool budget"), ("upload_max_mb", "PHP upload chunk limit")):
                if name == "office_memory_mb" and not c.has_office:
                    continue
                field(name, label, int)
            if c.backend in ('eurooffice','collabora'):
                field('office_vm_cpus', 'Dedicated office VM vCPU count', int)
                field('office_vm_disk_gib', 'Office guest disk capacity (GiB; distinct from dataset cap)', int)
        remaining = remaining_memory(facts, others, c.host_reserved_mb)
        try:
            c.validate_provisioning()
            if c.backend in ('eurooffice','collabora'):
                from .versions import vm_resource_policy
                floor=vm_resource_policy(c)['minimum']
                if (c.office_vm_cpus<floor['cpus'] or c.office_memory_mb<floor['memory_mb']
                        or c.office_vm_disk_gib<floor['disk_gib']):
                    raise ValueError('Selected VM allocation is below reviewed guest/container resource policy')
                if c.office_quota_gib and c.office_quota_gib<c.office_vm_disk_gib:
                    raise ValueError('Office VM dataset cap cannot accommodate the guest disk capacity')
            if c.instance in facts.get("reserved_instances", ()):
                raise ValueError("This instance name remains reserved in the host audit registry; select a new name")
            if service_memory(c) > remaining:
                raise ValueError("Combined instance budgets and the host reserve exceed installed RAM")
            occupied = used_ports(others, c.ingress_address, c.management_port)
            selected = set(c.ingress_ports)
            if selected & occupied:
                raise ValueError("An ingress port is already reserved on this host address")
            for other in others:
                if c.instance == other.instance:
                    raise ValueError("This instance name is already registered")
                if c.network.overlaps(other.network):
                    raise ValueError("Private network overlaps a registered instance")
                if set(c.bridges) & set(other.bridges):
                    raise ValueError("A bridge name is already registered")
            if facts.get("ssh_peer"):
                peer = ipaddress.IPv4Address(facts["ssh_peer"])
                if peer not in ipaddress.IPv4Network(c.management_network, strict=False) or c.management_port != facts["ssh_port"]:
                    raise ValueError("The managed SSH rule must preserve the current SSH client and port")
        except ValueError as error:
            ui.message(f"\nConfiguration needs correction: {error}\nReview the form again; current entries are retained.")
            continue
        ui.message("\n" + resource_review(facts, c, others))
        ui.message("\n" + deployment_plan(c))
        action = ui.menu("Review configuration", [("accept", "Accept this plan"), ("edit", "Edit these settings"),
                                                 ("quit", "Cancel")], "edit")
        if action == "accept":
            return c
        if action == "quit":
            raise KeyboardInterrupt


def create_secrets(*, ui=None, generate=False, backend="onlyoffice"):
    if (backend or "onlyoffice") not in OFFICE_BACKENDS:
        raise ValueError("Unknown office backend")
    ui = ui or TerminalUI()
    ui.message("\nFresh credentials will be generated in the private credentials file." if generate else
               "\nAdministrator password: leave blank to generate one in the private credentials file.")
    while True:
        password = "" if generate else ui.secret("Password (not displayed)")
        if not password:
            password = secrets.token_urlsafe(24)
            break
        if len(password) < 14 or len(password.encode("utf-8")) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in password):
            ui.message("Use at least 14 characters, at most 1024 UTF-8 bytes, without control characters.")
            continue
        if password == ui.secret("Confirm password"):
            break
        ui.message("Passwords differ; please retry.")
    credentials = {"admin_password": password, "db_password": secrets.token_hex(32)}
    if (backend or 'onlyoffice') in ('onlyoffice','eurooffice'):
        credentials["jwt_secret"] = secrets.token_hex(32)
    return credentials
