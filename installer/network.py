"""Render selected isolated jail topologies; never configure the host here."""

import ipaddress


def pf_rules(config, ssh_connection=None, *, host_config=None):
    """Render one coherent host policy for all managed instances, never a merge
    with foreign PF rules. Integrated instances have two routed /30 segments;
    Nextcloud-only instances have one, with no office allowances.
    """
    configs = list(config) if isinstance(config, (list, tuple)) else [config]
    configs = sorted((item.validate() for item in configs), key=lambda item: item.instance)
    c = (host_config or (configs[0] if configs else None))
    if c is None:
        raise ValueError("A host configuration is required even when removing the last instance")
    c.validate()
    if ssh_connection:
        if len(ssh_connection) != 4:
            raise ValueError("Invalid current SSH connection tuple")
        peer, client_port, server, server_port = ssh_connection
        peer, server = str(ipaddress.IPv4Address(peer)), str(ipaddress.IPv4Address(server))
        client_port, server_port = int(client_port), int(server_port)
        if (not 1 <= client_port <= 65535 or server_port != c.management_port
                or ipaddress.IPv4Address(peer) not in ipaddress.IPv4Network(c.management_network, strict=False)):
            raise ValueError("The active SSH tuple is outside the approved management policy")
        # PF did not observe this connection's SYN/window-scale negotiation on
        # first activation. Midstream pickup needs sloppy state, restricted to
        # this exact approved tuple in both directions and before generic SSH.
        preserve_ssh = [f"pass in quick on $ext_if inet proto tcp from {peer} port {client_port} "
                        f"to {server} port {server_port} flags any keep state (sloppy)",
                        f"pass out quick on $ext_if inet proto tcp from {server} port {server_port} "
                        f"to {peer} port {client_port} flags any keep state (sloppy)"]
    else:
        # Console/su environments may have no SSH_CONNECTION tuple. This stays
        # restricted to the selected host SSH port and approved management CIDR.
        preserve_ssh = [f"pass out quick on $ext_if inet proto tcp from ($ext_if) port {c.management_port} "
                        f"to {c.management_network} flags any keep state"]
    addresses = ", ".join(address for item in configs for address in
                          ((item.nextcloud_ip, item.onlyoffice_ip) if item.has_office else (item.nextcloud_ip,)))
    # Snapshots/boot guards query both tables even after the last instance is
    # removed. PF may discard an unreferenced table unless it is persistent.
    lines = ["# cloud-installer managed host policy; no physical uplink is bridged.",
             f'ext_if = "{c.external_interface}"', f"table <cloud_jails> const persist {{ {addresses} }}",
             "table <cloud_noninternet> const persist { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }",
             "set block-policy drop", "set skip on lo0", "set state-policy if-bound",
             "set ruleset-optimization none", "scrub in all",
             "nat on $ext_if inet from <cloud_jails> to any -> ($ext_if:0)"]
    # PF translation rules precede every filter rule.
    for item in configs:
        source = "{ " + ", ".join(item.trusted_proxy_networks) + " }" if item.tls_mode == "external" else "any"
        lines.append(f"rdr on $ext_if inet proto tcp from {source} to {item.ingress_address} port {item.http_port} -> {item.nextcloud_ip} port 80")
        if item.tls_mode != "external":
            lines.append(f"rdr on $ext_if inet proto tcp from any to {item.ingress_address} port {item.https_port} -> {item.nextcloud_ip} port 443")
        if item.jail_ssh:
            endpoints = [(item.nextcloud_ip, item.ssh_nextcloud_port)]
            if item.native_office:
                endpoints.append((item.onlyoffice_ip, item.ssh_onlyoffice_port))
            for address, port in endpoints:
                lines.append(f"rdr on $ext_if inet proto tcp from {item.management_network} to {item.ingress_address} port {port} -> {address} port 22")
    lines.append("block log all")
    # Anti-spoofing precedes every quick pass, including management SSH.
    for item in configs:
        lines.extend([f"block in quick on $ext_if inet from {item.private_network} to any",
                      f"block in quick on {item.nextcloud_bridge} inet from ! {item.nextcloud_ip} to any"])
        if item.has_office:
            lines.extend([
                      f"block in quick on {item.onlyoffice_bridge} inet from ! {item.onlyoffice_ip} to any",
                      f"block quick on {{ {item.nextcloud_bridge}, {item.onlyoffice_bridge} }} inet6 all"])
        else:
            lines.append(f"block quick on {item.nextcloud_bridge} inet6 all")
    lines.extend(preserve_ssh)
    lines.append(f"pass in quick on $ext_if inet proto tcp from {c.management_network} to ($ext_if) port {c.management_port} flags any keep state")
    for item in configs:
        nc, nb = item.nextcloud_ip, item.nextcloud_bridge
        source = "{ " + ", ".join(item.trusted_proxy_networks) + " }" if item.tls_mode == "external" else "any"
        public_ports = "80" if item.tls_mode == "external" else "{ 80, 443 }"
        if item.has_office:
            oo, ob = item.onlyoffice_ip, item.onlyoffice_bridge
            lines.append(f"# Instance {item.instance}")
            if item.native_office:
                lines.extend([f"block quick inet proto tcp from any to {oo} port {{ 8000, 8126 }}",
                              f"block quick inet proto udp from any to {oo} port 8125"])
            lines.extend([
                      f"pass in quick on $ext_if inet proto tcp from {source} to {nc} port {public_ports} flags S/SA keep state",
                      f"pass out quick on {nb} inet proto tcp from {source} to {nc} port {public_ports} flags S/SA keep state received-on $ext_if",
                      f"pass quick on {{ {nb}, {ob} }} inet proto tcp from {nc} to {oo} port 8081 flags S/SA keep state",
                      f"pass quick on {{ {nb}, {ob} }} inet proto tcp from {oo} to {nc} port {item.callback_port} flags S/SA keep state",
                      f"pass in quick on {{ {nb}, {ob} }} inet proto {{ udp, tcp }} from {{ {nc}, {oo} }} to {item.dns_server} port 53 keep state",
                      f"block in quick on {{ {nb}, {ob} }} inet from any to self",
                      f"pass in quick on {{ {nb}, {ob} }} inet proto tcp from {{ {nc}, {oo} }} to ! <cloud_noninternet> port {{ 80, 443 }} flags S/SA keep state"])
        else:
            lines.extend([f"# Instance {item.instance} (Nextcloud only)",
                          f"pass in quick on $ext_if inet proto tcp from {source} to {nc} port {public_ports} flags S/SA keep state",
                          f"pass out quick on {nb} inet proto tcp from {source} to {nc} port {public_ports} flags S/SA keep state received-on $ext_if",
                          f"pass in quick on {nb} inet proto {{ udp, tcp }} from {nc} to {item.dns_server} port 53 keep state",
                          f"block in quick on {nb} inet from any to self",
                          f"pass in quick on {nb} inet proto tcp from {nc} to ! <cloud_noninternet> port {{ 80, 443 }} flags S/SA keep state"])
        if "mail" in item.selected_nextcloud_apps:
            lines.append("# Explicit Mail selection: outbound secure mailbox ports, Nextcloud only")
            lines.append(f"pass in quick on {nb} inet proto tcp from {nc} to ! <cloud_noninternet> port {{ 465, 587, 993 }} flags S/SA keep state")
        endpoints = [(nb, nc, item.nextcloud_gateway, public_ports)]
        if item.has_office:
            endpoints.append((ob, oo, item.onlyoffice_gateway, "8081"))
        for bridge, address, gateway, ports in endpoints:
            lines.extend([f"pass out quick on {bridge} inet proto icmp from ({bridge}) to {address} icmp-type unreach code needfrag no state",
                          f"pass out quick on {bridge} inet proto tcp from {gateway} to {address} port {ports} flags S/SA keep state"])
            if item.jail_ssh and (address == nc or item.native_office):
                lines.extend([f"pass in quick on $ext_if inet proto tcp from {item.management_network} to {address} port 22 flags S/SA keep state",
                              f"pass out quick on {bridge} inet proto tcp from {item.management_network} to {address} port 22 flags S/SA keep state received-on $ext_if",
                               f"pass out quick on {bridge} inet proto tcp from {gateway} to {address} port 22 flags S/SA keep state"])
            if item.has_office and not item.native_office and address == oo:
                lines.append(f"pass out quick on {bridge} inet proto tcp from {gateway} to {address} port 22 flags S/SA keep state")
    lines.extend(["pass out quick on $ext_if inet proto icmp from self to any icmp-type unreach code needfrag no state",
                  "pass out quick on $ext_if inet from ($ext_if) to any keep state", ""])
    return "\n".join(lines)


def storage_guard(config, storage, state_root=None, *, lifecycle=True):
    """Jail exec.prepare guard: validate policy and storage BEFORE nullfs mounts."""
    from .config import STATE_DIR
    root = state_root or STATE_DIR
    active = root / "network/active"
    c = config
    lines = ["#!/bin/sh", "set -eu", f'[ -f "{root}/instances/{c.instance}/allow-start" ] || exit 1',
             f'[ -f "{active}/firewall-confirmed" ] || exit 1',
             "/sbin/pfctl -s Running >/dev/null 2>&1 || exit 1"]
    # Optional for unenrolled hosts; fail closed once lifecycle state exists.
    # Enrollment also installs a separate wrapper around historical guards.
    from .paths import PROJECT_ROOT
    from .maintenance import executor_identity
    import shlex
    program = ("import sys; sys.path.insert(0, sys.argv[1]); "
               "from installer.maintenance import boot_check; "
               "boot_check(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])")
    lifecycle_lines = [f'if [ -e "{root}/lifecycle" ] || [ -L "{root}/lifecycle" ] || '
                  f'[ -e "{root}/maintenance/pending.json" ] || [ -L "{root}/maintenance/pending.json" ]; then',
                  "    /usr/local/bin/python3 -I -B -c " + shlex.quote(program) + " "
                  + " ".join(shlex.quote(str(value)) for value in (PROJECT_ROOT, root, c.instance))
                  + ' "${1:-}" ' + shlex.quote(executor_identity()) + " || exit 1", "fi"]
    if lifecycle:
        lines[2:2] = lifecycle_lines
    for name, args in (("filter", "-sr"), ("nat", "-sn"),
                       ("jails", "-t cloud_jails -T show"), ("noninternet", "-t cloud_noninternet -T show")):
        lines.extend([f'active=$(/sbin/pfctl {args}) || exit 1',
                      f'[ "$active" = "$(/bin/cat {active}/pf-{name}.expected)" ] || exit 1'])
    for name, value in (("net.inet.ip.forwarding", "1"), ("net.link.bridge.pfil_bridge", "1"),
                        ("net.link.bridge.pfil_member", "0"), ("net.link.bridge.pfil_local_phys", "0"),
                        ("net.link.bridge.pfil_onlyip", "1")):
        lines.append(f'[ "$(/sbin/sysctl -n {name})" = {value} ] || exit 1')
    endpoints = [(c.nextcloud_bridge, c.nextcloud_gateway, c.nextcloud_jail)]
    if c.native_office:
        endpoints.append((c.onlyoffice_bridge, c.onlyoffice_gateway, c.onlyoffice_jail))
    for bridge, gateway, jail in endpoints:
        lines.append(f"/sbin/ifconfig {bridge} | /usr/bin/awk '$1 == \"inet\" && $2 == \"{gateway}\" {{ found=1 }} $1 == \"member:\" && $2 != \"e0a_{jail}\" {{ foreign=1 }} END {{ exit !found || foreign }}' || exit 1")
    if c.has_office and not c.native_office:
        name=c.instance+'office'
        lines.extend([
            f"members=$(/sbin/ifconfig {c.onlyoffice_bridge} | /usr/bin/awk '$1 == \"inet\" && $2 == \"{c.onlyoffice_gateway}\" {{ found=1 }} $1 == \"member:\" {{ count++; print $2 }} END {{ exit !found || count > 1 }}') || exit 1",
            'if [ -n "$members" ]; then',
            '    case "$members" in tap*) number=${members#tap} ;; *) exit 1 ;; esac',
            '    case "$number" in ""|*[!0-9]*) exit 1 ;; esac',
            f"    /sbin/ifconfig \"$members\" | /usr/bin/awk '$1 == \"description:\" && $2 == \"vmnet/{name}/0/{name}\" {{ found=1 }} END {{ exit !found }}' || exit 1",
            'fi'])
    lines.append('case "${1:-}" in')
    for jail in config.jails:
        lines.append(f"{jail})")
        targets = [(item.name, item.mountpoint) for item in storage if item.jail == jail]
        targets.append((f"{c.bastille_dataset}/jails/{jail}/root", f"{c.bastille_root}/jails/{jail}/root"))
        for name, mountpoint in targets:
            lines.extend([
                f'    [ "$(/sbin/zfs get -H -o value mounted {name})" = yes ] || exit 1',
                f'    [ "$(/sbin/zfs get -H -o value org.cloud-installer:instance {name})" = "{c.instance}" ] || exit 1',
                f'    [ "$(/sbin/zfs get -H -o value mountpoint {name})" = "{mountpoint}" ] || exit 1',
                f'    [ "$(/bin/realpath {mountpoint})" = "{mountpoint}" ] || exit 1',
                f"    /sbin/mount -p | /usr/bin/awk '$1 == \"{name}\" && $2 == \"{mountpoint}\" && $3 == \"zfs\" {{ found=1 }} END {{ exit !found }}' || exit 1",
                f"    /bin/df -P {mountpoint} | /usr/bin/awk 'NR == 2 && $1 == \"{name}\" {{ found=1 }} END {{ exit !found }}' || exit 1",
            ])
        lines.append("    ;;")
    lines.extend(["*) exit 1 ;;", "esac", ""])
    return "\n".join(lines)
