# External HTTPS reverse proxy

Select **external** TLS in `sh install.sh` when an existing proxy will terminate public HTTPS. The installer configures a restricted **HTTP** backend in the Nextcloud jail; it does not install or manage the external proxy or its certificates. Complete external-proxy acceptance is not established by the bounded direct-TLS/profile checks; see the [validation matrix](verification.md).

```text
Browser -- HTTPS --> external proxy -- trusted IPv4 HTTP --> host:8080
                                                            | PF
                                                            v
                                                     Nextcloud jail:80
                                                       /onlyoffice/
                                                            |
                                                     ONLYOFFICE:8081
                                               callbacks --> Nextcloud:80
```

The HTTP leg must stay on a **private/trusted LAN or VPN**. An IPv4 allowlist does not encrypt traffic: do not send authenticated HTTP across the public Internet. The proxy must be a separately reachable frontend on the host's selected uplink, not an extra unregistered jail or a loopback proxy on this managed host.

## Wizard and schema-2 settings

The following is a documentation-only example, also suitable for offline `plan`. Replace the reserved addresses, domains and interface with your environment. Here the public URL deliberately uses port **8443**, independently of backend port **8080**:

```json
{
  "schema_version": 2,
  "instance": "team2",
  "pool": "zroot",
  "public_hostname": "team2.example.test",
  "nextcloud_hostname": "team2-files.internal.example.test",
  "onlyoffice_hostname": "team2-docs.internal.example.test",
  "admin_email": "admin@example.test",
  "external_interface": "igb0",
  "ingress_address": "192.0.2.10",
  "dns_server": "192.0.2.53",
  "management_network": "198.51.100.0/24",
  "private_network": "10.77.0.8/29",
  "nextcloud_bridge": "bridge242",
  "onlyoffice_bridge": "bridge243",
  "tls_mode": "external",
  "http_port": 8080,
  "public_https_port": 8443,
  "proxy_networks": "192.0.2.20/32"
}
```

- `ingress_address` is assigned to the **FreeBSD host**, not the proxy or jail. PF redirects `192.0.2.10:8080` to this instance's Nextcloud `10.77.0.10:80`.
- `proxy_networks` is the comma-separated IPv4 source allowlist **as observed by the backend**. Prefer each proxy's `/32`; validation accepts narrow `/24`–`/32` networks, never `0.0.0.0/0`. Include any intentional source NAT address only after reviewing which clients it represents. The same list supplies PF ingress and Nextcloud proxy trust.
- Public A/AAAA records point to the **proxy frontend**. External mode can serve IPv4, IPv6 or both there, including an IPv6-only public frontend; the proxy still needs an IPv4 route to the backend. An optional `dns_address` checks the expected proxy A address. The host/jails do not acquire public IPv6 ingress.
- `public_https_port` defines browser/share/CLI/document URLs. For standard HTTPS use `443` and omit `:8443` from the proxy example below. `https_port` is not a backend listener in external mode.
- Each additional instance needs a distinct host-address/backend-port pair, network and bridges. Multiple public names can share the external proxy's HTTPS listener, with separate virtual hosts/upstreams. The static plan does not replace host collision checks.

For direct `acme` or `provided` TLS, use the corresponding wizard mode instead: PF maps the selected host ports to jail 80/443 and callbacks use internal HTTPS 443. ACME requires public TCP 80; direct DNS must match the host/router ingress and have no AAAA record. See [TLS defaults](jails.md#service-defaults-and-https).

## Concrete Nginx frontend

Place this in the external proxy's `http {}` context. The certificate paths are **operator-provided placeholders** for an already issued, trusted chain and matching private key. Configure certificate renewal on that proxy and validate it with `nginx -t` before reloading.

```nginx
map $http_upgrade $cloud_connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name team2.example.test;
    if ($host != team2.example.test) { return 444; }
    return 308 https://team2.example.test:8443$request_uri;
}

server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    server_name team2.example.test;
    if ($host != team2.example.test) { return 444; }

    ssl_certificate     /usr/local/etc/nginx/tls/team2-fullchain.pem;
    ssl_certificate_key /usr/local/etc/nginx/tls/team2-privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Fits the default 1024 MiB upload chunk plus request overhead.
    # Review together with the instance's upload/temp/storage budgets.
    client_max_body_size 1100m;
    client_body_timeout 3600s;
    send_timeout 3600s;

    location = /.well-known/carddav {
        return 301 https://team2.example.test:8443/remote.php/dav/;
    }
    location = /.well-known/caldav {
        return 301 https://team2.example.test:8443/remote.php/dav/;
    }

    location / {
        # No URI suffix: preserve /onlyoffice/ for the jail's Apache proxy.
        proxy_pass http://192.0.2.10:8080;
        proxy_http_version 1.1;

        # Canonical authority is configuration, not an incoming client header.
        proxy_set_header Host team2.example.test:8443;
        proxy_set_header X-Forwarded-Host team2.example.test:8443;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 8443;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Forwarded "";
        proxy_set_header X-Forwarded-Prefix "";
        proxy_set_header CloudFront-Forwarded-Proto "";

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $cloud_connection_upgrade;
        proxy_connect_timeout 10s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_cache off;
        proxy_redirect off;
    }
}
```

This example assumes the proxy directly receives client connections. It **replaces** incoming forwarded headers; do not change `X-Forwarded-For` to `$proxy_add_x_forwarded_for` and inherit arbitrary client input. If another load balancer/CDN precedes Nginx, separately restrict and validate that hop and its real-IP configuration before using its asserted client address. Preserve ordinary `Authorization` and the connector's `AuthorizationJWT` headers.

Nextcloud occupies `/`, and ONLYOFFICE occupies `/onlyoffice/` on the **same public origin**. Forward that path unchanged to Apache. Apache removes the prefix for the private office upstream and supplies the canonical `X-Forwarded-Host: team2.example.test:8443/onlyoffice` and `X-Forwarded-Proto: https` required by ONLYOFFICE. The outer proxy must not append another `/onlyoffice`, inject `X-Forwarded-Prefix`, or expose the office jail directly. Nextcloud under an additional subdirectory is not this installer's topology.

## Generated application settings

The Nextcloud worker derives settings from the saved configuration, not client-supplied headers:

- `trusted_proxies`: exactly the configured proxy IPv4 allowlist; `forwarded_for_headers`: `HTTP_X_FORWARDED_FOR`.
- `trusted_domains`: the canonical public authority/hostname plus the **private Nextcloud IP** needed for office HTTP callbacks.
- `overwritehost`: `team2.example.test:8443`; `overwriteprotocol`: `https`; `overwrite.cli.url`: `https://team2.example.test:8443/`. Public URL generation remains HTTPS even when the request arrived over the internal HTTP leg.
- Connector `DocumentServerUrl`: `https://team2.example.test:8443/onlyoffice/`; `DocumentServerInternalUrl`: `http://10.77.0.14:8081/`; `StorageUrl`: **`http://10.77.0.10/`**. The internal callback does not go through the external proxy or depend on its public DNS/port.

JWT authentication remains enabled. External mode has no jail TLS listener or certificate; it does not disable verification on an HTTPS connection. Direct-TLS modes continue to validate the callback certificate hostname/chain, including configured private-CA trust. Apache and the office nginx keep internal/info/admin/example endpoints denied, including version-prefixed paths.

## Acceptance

After `sh install.sh verify team2`, test from actual clients; local verification cannot prove the proxy/DNS path:

1. HTTPS certificate trust, public A and AAAA paths, redirects and generated share/CLI links must preserve the configured hostname and port, with no mixed content or HTTP redirect loops.
2. Confirm backend 8080 succeeds from the selected proxy source and is denied from an untrusted source. An allowed proxy must sanitize forged `Host`, `Forwarded`, `X-Forwarded-*` and real-IP headers; verify application client-IP attribution with a controlled request and logs.
3. Test login, large/chunked upload/download, WebDAV, and CardDAV/CalDAV discovery and synchronization for two ordinary users.
4. Open documents, observe successful WebSocket upgrades, co-edit, save, close and reopen. The healthcheck alone is insufficient. Confirm callbacks reach private NC port 80; office 8081 and backend/metrics ports remain inaccessible from outside.
5. Reboot the FreeBSD host and repeat these checks alongside another active direct-TLS instance. Exercise proxy certificate renewal separately.

## Sources reviewed on 2026-10-14

- [Nextcloud 35 reverse proxy configuration](https://docs.nextcloud.com/server/35/admin_manual/configuration_server/reverse_proxy_configuration.html): explicit proxy trust, spoofing implications, authority/port overrides and DAV redirects.
- [Nginx WebSocket proxying](https://nginx.org/en/docs/http/websocket.html): explicit Upgrade/Connection forwarding and read timeout.
- [ONLYOFFICE Apache virtual-path example](https://github.com/ONLYOFFICE/document-server-proxy/blob/master/apache/proxy-to-virtual-path.conf) and [connector URL/JWT settings](https://github.com/ONLYOFFICE/onlyoffice-nextcloud).
