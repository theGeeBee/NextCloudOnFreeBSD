"""Pure transformations of the reviewed native ONLYOFFICE package templates."""

import copy
import re
from urllib.parse import urlsplit


def public_base_url(value):
    if not isinstance(value, str) or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise ValueError("The public URL must be a root HTTPS URL")
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment
            or not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]+)?", url.netloc)):
        raise ValueError("The public URL must be a root HTTPS URL without credentials")
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError("Invalid HTTPS port")
    return f"https://{url.netloc}/"


def backend_port(value):
    if not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("ONLYOFFICE_NGINX_PORT must be numeric")
    port = int(value)
    if not 1024 <= port <= 65535 or port in (8000, 8125, 8126, 9000):
        raise ValueError("Choose an unprivileged nginx port distinct from DocService/metrics/PHP-FPM")
    return port


def local_config(original, jwt, allow_private):
    config = copy.deepcopy(original)
    coauthoring = config.setdefault("services", {}).setdefault("CoAuthoring", {})
    token = coauthoring.setdefault("token", {})
    token["enable"] = {"browser": True, "request": {"inbox": True, "outbox": True}}
    token.setdefault("browser", {})["secretFromInbox"] = True
    for direction in ("inbox", "outbox"):
        token.setdefault(direction, {}).update({"header": "AuthorizationJWT", "inBody": False})
    secret = coauthoring.setdefault("secret", {})
    for name in ("browser", "inbox", "outbox", "session"):
        secret[name] = {"string": jwt, "file": ""}
    coauthoring.setdefault("requestDefaults", {})["rejectUnauthorized"] = True
    coauthoring.setdefault("request-filtering-agent", {}).update({
        "allowPrivateIPAddress": allow_private, "allowMetaIPAddress": False,
    })
    return config


def nginx_frontend(original, port):
    # Retain the package's static files, secure-link secret and websocket config.
    # Refuse unknown layouts rather than leave an unintended public listener.
    pattern = r"(?m)^\s*listen\s+[^;]+;"
    listeners = re.findall(pattern, original)
    normalized = {" ".join(line.split()) for line in listeners}
    if normalized != {"listen 0.0.0.0:80;", "listen [::]:80 default_server;"} or len(listeners) != 2:
        raise ValueError("Unexpected packaged ds.conf listeners; review the port before proceeding")
    replacement = iter([f"\n  listen 127.0.0.1:{backend_port(port)};", ""])
    return re.sub(pattern, lambda _: next(replacement), original)


def restrict_nginx_internal(original):
    # Apache's loopback address must not grant public users access to /internal
    # or /info. Keep the packaged deny-all directives, including version routes.
    rendered, count = re.subn(r"(?m)^\s*allow\s+127\.0\.0\.1\s*;",
                             "\n  # No localhost exception behind the Apache proxy.", original)
    if count != 2 or len(re.findall(r"\bdeny\s+all\s*;", original)) < 2:
        raise ValueError("Unexpected nginx internal/info restrictions; review the port")
    return rendered


def proxy_config(template, base_url, port):
    authority = urlsplit(public_base_url(base_url)).netloc
    return template.replace("ONLYOFFICE_PUBLIC_AUTHORITY", authority).replace(
        "ONLYOFFICE_NGINX_PORT", str(backend_port(port)))
