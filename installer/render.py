#!/usr/bin/env python3
"""Offline core renderer, never an installer or service validator.

CLI: python3 -I -B installer/render.py --domain vpn.example.org --output-directory /tmp/NEW-dir
Only a NEW private staging directory is written, never runtime destinations or source.
Parent deployment must preserve existing configs, provision TLS/host keys/log ownership,
validate the locked binaries, and deploy units. /run/sshd is a parent prerequisite;
the additional sshd must be gated on effective loopback-only listeners (shared
sshd_config may contain additive ListenAddress directives). No admin files are changed.
No OpenVPN installation is implied.

Pure API: render_core(domain, ports, *, ss_server_key) -> {flat_filename: text}.
load_ports() is an explicit local read; new_server_key() is the explicit entropy step.
SS2022 requires a server key even with clients=[] (not an account/seed credential).
gRPC/WS are deprecated but supported at the pinned tag; real binary tests remain mandatory.
References:
https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.11.9
https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/infra/conf/shadowsocks.go
https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/infra/conf/transport_internet.go
https://www.haproxy.com/documentation/haproxy-configuration-manual/2-8r1/
https://nginx.org/en/docs/http/ngx_http_v2_module.html
"""
import argparse
import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets

SOURCE_ROOT = Path(__file__).resolve().parent.parent
PROTOCOLS = ("vmess", "vless", "trojan", "shadowsocks")
SERVICES = "/etc/nathaya-tunnel/services"
XRAY = "/etc/nathaya-tunnel/xray"
TLS = "/etc/nathaya-tunnel/tls"
LOGS = "/opt/nathaya/logs"
DOWNLOAD_ROOT = "/opt/nathaya/public/openvpn"
DOWNLOAD_FILES = ("client-tcp.ovpn", "client-udp.ovpn", "client-ssl.ovpn", "allovpn.zip")


def validate_domain(domain):
    """ASCII DNS name only; no IPs, ports, wildcard, trailing dot or interpolation."""
    if not isinstance(domain, str) or not 1 <= len(domain) <= 253:
        raise ValueError("Invalid DNS domain")
    label = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    if not re.fullmatch(label + r"(?:\." + label + r")+", domain, flags=re.ASCII):
        raise ValueError("Invalid DNS domain")
    if domain.rsplit(".", 1)[1].isdigit():
        raise ValueError("Invalid DNS domain")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain.lower()
    raise ValueError("IP addresses are not domains")


def validate_ports(p):
    """Local trusted schema, still reject templating injection and port collisions."""
    if not isinstance(p, dict) or p.get("schema") != 1 or p.get("profile") != "alrescha-core" or p.get("loopback") != "127.0.0.1":
        raise ValueError("Unsupported port profile")
    pub, inner = p["public"], p["internal"]
    if not all(isinstance(section, dict) for section in (pub, inner, p["routes"], p["xray"], p["openvpn"])):
        raise ValueError("Invalid port profile schema")
    if set(pub) != {"haproxy", "tls_download", "dropbear"} or set(inner) != {
            "nginx_ws", "nginx_grpc", "ssh_relay", "dropbear", "sshd_tls", "sshd_plain"}:
        raise ValueError("Invalid listener map")
    if not isinstance(pub["haproxy"], list) or len(pub["haproxy"]) != 3:
        raise ValueError("Invalid public mux ports")
    numbers = pub["haproxy"] + [pub["tls_download"], pub["dropbear"]] + list(inner.values())
    paths, services = [p["ssh_ws_path"]], []
    if set(p["routes"]) != set(PROTOCOLS):
        raise ValueError("Invalid protocol set")
    for proto in PROTOCOLS:
        route = p["routes"][proto]
        if not isinstance(route, dict) or set(route) != {"ws_path", "ws_port", "grpc_service", "grpc_port", "stats_port"}:
            raise ValueError("Invalid route schema")
        numbers.extend(route[k] for k in ("ws_port", "grpc_port", "stats_port"))
        paths.append(route["ws_path"])
        services.append(route["grpc_service"])
    if any(type(n) is not int or not 1 <= n <= 65535 for n in numbers) or len(set(numbers)) != len(numbers):
        raise ValueError("Invalid or colliding ports")
    if any(not isinstance(s, str) or not re.fullmatch(r"/[a-z0-9-]+", s) for s in paths):
        raise ValueError("Invalid WS path")
    if any(not isinstance(s, str) or not re.fullmatch(r"[a-z0-9-]+", s) for s in services):
        raise ValueError("Invalid gRPC service")
    if len(set(paths)) != len(paths) or len(set(services)) != len(services):
        raise ValueError("Duplicate routes")
    if tuple(p["download_files"]) != DOWNLOAD_FILES or p["xray"]["version"] != "v26.11.9":
        raise ValueError("Unsupported artifacts or engine version")
    if p["openvpn"]["status"] != "BLOCKED":
        raise ValueError("OpenVPN is not in the core profile")
    # The separately deployed relay deliberately has no target/listener CLI overrides.
    if inner["ssh_relay"] != 10015 or inner["dropbear"] != 109:
        raise ValueError("Relay fixed-port contract mismatch")


def load_ports(path=None):
    with Path(path or SOURCE_ROOT / "config/ports.json").open(encoding="utf-8") as stream:
        p = json.load(stream)
    validate_ports(p)
    return p


def new_server_key():
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def validate_server_key(key):
    try:
        raw = base64.b64decode(key, validate=True)
        if len(raw) == 32 and base64.b64encode(raw).decode("ascii") == key:
            return
    except (ValueError, TypeError, binascii.Error):
        pass
    raise ValueError("Invalid Shadowsocks server key")  # Never include key in errors.


def nginx_config(domain, p):
    i, host = p["internal"], p["loopback"]
    text = f"""# Generated core only; download files are provisioned separately, never here.
user www-data;
worker_processes auto;
pid /run/nathaya-nginx/nginx.pid;
error_log {LOGS}/nginx-error.log warn;
events {{ worker_connections 1024; }}
http {{
    access_log off;
    server_tokens off;
    autoindex off;
    default_type application/octet-stream;
    client_body_temp_path /run/nathaya-nginx/body;
    proxy_temp_path /run/nathaya-nginx/proxy;
    fastcgi_temp_path /run/nathaya-nginx/fastcgi;
    uwsgi_temp_path /run/nathaya-nginx/uwsgi;
    scgi_temp_path /run/nathaya-nginx/scgi;
    client_max_body_size 0;
    client_header_timeout 10s;
    client_body_timeout 60s;
    send_timeout 60s;
    map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
    server {{
        listen {host}:{i['nginx_ws']} proxy_protocol;
        server_name {domain};
        set_real_ip_from {host};
        real_ip_header proxy_protocol;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        location = /healthz {{ default_type text/plain; return 200 "Nathaya Tunnel"; }}
"""
    for proto in PROTOCOLS:
        r = p["routes"][proto]
        text += f"        location = {r['ws_path']} {{ proxy_pass http://{host}:{r['ws_port']}; }}\n"
    # Unknown HTTP paths intentionally use the same fixed SSH relay, never an arbitrary target.
    for route in ("= " + p["ssh_ws_path"], "/"):
        text += f"        location {route} {{ proxy_pass http://{host}:{i['ssh_relay']}; }}\n"
    text += f"""    }}
    server {{
        # Ubuntu Noble nginx 1.24: HTTP/2 is a listen parameter (not http2 on).
        listen {host}:{i['nginx_grpc']} http2 proxy_protocol;
        server_name {domain};
        set_real_ip_from {host};
        real_ip_header proxy_protocol;
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
        location = /healthz {{ default_type text/plain; return 200 "Nathaya Tunnel"; }}
"""
    for proto in PROTOCOLS:
        r = p["routes"][proto]
        text += f"        location ^~ /{r['grpc_service']}/ {{ grpc_pass grpc://{host}:{r['grpc_port']}; }}\n"
    text += f"""        location / {{ return 404; }}
    }}
    server {{
        listen 0.0.0.0:{p['public']['tls_download']} ssl;
        server_name {domain};
        ssl_certificate {TLS}/fullchain.pem;
        ssl_certificate_key {TLS}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        disable_symlinks on;
"""
    for name in p["download_files"]:
        text += f"""        location = /{name} {{
            limit_except GET {{ deny all; }}
            alias {DOWNLOAD_ROOT}/{name};
            add_header Content-Disposition 'attachment; filename="{name}"' always;
        }}
"""
    return text + "        location / { return 404; }\n    }\n}\n"


def haproxy_config(p):
    i, host = p["internal"], p["loopback"]
    binds = "\n".join(f"    bind 0.0.0.0:{port}" for port in p["public"]["haproxy"])
    return f"""# One backend server per protocol; never balance across protocols.
global
    master-worker
    user haproxy
    group haproxy
    maxconn 2048
    ssl-default-bind-options ssl-min-ver TLSv1.2

defaults
    mode tcp
    timeout connect 5s
    timeout client 300s
    timeout server 300s
    timeout tunnel 300s

frontend public_mux
{binds}
    tcp-request inspect-delay 5s
    acl tls_hello req.ssl_hello_type 1
    acl ssh_prefix req.payload(0,7) -m bin 5353482d322e30
    tcp-request content accept if tls_hello
    tcp-request content accept if ssh_prefix
    tcp-request content accept if HTTP
    use_backend tls_terminator if tls_hello
    use_backend ssh_plain if ssh_prefix
    default_backend http_ws

backend tls_terminator
    server tls abns@nathaya-tls send-proxy-v2

frontend decrypted_tls
    bind abns@nathaya-tls accept-proxy ssl crt {TLS}/haproxy.pem alpn h2,http/1.1
    tcp-request inspect-delay 5s
    acl grpc_alpn ssl_fc_alpn -m str h2
    acl ssh_prefix req.payload(0,7) -m bin 5353482d322e30
    tcp-request content accept if grpc_alpn
    tcp-request content accept if ssh_prefix
    tcp-request content accept if HTTP
    use_backend grpc_h2 if grpc_alpn
    use_backend ssh_tls if ssh_prefix
    default_backend http_ws

backend http_ws
    server nginx {host}:{i['nginx_ws']} send-proxy-v2

backend grpc_h2
    server nginx {host}:{i['nginx_grpc']} send-proxy-v2

backend ssh_plain
    server ssh {host}:{i['sshd_plain']}

backend ssh_tls
    server ssh {host}:{i['sshd_tls']}
"""


def xray_config(proto, p, ss_server_key):
    r = p["routes"][proto]
    inbounds = []
    for transport in ("ws", "grpc"):
        settings = {"clients": []}
        if proto == "vless":
            settings["decryption"] = "none"
        if proto == "shadowsocks":
            settings.update(method="2022-blake3-aes-256-gcm", password=ss_server_key, network="tcp")
        stream = {"network": transport, "security": "none"}
        stream["wsSettings" if transport == "ws" else "grpcSettings"] = (
            {"path": r["ws_path"]} if transport == "ws" else {"serviceName": r["grpc_service"]})
        inbounds.append({"tag": proto + "-" + transport, "listen": p["loopback"],
                         "port": r[transport + "_port"], "protocol": proto,
                         "settings": settings, "streamSettings": stream})
    inbounds.append({"tag": "api-in", "listen": p["loopback"], "port": r["stats_port"],
                     "protocol": "dokodemo-door", "settings": {"address": p["loopback"]}})
    return json.dumps({
        "log": {"access": "none", "error": f"{LOGS}/{proto}-error.log", "loglevel": "warning"},
        "api": {"tag": "api", "services": ["StatsService"]}, "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                   "system": {"statsInboundUplink": True, "statsInboundDownlink": True}},
        "inbounds": inbounds,
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}]}
    }, indent=2) + "\n"


def unit(description, command, *, extra="", writable=LOGS, caps="", user="root", group="root"):
    return f"""[Unit]
Description={description}
After=network.target

[Service]
Type=simple
User={user}
Group={group}
UMask=0077
StandardOutput=append:/opt/nathaya/logs/%N.log
StandardError=append:/opt/nathaya/logs/%N.log
{extra}ExecStart={command}
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet={caps}
AmbientCapabilities=
ReadWritePaths={writable}

[Install]
WantedBy=multi-user.target
"""


def render_core(domain, ports, *, ss_server_key):
    """Return exactly 15 flat staging outputs. No reads, writes or entropy here."""
    domain = validate_domain(domain)
    validate_ports(ports)
    validate_server_key(ss_server_key)
    i, pub = ports["internal"], ports["public"]
    result = {"nginx.conf": nginx_config(domain, ports), "haproxy.cfg": haproxy_config(ports)}
    for proto in PROTOCOLS:
        result[proto + ".json"] = xray_config(proto, ports, ss_server_key)
        result[proto + "@config.service"] = unit(
            "Nathaya " + proto + " (locked Xray v26.11.9)",
            f"/opt/nathaya/bin/xray run -config {XRAY}/{proto}/config.json")
    result["nathaya-nginx.service"] = unit(
        "Nathaya Nginx", f"/usr/sbin/nginx -c {SERVICES}/nginx.conf -g 'daemon off;'",
        group="www-data", writable=f"{LOGS} /run/nathaya-nginx",
        caps="CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER",
        extra="RuntimeDirectory=nathaya-nginx\nRuntimeDirectoryMode=0750\n"
              "ExecStartPre=/usr/bin/install -d -o www-data -g www-data -m 0700 /run/nathaya-nginx/body /run/nathaya-nginx/proxy /run/nathaya-nginx/fastcgi /run/nathaya-nginx/uwsgi /run/nathaya-nginx/scgi\n"
              f"ExecReload=/usr/sbin/nginx -s reload -c {SERVICES}/nginx.conf\n")
    # Root master reads private PEM/binds low ports; HAProxy drops worker UID/GID.
    # KILL permits master signals to non-root workers during USR2/reexec. It is
    # NOT a claimed fix for an unexplained setuid() failure on a particular VPS.
    result["nathaya-haproxy.service"] = unit(
        "Nathaya HAProxy", f"/usr/sbin/haproxy -W -db -f {SERVICES}/haproxy.cfg",
        caps="CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_KILL",
        extra="ExecReload=/bin/kill -USR2 $MAINPID\n")
    result["nathaya-ws.service"] = unit(
        "Nathaya fixed-target SSH WebSocket relay", "/usr/bin/python3 -I -B /opt/nathaya/services/ws_proxy.py",
        extra="DynamicUser=true\n", user="nathaya-ws", group="nathaya-ws", writable="")
    # SSH daemons must retain normal PAM/account-switching privileges. Do not apply
    # empty capabilities or NoNewPrivileges to them: this would silently break logins.
    ssh_caps = "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID CAP_SYS_CHROOT CAP_AUDIT_WRITE CAP_KILL CAP_NET_BIND_SERVICE"
    result["nathaya-dropbear.service"] = unit(
        "Nathaya Dropbear (pre-provisioned unique Ed25519 host key)",
        f"/usr/sbin/dropbear -F -E -w -p 0.0.0.0:{pub['dropbear']} -p 127.0.0.1:{i['dropbear']} "
        "-r /etc/dropbear/dropbear_ed25519_host_key", caps=ssh_caps,
        writable="/run /dev/pts /dev/ptmx /var/log /var/lib /tmp").replace("NoNewPrivileges=true", "NoNewPrivileges=false").replace("ProtectHome=true", "ProtectHome=false").replace("ProtectSystem=strict", "ProtectSystem=full")
    result["nathaya-sshd.service"] = unit(
        "Nathaya additional loopback OpenSSH (admin daemon unchanged)",
        f"/usr/sbin/sshd -D -f /etc/ssh/sshd_config -p {i['sshd_tls']} -p {i['sshd_plain']} "
        "-oListenAddress=127.0.0.1 -oPidFile=/run/nathaya-sshd.pid", caps=ssh_caps,
        extra="ExecStartPre=/usr/bin/test ! -L /run/sshd\n"
              "ExecStartPre=/usr/bin/install -d -o root -g root -m 0755 /run/sshd\n",
        writable="/run /dev/pts /dev/ptmx /var/log /var/lib /tmp").replace("NoNewPrivileges=true", "NoNewPrivileges=false").replace("ProtectHome=true", "ProtectHome=false").replace("ProtectSystem=strict", "ProtectSystem=full")
    return result


def deployment_destinations():
    """Metadata only: parent deployer handles preservation, permissions and validation."""
    result = {"nginx.conf": SERVICES + "/nginx.conf", "haproxy.cfg": SERVICES + "/haproxy.cfg"}
    for proto in PROTOCOLS:
        result[proto + ".json"] = f"{XRAY}/{proto}/config.json"
    for name in ("nathaya-nginx", "nathaya-haproxy", "nathaya-ws", "nathaya-dropbear", "nathaya-sshd") + tuple(p + "@config" for p in PROTOCOLS):
        result[name + ".service"] = "/etc/systemd/system/" + name + ".service"
    return result


def write_outputs(outputs, output_directory):
    """Exclusive creation only. Failure may leave a PRIVATE partial staging directory."""
    if set(outputs) != set(deployment_destinations()):
        raise ValueError("Unexpected output set")
    destination = Path(output_directory).absolute()
    if destination.parent.resolve() != destination.parent or destination.is_symlink():
        raise ValueError("Staging path must not contain symlinks")
    forbidden = (SOURCE_ROOT, Path("/etc/nathaya-tunnel"), Path("/etc/systemd/system"),
                 Path("/opt/nathaya"), Path("/run"))
    if any(destination == root or root in destination.parents for root in forbidden):
        raise ValueError("Staging must be outside source and runtime destinations")
    # No parents=True: never construct an implicit source/runtime directory tree.
    destination.mkdir(mode=0o700, exist_ok=False)
    for name, content in outputs.items():
        fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--output-directory", required=True, help="NEW staging directory outside the checkout")
    parser.add_argument("--ports", type=Path, help="Trusted local ports.json fixture; never downloaded")
    args = parser.parse_args(argv)
    try:
        domain = validate_domain(args.domain)
        outputs = render_core(domain, load_ports(args.ports), ss_server_key=new_server_key())
        write_outputs(outputs, args.output_directory)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "Rendering failed: check domain, trusted port profile and NEW staging directory.\n")
    # Deliberately do not print configs, keys, environment or exception values.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
