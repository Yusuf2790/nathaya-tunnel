#!/usr/bin/env python3
"""Render Nathaya configs from preserved, root-only enrollment credentials."""
import json
from pathlib import Path
import re
import secrets
import sys
import uuid

ROUTES = (
    ('vless', '/vless', 'vless-grpc', 10001, 10005),
    ('vmess', '/vmess', 'vmess-grpc', 10002, 10006),
    ('trojan', '/trojan-ws', 'trojan-grpc', 10003, 10007),
    ('shadowsocks', '/ss-ws', 'ss-grpc', 10004, 10008),
)


def write(path, text, mode=0o600):
    path.write_text(text, encoding='ascii')
    path.chmod(mode)


def render_xray(directory):
    path = directory / 'xray-credentials.json'
    if path.exists():
        creds = json.loads(path.read_text())
    else:
        creds = {kind: str(uuid.uuid4()) if kind in ('vmess', 'vless') else secrets.token_hex(24)
                 for kind, *_ in ROUTES}
        write(path, json.dumps(creds, indent=2) + '\n')
    inbounds = []
    for kind, ws, grpc, port_ws, port_grpc in ROUTES:
        value = creds[kind]
        if kind in ('vless', 'vmess'):
            uuid.UUID(value)
            settings = {'clients': [{'id': value}]}
            if kind == 'vless':
                settings['decryption'] = 'none'
        elif not re.fullmatch('[a-f0-9]{48}', value):
            raise ValueError('invalid credentials')
        elif kind == 'trojan':
            settings = {'clients': [{'password': value}]}
        else:
            settings = {'method': 'aes-256-gcm', 'password': value, 'network': 'tcp'}
        for port, transport in ((port_ws, {'network': 'ws', 'wsSettings': {'path': ws}}),
                                (port_grpc, {'network': 'grpc', 'grpcSettings': {'serviceName': grpc}})):
            inbounds.append({'listen': '127.0.0.1', 'port': port, 'protocol': kind,
                             'settings': settings, 'streamSettings': transport})
    write(directory / 'xray.json', json.dumps({'log': {'loglevel': 'warning', 'access': 'none'},
          'inbounds': inbounds, 'outbounds': [{'protocol': 'freedom', 'tag': 'internet'},
                                             {'protocol': 'blackhole', 'tag': 'deny'}],
          'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': [
              {'type': 'field', 'ip': ['0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
                                       '172.16.0.0/12', '192.168.0.0/16', '::/128', '::1/128', 'fc00::/7', 'fe80::/10'],
               'outboundTag': 'deny'}]}}, indent=2) + '\n')


def render_nginx(directory):
    temp = ''.join(f'    {kind}_temp_path tmp-{kind};\n' for kind in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'))
    ws = ''.join(f'        location = {path} {{ proxy_pass http://127.0.0.1:{port}; }}\n'
                 for _, path, _, port, _ in ROUTES)
    grpc = ''.join(f'        location ^~ /{name}/ {{ grpc_pass grpc://127.0.0.1:{port}; }}\n'
                   for _, _, name, _, port in ROUTES)
    write(directory / 'nginx.conf', f'''worker_processes 1;
error_log stderr warn;
pid nginx.pid;
events {{ worker_connections 512; }}
http {{
    access_log off;
{temp}    server {{
        listen 127.0.0.1:1010;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1h;
{ws}        location / {{ return 404; }}
    }}
    server {{
        listen 127.0.0.1:1013 http2;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
{grpc}        location / {{ return 404; }}
    }}
}}
''', 0o644)


def render_vpn(directory, final_path, domain):
    for name, port, subnet, device in (('tcp', 1194, '10.79.94.0', 'nathovpnt'),
                                       ('udp', 2200, '10.79.22.0', 'nathovpnu')):
        protocol = 'tcp4-server' if name == 'tcp' else 'udp4'
        client_protocol = 'tcp4-client' if name == 'tcp' else 'udp4'
        write(directory / f'openvpn-{name}.conf', f'''port {port}
proto {protocol}
dev {device}
dev-type tun
topology subnet
server {subnet} 255.255.255.0
ca {final_path}/ca.crt
cert {final_path}/server.crt
key {final_path}/server.key
tls-crypt {final_path}/tls-crypt.key
dh none
tls-version-min 1.2
remote-cert-tls client
verify-client-cert require
data-ciphers AES-256-GCM:AES-128-GCM
keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup
verb 3
''')
        profile = f'''client
dev tun
proto {client_protocol}
remote {domain} {port}
nobind
persist-key
persist-tun
tls-version-min 1.2
remote-cert-tls server
verify-x509-name nathaya-openvpn name
data-ciphers AES-256-GCM:AES-128-GCM
verb 3
'''
        for tag, filename in (('ca', 'ca.crt'), ('cert', 'client.crt'), ('key', 'client.key'), ('tls-crypt', 'tls-crypt.key')):
            profile += f'<{tag}>\n' + (directory / filename).read_text(encoding='ascii').strip() + f'\n</{tag}>\n'
        write(directory / f'client-{name}.ovpn', profile)


if __name__ == '__main__':
    render_xray(Path(sys.argv[1]))
    render_nginx(Path(sys.argv[1]))
    render_vpn(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
