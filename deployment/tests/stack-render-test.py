#!/usr/bin/env python3
"""Render stack configs in a temporary directory. No services or live PKI."""
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('render_stack', ROOT / 'deployment/render-stack.py')
render = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render)
EXPECTED = [('vless', '/vless', 'vless-grpc', 10001, 10005),
            ('vmess', '/vmess', 'vmess-grpc', 10002, 10006),
            ('trojan', '/trojan-ws', 'trojan-grpc', 10003, 10007),
            ('shadowsocks', '/ss-ws', 'ss-grpc', 10004, 10008)]
with tempfile.TemporaryDirectory() as temp:
    path = Path(temp)
    for name in ('ca.crt', 'client.crt', 'client.key', 'tls-crypt.key'):
        (path / name).write_text('fixture\n')
    render.render_xray(path)
    saved = (path / 'xray-credentials.json').read_bytes()
    render.render_xray(path)
    assert saved == (path / 'xray-credentials.json').read_bytes()
    render.render_nginx(path)
    render.render_vpn(path, '/fixture', 'test.example')
    inbounds = {entry['port']: entry for entry in json.loads((path / 'xray.json').read_text())['inbounds']}
    nginx = (path / 'nginx.conf').read_text()
    proxy = (ROOT / 'deployment/nathaya-haproxy.cfg.in').read_text()
    assert 'acl ssh_path path -m str /\n' in proxy
    assert 'default_backend' not in proxy
    for protocol, ws, grpc, ws_port, grpc_port in EXPECTED:
        assert all(inbounds[port]['listen'] == '127.0.0.1' for port in (ws_port, grpc_port))
        assert inbounds[ws_port]['protocol'] == protocol == inbounds[grpc_port]['protocol']
        assert inbounds[ws_port]['streamSettings']['wsSettings']['path'] == ws
        assert inbounds[grpc_port]['streamSettings']['grpcSettings']['serviceName'] == grpc
        assert f'location = {ws} {{ proxy_pass http://127.0.0.1:{ws_port};' in nginx
        assert f'location ^~ /{grpc}/ {{ grpc_pass grpc://127.0.0.1:{grpc_port};' in nginx
        assert f'/{grpc}/' in proxy
    for proto, port in (('tcp', 1194), ('udp', 2200)):
        profile = path / f'client-{proto}.ovpn'
        text = profile.read_text()
        assert f'remote test.example {port}' in text
        assert 'remote-cert-tls server' in text and 'verify-x509-name nathaya-openvpn name' in text
        assert profile.stat().st_mode & 0o777 == 0o600
print('OK: SSH root, delapan rute Xray, kredensial persisten, dan profil VPN (fixture).')
