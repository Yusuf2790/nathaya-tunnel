#!/usr/bin/env python3
"""Local HAProxy + aiohttp integration; ephemeral ports, synthetic relay, no systemd."""
import asyncio
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile

import aiohttp
from aiohttp import web
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ws_gateway', REPO / 'modules/ssh/ws_gateway.py')
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)
DOMAIN = 'tunnel.example.test'
TOKEN = 'a' * 64  # Fixture only.


async def h2_fixture(reader, writer):
    conn = H2Connection(H2Configuration(client_side=False, header_encoding='ascii'))
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    try:
        while data := await reader.read(65535):
            for event in conn.receive_data(data):
                if isinstance(event, RequestReceived):
                    path = dict(event.headers)[':path'].encode()
                    conn.send_headers(event.stream_id, [(':status', '200'), ('content-type', 'application/grpc')])
                    conn.send_data(event.stream_id, path, end_stream=True)
            writer.write(conn.data_to_send())
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def grpc_path(https, tls, path):
    tls.set_alpn_protocols(['h2'])
    reader, writer = await asyncio.open_connection('127.0.0.1', https, ssl=tls)
    try:
        assert writer.get_extra_info('ssl_object').selected_alpn_protocol() == 'h2'
        conn = H2Connection(H2Configuration(client_side=True, header_encoding='ascii'))
        conn.initiate_connection()
        conn.send_headers(1, [(':method', 'POST'), (':authority', DOMAIN), (':path', path),
                              (':scheme', 'https'), ('content-type', 'application/grpc')], end_stream=True)
        writer.write(conn.data_to_send())
        await writer.drain()
        body = b''
        while data := await asyncio.wait_for(reader.read(65535), 3):
            for event in conn.receive_data(data):
                if isinstance(event, ResponseReceived):
                    assert dict(event.headers)[':status'] == '200'
                elif isinstance(event, DataReceived):
                    body += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    return body
            writer.write(conn.data_to_send())
            await writer.drain()
        raise AssertionError('HTTP/2 backend did not reply')
    finally:
        writer.close()
        await writer.wait_closed()


async def exercise(work, haproxy):
    cert, key, pem = (work / n for n in ('cert.pem', 'key.pem', 'tls.pem'))
    subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1',
                    '-subj', '/CN=' + DOMAIN, '-addext', 'subjectAltName=DNS:' + DOMAIN,
                    '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    pem.write_bytes(cert.read_bytes() + key.read_bytes())
    captures = []

    async def fake_ssh(reader, writer):
        try:
            captures.append(await reader.readline())
            writer.write(b'OK\n')
            await writer.drain()
            if data := await reader.read(4096):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    upstream = await asyncio.start_server(fake_ssh, '127.0.0.1', 0)
    upstream_port = upstream.sockets[0].getsockname()[1]
    runner = web.AppRunner(gateway.build_app(TOKEN, DOMAIN, upstream_port), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    gateway_port = runner.addresses[0][1]
    paths = ('/vless', '/vmess', '/trojan-ws', '/ss-ws')

    async def fake_nginx(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_bytes(request.path.encode())
        await ws.close()
        return ws

    proxy_backend = web.Application()
    for path in paths:
        proxy_backend.router.add_get(path, fake_nginx)
    nginx = web.AppRunner(proxy_backend)
    await nginx.setup()
    await web.TCPSite(nginx, '127.0.0.1', 0).start()
    grpc_backend = await asyncio.start_server(h2_fixture, '127.0.0.1', 0)
    grpc_port = grpc_backend.sockets[0].getsockname()[1]
    with socket.socket() as ws_port, socket.socket() as tls_port, socket.socket() as web_port:
        for sock in (ws_port, tls_port, web_port):
            sock.bind(('127.0.0.1', 0))
        http, https, extra_http = [sock.getsockname()[1] for sock in (ws_port, tls_port, web_port)]
    template = (REPO / 'deployment/nathaya-haproxy.cfg.in').read_text()
    cfg = (template.replace('    user haproxy\n    group haproxy\n', '')
           .replace('[::]:80 v4v6', f'127.0.0.1:{http}')
           .replace('[::]:443 v4v6', f'127.0.0.1:{https}')
           .replace('[::]:8080 v4v6', f'127.0.0.1:{extra_http}')
           .replace('dst_port 8080', f'dst_port {extra_http}')
           .replace('127.0.0.1:1010', f'127.0.0.1:{nginx.addresses[0][1]}')
           .replace('127.0.0.1:1013', f'127.0.0.1:{grpc_port}')
           .replace('127.0.0.1:18080', f'127.0.0.1:{gateway_port}')
           .replace('@DOMAIN@', DOMAIN).replace('@TOKEN@', TOKEN).replace('@CERT@', str(pem)))
    config = work / 'haproxy.cfg'
    config.write_text(cfg)
    process = None
    try:
        subprocess.run([haproxy, '-c', '-f', str(config)], check=True)
        process = subprocess.Popen([haproxy, '-db', '-f', str(config)])
        for _ in range(50):
            try:
                _, candidate = await asyncio.open_connection('127.0.0.1', http)
                candidate.close()
                await candidate.wait_closed()
                break
            except ConnectionRefusedError:
                await asyncio.sleep(0.1)
        else:
            raise AssertionError('HAProxy did not listen')
        tls = ssl.create_default_context(cafile=str(cert))
        # Connect using loopback fixture address; chain verification stays enabled.
        tls.check_hostname = False
        headers = {'Host': DOMAIN, 'X-Forwarded-For': '198.51.100.9', 'X-Real-IP': '198.51.100.9',
                   'X-Nathaya-Source-IP': '198.51.100.9', 'X-Nathaya-Relay-Auth': 'client-value'}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as client:
            async with client.get(f'http://127.0.0.1:{http}/ordinary', headers=headers, allow_redirects=False) as r:
                assert r.status == 308 and r.headers['Location'] == 'https://' + DOMAIN + '/ordinary'
            async with client.get(f'http://127.0.0.1:{extra_http}/', headers=headers, allow_redirects=False) as r:
                assert r.status == 308
            for path in paths:
                async with client.ws_connect(f'wss://127.0.0.1:{https}{path}', headers=headers, ssl=tls) as routed:
                    assert await routed.receive_bytes(timeout=3) == path.encode()
            for url in (f'ws://127.0.0.1:{http}/', f'wss://127.0.0.1:{https}/'):
                async with client.ws_connect(url, headers=headers, ssl=tls) as ws:
                    await ws.send_bytes(b'fixture SSH bytes')
                    assert await ws.receive_bytes(timeout=3) == b'fixture SSH bytes'
            expected = f'NATHAYA1 {TOKEN} 127.0.0.1\n'.encode()
            assert captures == [expected, expected], captures
            rejected = [(f'ws://127.0.0.1:{http}/wrong', headers, 404),
                        (f'ws://127.0.0.1:{http}/ssh', headers, 404),  # Obsolete SSH path.
                        (f'ws://127.0.0.1:{extra_http}/', headers, 404),
                        (f'wss://127.0.0.1:{https}/', {'Host': 'other.example.test'}, 400),
                        (f'ws://127.0.0.1:{gateway_port}/', {'Host': DOMAIN}, 403),
                        (f'ws://127.0.0.1:{gateway_port}/', {**headers, 'X-Nathaya-Relay-Auth': TOKEN,
                                                              'X-Nathaya-Source-IP': 'invalid'}, 403)]
            for url, request_headers, status in rejected:
                try:
                    ws = await client.ws_connect(url, headers=request_headers, ssl=tls)
                except aiohttp.WSServerHandshakeError as error:
                    assert error.status == status, error
                else:
                    await ws.close()
                    raise AssertionError('Invalid WebSocket request accepted')
            assert captures == [expected, expected]
        for name in ('vless-grpc', 'vmess-grpc', 'trojan-grpc', 'ss-grpc'):
            path = '/' + name + '/Tun'
            assert await grpc_path(https, tls, path) == path.encode()
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        grpc_backend.close()
        await grpc_backend.wait_closed()
        await nginx.cleanup()
        await runner.cleanup()
        upstream.close()
        await upstream.wait_closed()


if __name__ == '__main__':
    haproxy = shutil.which('haproxy') or '/usr/sbin/haproxy'
    if not os.access(haproxy, os.X_OK):
        raise SystemExit('HAProxy diperlukan untuk uji integrasi lokal.')
    with tempfile.TemporaryDirectory() as directory:
        asyncio.run(exercise(Path(directory), haproxy))
    print('OK: WS, WSS, HTTP redirect, host/path, dan metadata palsu (port lokal sementara).')
