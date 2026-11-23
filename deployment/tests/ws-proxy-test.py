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

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ws_gateway', REPO / 'modules/ssh/ws_gateway.py')
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)
DOMAIN = 'tunnel.example.test'
TOKEN = 'a' * 64  # Fixture only.


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
    with socket.socket() as ws_port, socket.socket() as tls_port:
        ws_port.bind(('127.0.0.1', 0)); tls_port.bind(('127.0.0.1', 0))
        http, https = ws_port.getsockname()[1], tls_port.getsockname()[1]
    template = (REPO / 'deployment/nathaya-haproxy.cfg.in').read_text()
    cfg = (template.replace('    user haproxy\n    group haproxy\n', '')
           .replace('[::]:80 v4v6', f'127.0.0.1:{http}')
           .replace('[::]:443 v4v6', f'127.0.0.1:{https}')
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
            for url in (f'ws://127.0.0.1:{http}/ssh', f'wss://127.0.0.1:{https}/ssh'):
                async with client.ws_connect(url, headers=headers, ssl=tls) as ws:
                    await ws.send_bytes(b'fixture SSH bytes')
                    assert await ws.receive_bytes(timeout=3) == b'fixture SSH bytes'
            expected = f'NATHAYA1 {TOKEN} 127.0.0.1\n'.encode()
            assert captures == [expected, expected], captures
            rejected = [(f'ws://127.0.0.1:{http}/wrong', headers, 404),
                        (f'wss://127.0.0.1:{https}/ssh', {'Host': 'other.example.test'}, 400),
                        (f'ws://127.0.0.1:{gateway_port}/ssh', {'Host': DOMAIN}, 403),
                        (f'ws://127.0.0.1:{gateway_port}/ssh', {**headers, 'X-Nathaya-Relay-Auth': TOKEN,
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
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
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
