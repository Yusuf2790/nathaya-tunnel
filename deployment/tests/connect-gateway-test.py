#!/usr/bin/env python3
"""Loopback HAProxy TLS → CONNECT gateway → mock SSH relay, no production credentials."""
import asyncio
import base64
import contextlib
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('connect_gateway', ROOT / 'modules/ssh/connect_gateway.py')
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)
DOMAIN = 'tunnel.example.test'
AUTHORITY = (DOMAIN + ':109').encode()
PASSWORD = b'a' * 48
RELAY = b'b' * 64
BANNER = b'SSH-2.0-NathayaFixture\r\n'


async def exercise(work, haproxy):
    observed = []

    async def upstream(reader, writer):
        try:
            observed.append(await reader.readline())
            writer.write(b'OK\n' + BANNER)
            await writer.drain()
            if data := await reader.read(1024):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    cert, key, pem = [work / item for item in ('cert.pem', 'key.pem', 'tls.pem')]
    subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1',
                    '-subj', '/CN=' + DOMAIN, '-addext', 'subjectAltName=DNS:' + DOMAIN,
                    '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    pem.write_bytes(cert.read_bytes() + key.read_bytes())
    relay = await asyncio.start_server(upstream, '127.0.0.1', 0)
    sockpath = work / 'connect.sock'
    internal = await asyncio.start_unix_server(gateway.handler(AUTHORITY, PASSWORD, RELAY, os.geteuid(),
                                                               relay.sockets[0].getsockname()[1]),
                                                path=str(sockpath), limit=8192)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    config = work / 'haproxy.cfg'
    template = (ROOT / 'deployment/nathaya-connect.cfg.in').read_text()
    config.write_text('defaults\n    timeout connect 3s\n    timeout client 10s\n    timeout server 10s\n\n' +
                      template.replace('[::]:8443 v4v6', f'127.0.0.1:{port}')
                      .replace('@CERT@', str(pem)).replace('/run/nathaya-connect/proxy.sock', str(sockpath)))
    tls = ssl.create_default_context(cafile=str(cert))
    process = None

    async def dial(host=DOMAIN):
        return await asyncio.open_connection('127.0.0.1', port, ssl=tls, server_hostname=host)

    async with relay, internal:
        try:
            subprocess.run([haproxy, '-c', '-f', str(config)], check=True)
            process = subprocess.Popen([haproxy, '-db', '-f', str(config)])
            for _ in range(50):
                try:
                    _, writer = await dial()
                    writer.close()
                    await writer.wait_closed()
                    break
                except ConnectionRefusedError:
                    await asyncio.sleep(0.1)
            else:
                raise AssertionError('HAProxy not listening')

            try:
                _, writer = await dial('wrong.example.test')
            except ssl.SSLCertVerificationError:
                pass
            else:
                writer.close()
                raise AssertionError('Wrong certificate name accepted')

            # An HTTP-only proxy client cannot use this TLS port. No credentials are sent here.
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            try:
                writer.write(b'CONNECT tunnel.example.test:109 HTTP/1.1\r\n\r\n')
                await writer.drain()
                assert not (await asyncio.wait_for(reader.read(64), 3)).startswith(b'HTTP/1.1 200')
            except ConnectionResetError:
                pass
            finally:
                writer.close()
                with contextlib.suppress(ConnectionResetError):
                    await writer.wait_closed()

            # Even a valid HTTP request on the Unix socket is rejected without trusted PROXY metadata.
            reader, writer = await asyncio.open_unix_connection(str(sockpath))
            try:
                writer.write(b'CONNECT tunnel.example.test:109 HTTP/1.1\r\n\r\n')
                await writer.drain()
                try:
                    assert await asyncio.wait_for(reader.read(1), 3) == b''
                except ConnectionResetError:
                    pass
            finally:
                writer.close()
                with contextlib.suppress(ConnectionResetError):
                    await writer.wait_closed()

            valid = b'Proxy-Authorization: Basic ' + base64.b64encode(b'nathaya:' + PASSWORD) + b'\r\n'
            wrong = b'Proxy-Authorization: Basic ' + base64.b64encode(b'nathaya:wrong') + b'\r\n'
            for target, headers, code in (
                (AUTHORITY, b'', 407), (AUTHORITY, wrong, 407),
                (b'outside.example.test:22', valid, 403),
                (AUTHORITY, valid + b'Content-Length: 1\r\n', 400),
                (AUTHORITY, valid + b'X-Forwarded-For: 198.51.100.10\r\n', 200),
            ):
                reader, writer = await dial()
                try:
                    writer.write(b'CONNECT ' + target + b' HTTP/1.1\r\nHost: ' + target + b'\r\n' + headers + b'\r\n')
                    await writer.drain()
                    response = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 3)
                    assert response.startswith(b'HTTP/1.1 %d ' % code), response
                    if code == 407:
                        assert b'Proxy-Authenticate: Basic' in response
                    if code == 200:
                        assert await asyncio.wait_for(reader.readline(), 3) == BANNER
                        writer.write(b'fixture data')
                        await writer.drain()
                        assert await asyncio.wait_for(reader.readexactly(12), 3) == b'fixture data'
                    else:
                        assert observed == []
                finally:
                    writer.close()
                    await writer.wait_closed()
            assert observed == [b'NATHAYA1 ' + RELAY + b' 127.0.0.1\n'], observed
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    haproxy = shutil.which('haproxy') or '/usr/sbin/haproxy'
    if not os.access(haproxy, os.X_OK):
        raise SystemExit('HAProxy diperlukan untuk uji CONNECT lokal.')
    with tempfile.TemporaryDirectory() as directory:
        asyncio.run(exercise(Path(directory), haproxy))
    print('OK: TLS/hostname, proxy auth, fixed target, trusted IP, dan raw SSH fixture; bukan login Dropbear.')
