#!/usr/bin/env python3
"""Authenticated fixed-destination HTTP CONNECT over TLS."""
import asyncio
import base64
import binascii
import ipaddress
import os
from pathlib import Path
import re
import secrets
import socket
import ssl


def request_status(raw, authority, password):
    request, *lines = raw[:-4].split(b'\r\n')
    parts = request.split(b' ')
    if len(parts) != 3 or parts[2] not in (b'HTTP/1.0', b'HTTP/1.1'):
        return 400
    if parts[0] != b'CONNECT' or parts[1].lower() != authority:
        return 403
    headers = {}
    for line in lines:
        key, separator, value = line.partition(b':')
        key = key.lower()
        if (not separator or not re.fullmatch(rb'[a-z0-9-]+', key) or key in headers
                or b'\x00' in value or b'\r' in value or b'\n' in value):
            return 400
        headers[key] = value.strip()
    if (b'transfer-encoding' in headers or headers.get(b'content-length', b'0') != b'0'
            or headers.get(b'host', authority).lower() != authority):
        return 400
    scheme, _, encoded = headers.get(b'proxy-authorization', b'').partition(b' ')
    if scheme.lower() != b'basic':
        return 407
    try:
        credential = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return 407
    return 200 if secrets.compare_digest(credential, b'nathaya:' + password) else 407


STATUS = {200: b'Connection Established', 400: b'Bad Request', 403: b'Forbidden',
          407: b'Proxy Authentication Required', 502: b'Bad Gateway', 503: b'Service Unavailable'}


def handler(authority, password, relay_key, upstream_port=18091):
    slots = asyncio.Semaphore(64)

    async def connect(reader, client):
        async def respond(code):
            client.write(b'HTTP/1.1 %d %s\r\n' % (code, STATUS[code]))
            if code == 407:
                client.write(b'Proxy-Authenticate: Basic realm="Nathaya"\r\n')
            if code != 200:
                client.write(b'Connection: close\r\nContent-Length: 0\r\n')
            client.write(b'\r\n')
            await asyncio.wait_for(client.drain(), 3)

        async def pipe(source, dest):
            while data := await asyncio.wait_for(source.read(32768), 900):
                dest.write(data)
                await asyncio.wait_for(dest.drain(), 30)

        upstream = None
        tasks = []
        try:
            if slots.locked():
                await respond(503)
                return
            async with slots:
                try:
                    raw = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 8)
                except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
                    await respond(400)
                    return
                status = request_status(raw, authority, password)
                if status != 200:
                    await respond(status)
                    return
                address = ipaddress.ip_address(client.get_extra_info('peername')[0].split('%', 1)[0])
                ip = str(address).encode('ascii')
                try:
                    reply, upstream = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', upstream_port), 3)
                    upstream.write(b'NATHAYA1 ' + relay_key + b' ' + ip + b'\n')
                    await asyncio.wait_for(upstream.drain(), 3)
                    if await asyncio.wait_for(reply.readexactly(3), 3) != b'OK\n':
                        raise OSError('relay rejected metadata')
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    await respond(502)
                    return
                await respond(200)
                tasks = [asyncio.create_task(pipe(reader, upstream)), asyncio.create_task(pipe(reply, client))]
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if upstream is not None:
                upstream.close()
            client.close()

    return connect


async def main():
    directory = Path(os.environ['CREDENTIALS_DIRECTORY'])
    relay_key = (directory / 'relay').read_bytes().strip()
    password = (directory / 'proxy_auth').read_bytes().strip()
    authority = (directory / 'domain').read_bytes().strip().lower() + b':109'
    if not re.fullmatch(rb'[a-f0-9]{64}', relay_key) or not re.fullmatch(rb'[a-f0-9]{48,128}', password):
        raise ValueError('Invalid Nathaya CONNECT credentials')
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(directory / 'certificate', directory / 'private_key')
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        listener.bind(('::', 8443))
        listener.listen(128)
        server = await asyncio.start_server(handler(authority, password, relay_key), sock=listener,
                                            ssl=tls, ssl_handshake_timeout=8, limit=8192)
        async with server:
            if addr := os.environ.get('NOTIFY_SOCKET'):
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
                    notifier.connect('\0' + addr[1:] if addr.startswith('@') else addr)
                    notifier.sendall(b'READY=1')
            await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
