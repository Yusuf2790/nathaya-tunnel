#!/usr/bin/env python3
"""Internal RFC 6455 binary WebSocket relay; HAProxy is the only public frontend."""

import asyncio
import grp
import ipaddress
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import struct

from aiohttp import web, WSMsgType


def credentials():
    directory = Path(os.environ['CREDENTIALS_DIRECTORY'])
    token = (directory / 'relay').read_text(encoding='ascii').strip()
    domain = (directory / 'domain').read_text(encoding='ascii').strip()
    if not re.fullmatch('[a-f0-9]{64}', token) or not domain:
        raise ValueError('Invalid Nathaya gateway credentials')
    return token, domain


def source_ip(request, token, domain):
    hosts = request.headers.getall('Host', [])
    if len(hosts) != 1 or hosts[0].lower() not in {domain, domain + ':80', domain + ':443'}:
        raise web.HTTPBadRequest()
    auth = request.headers.getall('X-Nathaya-Relay-Auth', [])
    sources = request.headers.getall('X-Nathaya-Source-IP', [])
    if (len(auth) != 1 or not auth[0].isascii() or not secrets.compare_digest(auth[0], token)
            or len(sources) != 1 or '%' in sources[0]):
        raise web.HTTPForbidden()
    try:
        return str(ipaddress.ip_address(sources[0]))
    except ValueError:
        raise web.HTTPForbidden() from None


def build_app(token, domain, upstream_port=18091):
    slots = asyncio.Semaphore(128)

    async def relay(request):
        source = source_ip(request, token, domain)
        if request.raw_path != '/':
            raise web.HTTPNotFound()
        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=262144, compress=False)
        if request.headers.get('Sec-WebSocket-Version') != '13' or not ws.can_prepare(request).ok:
            raise web.HTTPBadRequest()
        if slots.locked():
            raise web.HTTPServiceUnavailable()
        async with slots:
            try:
                reader, target = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', upstream_port), 3)
            except (OSError, asyncio.TimeoutError):
                raise web.HTTPBadGateway() from None
            tasks = []
            try:
                target.write(f'NATHAYA1 {token} {source}\n'.encode('ascii'))
                try:
                    await asyncio.wait_for(target.drain(), 3)
                    if await asyncio.wait_for(reader.readexactly(3), 3) != b'OK\n':
                        raise web.HTTPBadGateway()
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    raise web.HTTPBadGateway() from None
                await ws.prepare(request)

                async def upload():
                    async for msg in ws:
                        if msg.type == WSMsgType.BINARY:
                            target.write(msg.data)
                            await target.drain()
                        elif msg.type == WSMsgType.TEXT:
                            await ws.close(code=1003)
                            break

                async def download():
                    while data := await reader.read(32768):
                        await ws.send_bytes(data)

                tasks = [asyncio.create_task(upload()), asyncio.create_task(download())]
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks:
                    task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                target.close()
                if ws.prepared:
                    await ws.close()
            return ws

    app = web.Application()
    app.router.add_get('/', relay, allow_head=False)
    return app


PROXY_MAGIC = b'\r\n\r\n\x00\r\nQUIT\n'


async def proxy_source(reader):
    signature, version, family, size = struct.unpack('!12sBBH', await reader.readexactly(16))
    address_length = {0x11: 4, 0x21: 16}.get(family)
    if (signature != PROXY_MAGIC or version != 0x21 or address_length is None
            or not 2 * address_length + 4 <= size <= 512):
        raise ValueError('Invalid PROXY v2 TCP header')
    addresses = await reader.readexactly(size)
    return str(ipaddress.ip_address(addresses[:address_length]))


def raw_handler(token, trusted_uid, upstream_port=18091):
    slots = asyncio.Semaphore(128)

    async def handle(reader, client):
        target = None
        tasks = []
        try:
            sock = client.get_extra_info('socket')
            if sock is None or sock.family != socket.AF_UNIX or slots.locked():
                return
            _, uid, _ = struct.unpack('iII', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != trusted_uid:
                return
            async with slots:
                source = await asyncio.wait_for(proxy_source(reader), 3)
                incoming, target = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', upstream_port), 3)
                target.write(f'NATHAYA1 {token} {source}\n'.encode('ascii'))
                await asyncio.wait_for(target.drain(), 3)
                if await asyncio.wait_for(incoming.readexactly(3), 3) != b'OK\n':
                    return

                async def pipe(source_stream, destination):
                    while data := await source_stream.read(32768):
                        destination.write(data)
                        await asyncio.wait_for(destination.drain(), 30)

                tasks = [asyncio.create_task(pipe(reader, target)), asyncio.create_task(pipe(incoming, client))]
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if target is not None:
                target.close()
            client.close()

    return handle


async def main():
    token, domain = credentials()
    proxy = pwd.getpwnam('haproxy')
    proxy_group = grp.getgrnam('haproxy').gr_gid
    runtime = Path('/run/nathaya-ws')
    os.chown(runtime, -1, proxy_group)
    path = runtime / 'raw.sock'
    runner = web.AppRunner(build_app(token, domain), access_log=None)
    await runner.setup()
    server = None
    try:
        await web.TCPSite(runner, '127.0.0.1', 18080).start()
        server = await asyncio.start_unix_server(raw_handler(token, proxy.pw_uid), path=str(path))
        os.chown(path, -1, proxy_group)
        path.chmod(0o660)
        if addr := os.environ.get('NOTIFY_SOCKET'):
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
                notifier.connect('\0' + addr[1:] if addr.startswith('@') else addr)
                notifier.sendall(b'READY=1')
        await asyncio.Future()
    finally:
        if server is not None:
            server.close()
            await server.wait_closed()
            path.unlink(missing_ok=True)
        await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())
