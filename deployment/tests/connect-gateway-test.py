#!/usr/bin/env python3
"""Exercise fixed-destination authenticated CONNECT without a real SSH service."""
import asyncio
import base64
import importlib.util
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / 'modules/ssh/connect_gateway.py'
SPEC = importlib.util.spec_from_file_location('connect_gateway', SOURCE)
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)
AUTHORITY = b'tunnel.example.test:109'
PASSWORD = b'a' * 48
RELAY = b'b' * 64


async def exercise():
    observed = []

    async def upstream(reader, writer):
        try:
            observed.append(await reader.readline())
            writer.write(b'OK\n')
            await writer.drain()
            data = await reader.readexactly(5)
            writer.write(data)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    relay = await asyncio.start_server(upstream, '127.0.0.1', 0)
    proxy = await asyncio.start_server(gateway.handler(AUTHORITY, PASSWORD, RELAY, relay.sockets[0].getsockname()[1]),
                                       '127.0.0.1', 0, limit=8192)
    valid_auth = b'Proxy-Authorization: Basic ' + base64.b64encode(b'nathaya:' + PASSWORD) + b'\r\n'
    port = proxy.sockets[0].getsockname()[1]
    async with proxy, relay:
        for target, headers, code in (
            (AUTHORITY, b'', 407),
            (AUTHORITY, b'Proxy-Authorization: Basic bmF0aGF5YTp3cm9uZw==\r\n', 407),
            (b'outside.example.test:22', valid_auth, 403),
            (AUTHORITY, valid_auth + b'Content-Length: 1\r\n', 400),
            (AUTHORITY, valid_auth + b'X-Forwarded-For: 198.51.100.10\r\n', 200),
        ):
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            try:
                writer.write(b'CONNECT ' + target + b' HTTP/1.1\r\n' + headers + b'\r\n')
                await writer.drain()
                response = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 3)
                assert response.startswith(b'HTTP/1.1 %d ' % code), response
                if code == 200:
                    writer.write(b'hello')
                    await writer.drain()
                    assert await asyncio.wait_for(reader.readexactly(5), 3) == b'hello'
            finally:
                writer.close()
                await writer.wait_closed()
        assert observed == [b'NATHAYA1 ' + RELAY + b' 127.0.0.1\n'], observed


if __name__ == '__main__':
    asyncio.run(exercise())
    print('OK: 407/403/400, fixed upstream, source IP, and CONNECT data (local fixture).')
