#!/usr/bin/env python3
"""Stdlib SSH relay: ONLY 127.0.0.1:10015 -> 127.0.0.1:109.

RFC6455 clients use validated masked binary frames and a computed accept value.
Legacy GET/HTTP Upgrade requests WITHOUT any Sec-WebSocket-* headers use raw
bytes after a 101 (no invented Sec-WebSocket-Accept). No header selects a target.
Text frames, extensions/subprotocol negotiation and arbitrary proxying unsupported.
Import is inert. Pure parsers are testable offline; only main()/serve() open sockets.
CLI: python3 -I -B services/ws_proxy.py (no address/target overrides).
"""
import argparse
import asyncio
import base64
import binascii
import contextlib
import hashlib
import re
import struct

LISTEN = ("127.0.0.1", 10015)
TARGET = ("127.0.0.1", 109)
HEADER_LIMIT = 8192
HEADER_TIMEOUT = 10
FRAME_LIMIT = 65536
MESSAGE_LIMIT = 1048576
FRAME_TIMEOUT = 30
READ_TIMEOUT = 300
WRITE_TIMEOUT = 30
CONNECT_TIMEOUT = 5
CONNECTION_LIMIT = 256
CHUNK_SIZE = 32768
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class ProtocolError(ValueError):
    """Fixed diagnostic only: never include client bytes or credential values."""

    def __init__(self, code=1002):
        super().__init__("Invalid relay protocol")
        self.code = code


def handshake(header):
    """Complete HTTP header -> (mode 'websocket'/'raw', response bytes)."""
    if len(header) > HEADER_LIMIT or not header.endswith(b"\r\n\r\n"):
        raise ProtocolError()
    lines = header[:-4].split(b"\r\n")
    if not lines or len(lines) > 65 or any(len(line) > 2048 for line in lines):
        raise ProtocolError()
    if not re.fullmatch(rb"GET /[^\x00-\x20\x7f-\xff]* HTTP/1\.1", lines[0]):
        raise ProtocolError()
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            raise ProtocolError()
        name, value = line.split(b":", 1)
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ProtocolError()
        name = name.lower()
        value = value.strip(b" \t")
        if name in headers or any(c < 32 or c > 126 for c in value):
            raise ProtocolError()
        headers[name] = value
    if not headers.get(b"host") or b"transfer-encoding" in headers:
        raise ProtocolError()
    if headers.get(b"content-length", b"0") != b"0":
        raise ProtocolError()
    if b"x-real-host" in headers and headers[b"x-real-host"] != b"127.0.0.1:109":
        raise ProtocolError()
    websocket_fields = any(name.startswith(b"sec-websocket-") for name in headers)
    if websocket_fields:
        if headers.get(b"upgrade", b"").lower() != b"websocket":
            raise ProtocolError()
        tokens = [token.strip().lower() for token in headers.get(b"connection", b"").split(b",")]
        if b"upgrade" not in tokens or headers.get(b"sec-websocket-version") != b"13":
            raise ProtocolError()
        if set(name for name in headers if name.startswith(b"sec-websocket-")) - {
                b"sec-websocket-key", b"sec-websocket-version", b"sec-websocket-extensions", b"sec-websocket-protocol"}:
            raise ProtocolError()
        key = headers.get(b"sec-websocket-key", b"")
        try:
            decoded = base64.b64decode(key, validate=True)
        except (ValueError, binascii.Error):
            raise ProtocolError() from None
        if len(decoded) != 16 or base64.b64encode(decoded) != key:
            raise ProtocolError()
        # Extensions/subprotocols are intentionally not selected in the response.
        accept = base64.b64encode(hashlib.sha1(key + GUID.encode("ascii")).digest())
        return "websocket", (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                             b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    if b"upgrade" in headers and headers[b"upgrade"].lower() != b"websocket":
        raise ProtocolError()
    return "raw", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"


def frame_prefix(data):
    """Masked client header -> (FIN, opcode, payload length, mask offset), or None."""
    if len(data) < 2:
        return None
    first, second = data[0], data[1]
    fin, opcode = bool(first & 128), first & 15
    if first & 112 or not second & 128 or opcode not in (0, 1, 2, 8, 9, 10):
        raise ProtocolError()
    length, offset = second & 127, 2
    if opcode >= 8 and (not fin or length > 125):
        raise ProtocolError()
    if length in (126, 127):
        size = 2 if length == 126 else 8
        if len(data) < offset + size:
            return None
        extended = int.from_bytes(data[offset:offset + size], "big")
        if extended < (126 if size == 2 else 65536) or extended >= 2 ** 63:
            raise ProtocolError()
        length, offset = extended, offset + size
    if length > FRAME_LIMIT:
        raise ProtocolError(1009)
    return fin, opcode, length, offset


def validate_close(payload):
    if len(payload) == 1:
        raise ProtocolError()
    if len(payload) >= 2:
        code = int.from_bytes(payload[:2], "big")
        if code not in {1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014} and not 3000 <= code <= 4999:
            raise ProtocolError()
        try:
            payload[2:].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ProtocolError(1007) from None


def decode_frame(data):
    """One client frame -> (FIN, opcode, unmasked payload, consumed), or None.

    Callers retain remaining bytes. Size is checked before awaiting/allocating payload.
    """
    prefix = frame_prefix(data)
    if prefix is None:
        return None
    fin, opcode, length, offset = prefix
    end = offset + 4 + length
    if len(data) < end:
        return None
    mask = data[offset:offset + 4]
    payload = bytes(value ^ mask[n % 4] for n, value in enumerate(data[offset + 4:end]))
    if opcode == 8:
        validate_close(payload)
    return fin, opcode, payload, end


def encode_frame(payload, opcode=2):
    """Unmasked, FIN server frame. No text, extensions or server masking."""
    if opcode not in (2, 8, 9, 10) or len(payload) > FRAME_LIMIT:
        raise ProtocolError(1009)
    if opcode >= 8 and len(payload) > 125:
        raise ProtocolError()
    if opcode == 8:
        validate_close(payload)
    length = len(payload)
    if length < 126:
        size = bytes([length])
    elif length < 65536:
        size = b"\x7e" + struct.pack("!H", length)
    else:
        size = b"\x7f" + struct.pack("!Q", length)
    return bytes([128 | opcode]) + size + payload


class BinaryMessages:
    """Bounded streaming fragment state; no message accumulation or text forwarding."""

    def __init__(self):
        self.fragmented = False
        self.size = 0

    def receive(self, fin, opcode, payload):
        if opcode in (8, 9, 10):
            return {8: "close", 9: "ping", 10: "pong"}[opcode], payload
        if opcode == 1:
            raise ProtocolError(1003)
        if opcode == 2:
            if self.fragmented:
                raise ProtocolError()
            self.size = 0
        elif opcode != 0 or not self.fragmented:
            raise ProtocolError()
        self.size += len(payload)
        if self.size > MESSAGE_LIMIT:
            raise ProtocolError(1009)
        self.fragmented = not fin
        if fin:
            self.size = 0
        return "data", payload


async def send(writer, payload):
    writer.write(payload)
    await asyncio.wait_for(writer.drain(), WRITE_TIMEOUT)


async def read_frame(reader):
    # Idle wait and active frame read have separate finite deadlines. Slowloris
    # peers cannot renew the active frame deadline by sending one byte at a time.
    first = await asyncio.wait_for(reader.readexactly(1), READ_TIMEOUT)

    async def remaining():
        head = first + await reader.readexactly(1)
        prefix = frame_prefix(head)
        if prefix is None:
            head += await reader.readexactly(2 if (head[1] & 127) == 126 else 8)
            prefix = frame_prefix(head)
        return decode_frame(head + await reader.readexactly(4 + prefix[2]))

    return await asyncio.wait_for(remaining(), FRAME_TIMEOUT)


async def websocket_to_ssh(reader, client, backend):
    messages = BinaryMessages()
    while True:
        fin, opcode, payload, _ = await read_frame(reader)
        action, data = messages.receive(fin, opcode, payload)
        if action == "close":
            await send(client, encode_frame(data, 8))
            return
        if action == "ping":
            await send(client, encode_frame(data, 10))
        elif action == "data":
            await send(backend, data)


async def copy_stream(reader, writer, framed=False):
    while True:
        data = await asyncio.wait_for(reader.read(CHUNK_SIZE), READ_TIMEOUT)
        if not data:
            if framed:
                await send(writer, encode_frame(struct.pack("!H", 1000), 8))
            elif writer.can_write_eof():
                writer.write_eof()
                await asyncio.wait_for(writer.drain(), WRITE_TIMEOUT)
            return
        await send(writer, encode_frame(data) if framed else data)


async def close_writer(writer):
    writer.close()
    with contextlib.suppress(OSError, asyncio.TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), WRITE_TIMEOUT)


async def handle_client(reader, writer):
    backend = None
    tasks = []
    mode = None
    try:
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT)
        mode, response = handshake(header)
        upstream, backend = await asyncio.wait_for(asyncio.open_connection(*TARGET, limit=HEADER_LIMIT), CONNECT_TIMEOUT)
        await send(writer, response)
        tasks = [asyncio.create_task(websocket_to_ssh(reader, writer, backend) if mode == "websocket"
                                     else copy_stream(reader, backend)),
                 asyncio.create_task(copy_stream(upstream, writer, framed=mode == "websocket"))]
        if mode == "raw":
            # Preserve TCP half-close: final SSH output can follow client EOF.
            await asyncio.gather(*tasks)
        else:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
    except ProtocolError as error:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await send(writer, encode_frame(struct.pack("!H", error.code), 8) if mode == "websocket" and backend
                       else b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass  # No request/header/payload/credential logging, including exception values.
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if backend is not None:
            await close_writer(backend)
        await close_writer(writer)


async def serve():
    slots = asyncio.Semaphore(CONNECTION_LIMIT)

    async def bounded(reader, writer):
        if slots.locked():
            await close_writer(writer)
            return
        async with slots:
            await handle_client(reader, writer)

    server = await asyncio.start_server(bounded, *LISTEN, limit=HEADER_LIMIT, backlog=128)
    async with server:
        await server.serve_forever()


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        return 0
    except OSError:
        return 1  # No socket diagnostics containing untrusted data.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
