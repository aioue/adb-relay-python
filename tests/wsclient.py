"""Minimal asyncio WebSocket client for the tests (standard library only)."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import struct
from urllib.parse import urlsplit

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class Closed(Exception):
    def __init__(self, code: int | None, reason: str = "") -> None:
        super().__init__(code, reason)
        self.code = code
        self.reason = reason


class Client:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, auto_pong: bool) -> None:
        self.reader = reader
        self.writer = writer
        self.auto_pong = auto_pong
        self.pings = 0

    @classmethod
    async def connect(cls, url: str, *, path: str = "/", auto_pong: bool = True, version: str = "13") -> "Client":
        u = urlsplit(url)
        reader, writer = await asyncio.open_connection(u.hostname, u.port)
        key = base64.b64encode(os.urandom(16)).decode()
        writer.write(
            (
                f"GET {path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: {version}\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode()
        if " 101 " not in status:
            writer.close()
            raise ConnectionRefusedError(status)
        return cls(reader, writer, auto_pong)

    @classmethod
    async def handshake(cls, url: str, role: str, token: str, **kw) -> "Client":
        c = await cls.connect(url, **kw)
        await c.send_text(json.dumps({"v": 1, "role": role, "token": token}))
        return c

    async def send_frame(self, opcode: int, payload: bytes, *, fin: bool = True, mask: bool = True) -> None:
        n = len(payload)
        b1 = (0x80 if fin else 0) | opcode
        mbit = 0x80 if mask else 0
        if n < 126:
            head = struct.pack("!BB", b1, mbit | n)
        elif n < 1 << 16:
            head = struct.pack("!BBH", b1, mbit | 126, n)
        else:
            head = struct.pack("!BBQ", b1, mbit | 127, n)
        if mask:
            key = os.urandom(4)
            body = (int.from_bytes(payload, "big") ^ int.from_bytes((key * (n // 4 + 1))[:n], "big")).to_bytes(n, "big") if n else b""
            self.writer.write(head + key + body)
        else:
            self.writer.write(head + payload)
        await self.writer.drain()

    async def send_text(self, text: str) -> None:
        await self.send_frame(OP_TEXT, text.encode())

    async def send_binary(self, data: bytes) -> None:
        await self.send_frame(OP_BINARY, data)

    async def recv(self, timeout: float = 5.0) -> bytes:
        """Next binary message. Raises Closed on a close frame or EOF."""
        return await asyncio.wait_for(self._recv_data(), timeout)

    async def _recv_data(self) -> bytes:
        while True:
            try:
                b1, b2 = await self.reader.readexactly(2)
            except (asyncio.IncompleteReadError, ConnectionError):
                raise Closed(None, "eof")
            opcode, n = b1 & 0x0F, b2 & 0x7F
            if n == 126:
                (n,) = struct.unpack("!H", await self.reader.readexactly(2))
            elif n == 127:
                (n,) = struct.unpack("!Q", await self.reader.readexactly(8))
            payload = await self.reader.readexactly(n) if n else b""
            if opcode == OP_PING:
                self.pings += 1
                if self.auto_pong:
                    await self.send_frame(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
                raise Closed(code, payload[2:].decode("utf-8", "replace"))
            return payload

    async def closed_within(self, timeout: float) -> Closed | None:
        """The close the server sent within ``timeout`` (data is discarded), else None."""
        try:
            while True:
                await self.recv(timeout)
        except Closed as c:
            return c
        except asyncio.TimeoutError:
            return None

    async def close(self) -> None:
        try:
            await self.send_frame(OP_CLOSE, struct.pack("!H", 1000))
        except (ConnectionError, OSError):
            pass
        self.writer.close()
