"""WebSocket relay for remote ADB, following the adb-relay spec v1.

A relay accepts WebSocket connections on ``/``. Each client's first message is a
JSON text handshake ``{"v": 1, "role": "dev" | "device", "token": "..."}``. One
``dev`` and one ``device`` that present the same token are paired, and from then
on every binary message from one is sent unchanged to the other. Binary messages
that arrive before the peer does are buffered and flushed in order when it
arrives. The relay never parses the mux frames inside binary messages.

Spec: https://github.com/AndroidGradleTools/adb-relay-jvm/blob/main/prompts/specs.md

Beyond the spec (all configurable, see :class:`RelayConfig`):

* a deadline for the handshake;
* server pings, so a peer that vanishes without closing is released;
* limits on message size, pre-pairing buffer, and waiting connections;
* an optional token allowlist;
* a waiter displaced by a newer one with the same role and token is closed
  rather than left open (the spec's "last registration wins" still holds).

Standard library only. One asyncio event loop, so pairing is race-free without
locks: the pending maps are only touched between awaits.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import struct
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("adb_relay")

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA
_DATA_OPCODES = (OP_CONT, OP_TEXT, OP_BINARY)
_CONTROL_OPCODES = (OP_CLOSE, OP_PING, OP_PONG)

ROLE_DEV = "dev"
ROLE_DEVICE = "device"
ROLES = (ROLE_DEV, ROLE_DEVICE)

# Close codes (RFC 6455 section 7.4.1).
CLOSE_NORMAL = 1000
CLOSE_PROTOCOL_ERROR = 1002
CLOSE_UNSUPPORTED_DATA = 1003
CLOSE_POLICY_VIOLATION = 1008
CLOSE_TOO_BIG = 1009
CLOSE_INTERNAL_ERROR = 1011

MAX_HTTP_HEAD = 8 * 1024
MAX_FRAGMENTS = 1024


@dataclass(frozen=True)
class RelayConfig:
    """Relay settings. Zero disables a timeout or limit."""

    host: str = "0.0.0.0"
    port: int = 18765
    # Seconds from TCP accept to a valid JSON handshake.
    handshake_timeout: float = 30.0
    # Seconds between server pings, and how long to wait for the pong.
    ping_interval: float = 15.0
    ping_timeout: float = 15.0
    # Largest WebSocket message (after reassembling fragments), in bytes.
    max_message_bytes: int = 16 * 1024 * 1024
    # Binary bytes one connection may buffer while waiting for its peer.
    max_buffer_bytes: int = 32 * 1024 * 1024
    # Connections not yet paired (including those still handshaking).
    max_waiting: int = 1024
    # If set, only these tokens may handshake. None accepts any token.
    tokens: Optional[frozenset] = None


class CloseConnection(Exception):
    """Raised inside a reader to close this connection with a code and reason."""

    def __init__(self, code: int, reason: str = "") -> None:
        super().__init__(code, reason)
        self.code = code
        self.reason = reason


def _unmask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    key = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big")


def _frame(opcode: int, payload: bytes) -> bytes:
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 1 << 16:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


class Connection:
    """One client WebSocket."""

    _ids = 0

    def __init__(self, relay: "Relay", reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        Connection._ids += 1
        self.id = Connection._ids
        self.relay = relay
        self.reader = reader
        self.writer = writer
        peer = writer.get_extra_info("peername")
        self.addr = peer[0] if isinstance(peer, tuple) else str(peer)
        self.role: Optional[str] = None
        self.token: Optional[str] = None
        self.peer: Optional[Connection] = None
        self.buffer: list = []
        self.buffered_bytes = 0
        self.closed = False
        self.upgraded = False
        # True while this connection counts against max_waiting.
        self.waiting = False
        self._write_lock = asyncio.Lock()
        # Serialises this side's buffered flush and live forwarding to the peer.
        self._forward_lock = asyncio.Lock()
        self._pong = asyncio.Event()

    def __repr__(self) -> str:
        return f"conn#{self.id}({self.role or '?'})"

    # -- writing ------------------------------------------------------------

    async def send(self, opcode: int, payload: bytes = b"") -> None:
        async with self._write_lock:
            if self.writer.is_closing():
                raise ConnectionResetError("closed")
            self.writer.write(_frame(opcode, payload))
            await self.writer.drain()

    async def close(self, code: int = CLOSE_NORMAL, reason: str = "") -> None:
        """Send a close frame (once, best effort) and drop the transport."""
        if self.closed:
            return
        self.closed = True
        body = struct.pack("!H", code) + reason.encode("utf-8")[:123]
        try:
            await asyncio.wait_for(self.send(OP_CLOSE, body), timeout=2.0)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        self.abort()

    def abort(self) -> None:
        self.closed = True
        transport = self.writer.transport
        if transport is not None and not transport.is_closing():
            transport.abort()

    # -- reading ------------------------------------------------------------

    async def read_message(self) -> tuple:
        """Next complete data message as (opcode, payload). Answers pings,
        records pongs, raises CloseConnection on a close frame or a protocol
        error, and IncompleteReadError when the TCP stream ends."""
        fragments: list = []
        size = 0
        message_opcode = None
        limit = self.relay.config.max_message_bytes
        while True:
            b1, b2 = await self.reader.readexactly(2)
            fin, rsv, opcode = b1 & 0x80, b1 & 0x70, b1 & 0x0F
            masked, length = b2 & 0x80, b2 & 0x7F
            if rsv:
                raise CloseConnection(CLOSE_PROTOCOL_ERROR, "reserved bits set")
            if opcode not in _DATA_OPCODES + _CONTROL_OPCODES:
                raise CloseConnection(CLOSE_PROTOCOL_ERROR, "unknown opcode")
            if not masked:
                raise CloseConnection(CLOSE_PROTOCOL_ERROR, "client frames must be masked")
            if opcode in _CONTROL_OPCODES and (length > 125 or not fin):
                raise CloseConnection(CLOSE_PROTOCOL_ERROR, "bad control frame")
            if length == 126:
                (length,) = struct.unpack("!H", await self.reader.readexactly(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", await self.reader.readexactly(8))
            # Check the declared size before reading the body.
            if opcode in _DATA_OPCODES and limit and size + length > limit:
                raise CloseConnection(CLOSE_TOO_BIG, "message too big")
            mask = await self.reader.readexactly(4)
            payload = _unmask(await self.reader.readexactly(length), mask) if length else b""

            if opcode == OP_PING:
                await self.send(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                self._pong.set()
                continue
            if opcode == OP_CLOSE:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else CLOSE_NORMAL
                raise CloseConnection(code if 1000 <= code < 5000 else CLOSE_NORMAL, "")

            if opcode == OP_CONT:
                if message_opcode is None:
                    raise CloseConnection(CLOSE_PROTOCOL_ERROR, "continuation without start")
            else:
                if message_opcode is not None:
                    raise CloseConnection(CLOSE_PROTOCOL_ERROR, "new message inside a fragmented one")
                message_opcode = opcode
            fragments.append(payload)
            size += length
            if len(fragments) > MAX_FRAGMENTS:
                raise CloseConnection(CLOSE_TOO_BIG, "too many fragments")
            if fin:
                return message_opcode, b"".join(fragments)

    # -- liveness -----------------------------------------------------------

    async def ping_loop(self, interval: float, timeout: float) -> None:
        """Ping every ``interval`` seconds; close if no pong within ``timeout``."""
        counter = 0
        while not self.closed:
            await asyncio.sleep(interval)
            counter += 1
            self._pong.clear()
            try:
                await asyncio.wait_for(self._ping_and_wait(counter), timeout=timeout)
            except asyncio.TimeoutError:
                log.info("event=ping_timeout %r", self)
                # The peer may not be reading, so do not wait on a close frame.
                self.abort()
                return
            except (ConnectionError, OSError):
                return

    async def _ping_and_wait(self, counter: int) -> None:
        await self.send(OP_PING, struct.pack("!Q", counter))
        await self._pong.wait()


class Relay:
    """Pairs dev and device connections by token and forwards between them."""

    def __init__(self, config: RelayConfig = RelayConfig()) -> None:
        self.config = config
        self.pending: dict = {ROLE_DEV: {}, ROLE_DEVICE: {}}
        self.waiting = 0
        self.server: Optional[asyncio.base_events.Server] = None

    @property
    def port(self) -> int:
        """The bound port (useful when configured with port 0)."""
        assert self.server is not None
        return self.server.sockets[0].getsockname()[1]

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle, self.config.host, self.config.port, limit=MAX_HTTP_HEAD + 1024
        )
        log.info("event=listen host=%s port=%d", self.config.host, self.port)

    async def serve_forever(self) -> None:
        if self.server is None:
            await self.start()
        assert self.server is not None
        async with self.server:
            await self.server.serve_forever()

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    # -- connection lifecycle -----------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = Connection(self, reader, writer)
        cfg = self.config
        ping_task: Optional[asyncio.Task] = None
        try:
            if cfg.max_waiting and self.waiting >= cfg.max_waiting:
                log.info("event=reject reason=too_many_waiting addr=%s", conn.addr)
                await self._http_error(writer, 503, "Service Unavailable")
                return
            self.waiting += 1
            conn.waiting = True
            try:
                await asyncio.wait_for(self._handshake(conn), timeout=cfg.handshake_timeout or None)
            except asyncio.TimeoutError:
                log.info("event=reject reason=handshake_timeout addr=%s", conn.addr)
                if conn.upgraded:
                    await conn.close(CLOSE_POLICY_VIOLATION, "handshake timeout")
                else:
                    conn.abort()
                return
            if conn.role is None:
                return  # _handshake already answered or closed
            if cfg.ping_interval:
                ping_task = asyncio.ensure_future(conn.ping_loop(cfg.ping_interval, cfg.ping_timeout or cfg.ping_interval))
            self._register(conn)
            await self._read_loop(conn)
        except CloseConnection as exc:
            await conn.close(exc.code, exc.reason)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            if ping_task is not None:
                ping_task.cancel()
            self._stop_waiting(conn)
            self._unregister(conn)
            if not conn.upgraded:
                conn.abort()  # answered with an HTTP error, or never upgraded
            elif not conn.closed:
                await conn.close(CLOSE_NORMAL)
            peer = conn.peer
            if peer is not None and not peer.closed:
                # Close coupling (spec 5.2): one side gone, close the other once.
                log.info("event=peer_closed %r closing %r", conn, peer)
                await peer.close(CLOSE_NORMAL, "peer closed")

    async def _http_error(self, writer: asyncio.StreamWriter, status: int, text: str) -> None:
        body = f"{status} {text}\n".encode()
        writer.write(
            f"HTTP/1.1 {status} {text}\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
        )
        try:
            await writer.drain()
        finally:
            writer.close()

    async def _handshake(self, conn: Connection) -> None:
        """HTTP upgrade, then the JSON handshake. Sets conn.role and conn.token
        on success; otherwise answers or closes and leaves conn.role None."""
        try:
            head = await conn.reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            conn.writer.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        headers = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
        path = parts[1].split("?", 1)[0] if len(parts) == 3 else ""
        if len(parts) != 3 or parts[0] != "GET":
            await self._http_error(conn.writer, 400, "Bad Request")
            return
        if path != "/":
            await self._http_error(conn.writer, 404, "Not Found")
            return
        if (
            headers.get("upgrade", "").lower() != "websocket"
            or "upgrade" not in headers.get("connection", "").lower()
            or not headers.get("sec-websocket-key")
        ):
            await self._http_error(conn.writer, 400, "Bad Request")
            return
        if headers.get("sec-websocket-version") != "13":
            conn.writer.write(b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n")
            await conn.writer.drain()
            conn.writer.close()
            return
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + WS_GUID).encode()).digest()).decode()
        conn.writer.write(
            (
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        await conn.writer.drain()
        conn.upgraded = True

        opcode, message = await conn.read_message()
        if opcode != OP_TEXT:
            log.info("event=reject reason=binary_first addr=%s", conn.addr)
            raise CloseConnection(CLOSE_UNSUPPORTED_DATA, "first frame must be text JSON handshake")
        role, token = self._parse_handshake(message)
        if role is None:
            log.info("event=reject reason=invalid_handshake addr=%s", conn.addr)
            raise CloseConnection(CLOSE_UNSUPPORTED_DATA, "invalid handshake")
        if self.config.tokens is not None and token not in self.config.tokens:
            log.info("event=reject reason=token_not_allowed role=%s addr=%s", role, conn.addr)
            raise CloseConnection(CLOSE_POLICY_VIOLATION, "invalid handshake")
        conn.role, conn.token = role, token
        log.info("event=handshake %r addr=%s", conn, conn.addr)

    @staticmethod
    def _parse_handshake(message: bytes) -> tuple:
        try:
            obj = json.loads(message.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None, None
        if not isinstance(obj, dict):
            return None, None
        v, role, token = obj.get("v"), obj.get("role"), obj.get("token")
        # bool is an int subclass; true must not pass for 1.
        if type(v) is not int or v != 1:
            return None, None
        if role not in ROLES or not isinstance(token, str) or not token:
            return None, None
        return role, token

    # -- pairing (spec section 5) -------------------------------------------

    def _register(self, conn: Connection) -> None:
        other_role = ROLE_DEVICE if conn.role == ROLE_DEV else ROLE_DEV
        other = self.pending[other_role].pop(conn.token, None)
        if other is not None and not other.closed:
            self._pair(dev=conn if conn.role == ROLE_DEV else other, device=other if conn.role == ROLE_DEV else conn)
            return
        displaced = self.pending[conn.role].get(conn.token)
        self.pending[conn.role][conn.token] = conn
        if displaced is not None and displaced is not conn and not displaced.closed:
            # Last registration wins (spec 5.3). The displaced waiter can never
            # be paired, so close it instead of leaving it open and buffering.
            log.info("event=replaced %r by %r", displaced, conn)
            asyncio.ensure_future(displaced.close(CLOSE_NORMAL, "replaced by a newer connection"))

    def _stop_waiting(self, conn: Connection) -> None:
        if conn.waiting:
            conn.waiting = False
            self.waiting -= 1

    def _unregister(self, conn: Connection) -> None:
        # Spec 5.4: remove the pending entry only if it is still this socket.
        if conn.role is not None and self.pending[conn.role].get(conn.token) is conn:
            del self.pending[conn.role][conn.token]

    def _pair(self, dev: Connection, device: Connection) -> None:
        dev.peer, device.peer = device, dev
        self._stop_waiting(dev)
        self._stop_waiting(device)
        log.info("event=paired %r %r", dev, device)
        # Flush both pre-pairing buffers FIFO (spec 5.2), each through its
        # forward lock so later live messages cannot overtake them.
        asyncio.ensure_future(self._forward(dev, None))
        asyncio.ensure_future(self._forward(device, None))

    async def _forward(self, conn: Connection, message: Optional[bytes]) -> None:
        """Send conn's buffered messages, then ``message``, to its peer in order."""
        peer = conn.peer
        if peer is None:
            return
        async with conn._forward_lock:
            try:
                while conn.buffer:
                    await peer.send(OP_BINARY, conn.buffer.pop(0))
                conn.buffered_bytes = 0
                if message is not None:
                    await peer.send(OP_BINARY, message)
            except (ConnectionError, OSError):
                pass

    async def _read_loop(self, conn: Connection) -> None:
        limit = self.config.max_buffer_bytes
        while True:
            opcode, message = await conn.read_message()
            if opcode == OP_TEXT:
                # Spec 4.3: only binary after the handshake; reference relays close.
                raise CloseConnection(CLOSE_UNSUPPORTED_DATA, "only binary frames after handshake")
            if conn.peer is not None:
                await self._forward(conn, message)
                continue
            if limit and conn.buffered_bytes + len(message) > limit:
                raise CloseConnection(CLOSE_TOO_BIG, "pre-pairing buffer limit exceeded")
            conn.buffer.append(message)
            conn.buffered_bytes += len(message)


async def serve(config: RelayConfig = RelayConfig()) -> None:
    """Run a relay until cancelled."""
    relay = Relay(config)
    await relay.serve_forever()


def load_tokens(path: str) -> frozenset:
    """One token per line; blank lines and lines starting with # are ignored."""
    with open(path, encoding="utf-8") as fh:
        tokens = frozenset(
            line.strip() for line in fh if line.strip() and not line.lstrip().startswith("#")
        )
    if not tokens:
        raise ValueError(f"{path}: no tokens")
    return tokens

