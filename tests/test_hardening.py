"""Limits and timeouts beyond the spec. In-process relay only."""

from __future__ import annotations

import asyncio
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from adb_relay import Relay, RelayConfig, load_tokens  # noqa: E402
from adb_relay.__main__ import parse_args  # noqa: E402
from test_conformance import RelayTestCase, token  # noqa: E402
from wsclient import OP_BINARY, OP_CONT, OP_TEXT, Client  # noqa: E402


class TestHandshakeTimeout(RelayTestCase):
    config = RelayConfig(host="127.0.0.1", port=0, handshake_timeout=0.5)

    async def test_closes_socket_that_never_handshakes(self) -> None:
        c = await self.raw()
        closed = await c.closed_within(3)
        self.assertEqual((closed.code, closed.reason), (1008, "handshake timeout"))

    async def test_drops_tcp_that_never_upgrades(self) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.relay.port)
        self.assertEqual(await asyncio.wait_for(reader.read(), 3), b"")
        writer.close()

    async def test_keeps_handshaked_waiter(self) -> None:
        dev = await self.client("dev", token())
        self.assertIsNone(await dev.closed_within(1.5))


class TestPings(RelayTestCase):
    config = RelayConfig(host="127.0.0.1", port=0, ping_interval=0.2, ping_timeout=0.5)

    async def test_releases_silent_peer_and_its_partner(self) -> None:
        t = token()
        dev = await self.client("dev", t)
        device = await self.client("device", t, auto_pong=False)
        self.assertIsNotNone(await device.closed_within(3))
        self.assertGreater(device.pings, 0)
        self.assertIsNotNone(await dev.closed_within(3))

    async def test_keeps_peers_that_answer(self) -> None:
        dev, device = await self.pair()
        # Keep reading (and so answering pings) for several ping periods.
        closes = await asyncio.gather(dev.closed_within(1.5), device.closed_within(1.5))
        self.assertEqual(closes, [None, None])
        await self.assert_forwards(device, dev, b"still here")
        self.assertGreater(dev.pings, 0)


class TestLimits(RelayTestCase):
    config = RelayConfig(host="127.0.0.1", port=0, max_message_bytes=1024, max_buffer_bytes=2048, max_waiting=3)

    async def test_closes_on_oversized_message(self) -> None:
        dev, device = await self.pair()
        await dev.send_binary(b"x" * 1025)
        self.assertEqual((await dev.closed_within(3)).code, 1009)

    async def test_counts_fragments_toward_message_limit(self) -> None:
        dev, device = await self.pair()
        await dev.send_frame(OP_BINARY, b"x" * 600, fin=False)
        await dev.send_frame(OP_CONT, b"x" * 600, fin=True)
        self.assertEqual((await dev.closed_within(3)).code, 1009)

    async def test_reassembles_fragmented_message(self) -> None:
        dev, device = await self.pair()
        await dev.send_frame(OP_BINARY, b"ab", fin=False)
        await dev.send_frame(OP_CONT, b"cd", fin=False)
        await dev.send_frame(OP_CONT, b"ef", fin=True)
        self.assertEqual(await device.recv(), b"abcdef")

    async def test_closes_waiter_over_buffer_limit(self) -> None:
        dev = await self.client("dev", token())
        for _ in range(3):
            await dev.send_binary(b"x" * 1000)
        closed = await dev.closed_within(3)
        self.assertEqual((closed.code, closed.reason), (1009, "pre-pairing buffer limit exceeded"))

    async def test_refuses_upgrade_beyond_max_waiting(self) -> None:
        for _ in range(3):
            await self.client("dev", token())
        with self.assertRaises(ConnectionRefusedError) as cm:
            await Client.connect(self.url)
        self.assertIn("503", str(cm.exception))

    async def test_paired_connections_free_waiting_slots(self) -> None:
        for _ in range(3):
            await self.pair()
        await self.pair()


class TestTokenAllowlist(RelayTestCase):
    config = RelayConfig(host="127.0.0.1", port=0, tokens=frozenset({"allowed-token"}))

    async def test_pairs_allowed_token(self) -> None:
        dev = await self.client("dev", "allowed-token")
        device = await self.client("device", "allowed-token")
        await self.assert_forwards(dev, device, b"ok")

    async def test_rejects_other_token(self) -> None:
        c = await self.client("dev", "guess")
        self.assertEqual((await c.closed_within(3)).code, 1008)

    def test_load_tokens_skips_comments_and_blanks(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("# comment\n\nalpha\n  beta  \n")
        try:
            self.assertEqual(load_tokens(fh.name), frozenset({"alpha", "beta"}))
        finally:
            os.unlink(fh.name)


class TestProtocolErrors(RelayTestCase):
    async def test_rejects_unmasked_frame(self) -> None:
        c = await self.raw()
        await c.send_frame(OP_TEXT, json.dumps({"v": 1, "role": "dev", "token": token()}).encode(), mask=False)
        self.assertEqual((await c.closed_within(3)).code, 1002)

    async def test_rejects_other_paths(self) -> None:
        with self.assertRaises(ConnectionRefusedError) as cm:
            await Client.connect(self.url, path="/other")
        self.assertIn("404", str(cm.exception))

    async def test_rejects_other_websocket_versions(self) -> None:
        with self.assertRaises(ConnectionRefusedError) as cm:
            await Client.connect(self.url, version="8")
        self.assertIn("426", str(cm.exception))

    async def test_echoes_client_close_code(self) -> None:
        c = await self.client("dev", token())
        await c.send_frame(0x8, struct.pack("!H", 4000))
        self.assertEqual((await c.closed_within(3)).code, 4000)


class TestCli(unittest.TestCase):
    def test_env_sets_host_and_port(self) -> None:
        old = {k: os.environ.get(k) for k in ("RELAY_HOST", "RELAY_PORT")}
        os.environ.update(RELAY_HOST="127.0.0.2", RELAY_PORT="19000")
        try:
            args = parse_args([])
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertEqual((args.host, args.port), ("127.0.0.2", 19000))

    def test_defaults_match_spec_networking(self) -> None:
        args = parse_args([])
        if "RELAY_HOST" not in os.environ:
            self.assertEqual(args.host, "0.0.0.0")
        if "RELAY_PORT" not in os.environ:
            self.assertEqual(args.port, 18765)


if __name__ == "__main__":
    unittest.main()
