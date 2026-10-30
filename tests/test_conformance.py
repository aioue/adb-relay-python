"""Spec v1 compliance checklist (prompts/specs.md section 10).

Runs against an in-process relay, or against any relay when ADB_RELAY_URL is
set (for example ADB_RELAY_URL=ws://127.0.0.1:18765/), so the same checks can
compare implementations. Tests of this relay's own extensions are skipped
for external targets.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from adb_relay import Relay, RelayConfig  # noqa: E402
from wsclient import OP_BINARY, Client, Closed  # noqa: E402

EXTERNAL = os.environ.get("ADB_RELAY_URL")


def token() -> str:
    return os.urandom(12).hex()


class RelayTestCase(unittest.IsolatedAsyncioTestCase):
    config = RelayConfig(host="127.0.0.1", port=0)

    async def asyncSetUp(self) -> None:
        if EXTERNAL:
            self.url = EXTERNAL
            self.relay = None
        else:
            self.relay = Relay(self.config)
            await self.relay.start()
            self.url = f"ws://127.0.0.1:{self.relay.port}/"
        self.clients: list = []

    async def asyncTearDown(self) -> None:
        for c in self.clients:
            await c.close()
        if self.relay is not None:
            await self.relay.close()

    async def client(self, role: str, tok: str, **kw) -> Client:
        c = await Client.handshake(self.url, role, tok, **kw)
        self.clients.append(c)
        return c

    async def raw(self, **kw) -> Client:
        c = await Client.connect(self.url, **kw)
        self.clients.append(c)
        return c

    async def pair(self) -> tuple:
        t = token()
        dev = await self.client("dev", t)
        device = await self.client("device", t)
        return dev, device

    async def assert_forwards(self, a: Client, b: Client, data: bytes) -> None:
        await a.send_binary(data)
        self.assertEqual(await b.recv(), data)

    async def assert_rejected(self, c: Client) -> Closed:
        closed = await c.closed_within(5)
        self.assertIsNotNone(closed, "relay kept the connection open")
        return closed


class TestUpgrade(RelayTestCase):
    async def test_upgrades_on_root_path(self) -> None:
        dev, device = await self.pair()
        await self.assert_forwards(dev, device, b"x")


class TestHandshake(RelayTestCase):
    async def test_rejects_binary_first(self) -> None:
        c = await self.raw()
        await c.send_binary(b"\x00")
        await self.assert_rejected(c)

    async def reject_text(self, text: str) -> None:
        c = await self.raw()
        await c.send_text(text)
        await self.assert_rejected(c)

    async def test_rejects_invalid_json(self) -> None:
        await self.reject_text("{not json")

    async def test_rejects_non_object(self) -> None:
        await self.reject_text("[1, 2]")

    async def test_rejects_wrong_version(self) -> None:
        await self.reject_text(json.dumps({"v": 2, "role": "dev", "token": token()}))

    async def test_rejects_version_as_string(self) -> None:
        await self.reject_text(json.dumps({"v": "1", "role": "dev", "token": token()}))

    async def test_rejects_unknown_role(self) -> None:
        await self.reject_text(json.dumps({"v": 1, "role": "admin", "token": token()}))

    async def test_rejects_empty_token(self) -> None:
        await self.reject_text(json.dumps({"v": 1, "role": "dev", "token": ""}))

    async def test_rejects_token_not_a_string(self) -> None:
        await self.reject_text(json.dumps({"v": 1, "role": "dev", "token": 123}))

    async def test_rejects_missing_field(self) -> None:
        await self.reject_text(json.dumps({"v": 1, "role": "dev"}))

    async def test_ignores_unknown_keys(self) -> None:
        t = token()
        dev = await self.raw()
        await dev.send_text(json.dumps({"v": 1, "role": "dev", "token": t, "client": "test"}))
        device = await self.client("device", t)
        await self.assert_forwards(dev, device, b"ok")

    async def test_closes_on_text_after_handshake(self) -> None:
        dev, device = await self.pair()
        await dev.send_text("hello")
        await self.assert_rejected(dev)


class TestPairing(RelayTestCase):
    async def test_forwards_both_ways_unchanged(self) -> None:
        dev, device = await self.pair()
        await self.assert_forwards(dev, device, bytes(range(256)))
        await self.assert_forwards(device, dev, b"\x00" * 3 + b"ADBM")

    async def test_forwards_a_large_message_as_one_message(self) -> None:
        dev, device = await self.pair()
        data = os.urandom(1024 * 1024)
        await self.assert_forwards(dev, device, data)

    async def test_keeps_message_order(self) -> None:
        dev, device = await self.pair()
        for i in range(50):
            await dev.send_binary(i.to_bytes(2, "big"))
        for i in range(50):
            self.assertEqual(await device.recv(), i.to_bytes(2, "big"))

    async def test_flushes_dev_buffer_fifo_on_pairing(self) -> None:
        t = token()
        dev = await self.client("dev", t)
        for i in range(5):
            await dev.send_binary(b"dev%d" % i)
        await asyncio.sleep(0.2)
        device = await self.client("device", t)
        for i in range(5):
            self.assertEqual(await device.recv(), b"dev%d" % i)
        await self.assert_forwards(dev, device, b"live")

    async def test_flushes_device_buffer_fifo_on_pairing(self) -> None:
        t = token()
        device = await self.client("device", t)
        for i in range(5):
            await device.send_binary(b"device%d" % i)
        await asyncio.sleep(0.2)
        dev = await self.client("dev", t)
        for i in range(5):
            self.assertEqual(await dev.recv(), b"device%d" % i)

    async def test_does_not_pair_different_tokens(self) -> None:
        dev = await self.client("dev", token())
        device = await self.client("device", token())
        await dev.send_binary(b"secret")
        with self.assertRaises(asyncio.TimeoutError):
            await device.recv(timeout=1.0)

    async def test_does_not_pair_same_role(self) -> None:
        t = token()
        a = await self.client("device", token())
        b = await self.client("device", t)
        c = await self.client("dev", t)
        await self.assert_forwards(c, b, b"to b")
        with self.assertRaises(asyncio.TimeoutError):
            await a.recv(timeout=0.5)

    async def test_many_sessions_in_parallel(self) -> None:
        async def one(i: int) -> None:
            dev, device = await self.pair()
            await self.assert_forwards(dev, device, b"session %d" % i)
            await self.assert_forwards(device, dev, b"reply %d" % i)

        await asyncio.gather(*(one(i) for i in range(20)))

    async def test_last_registration_wins(self) -> None:
        t = token()
        await self.client("dev", t)
        await asyncio.sleep(0.2)
        dev2 = await self.client("dev", t)
        await asyncio.sleep(0.2)
        device = await self.client("device", t)
        await self.assert_forwards(device, dev2, b"newest")


class TestDisconnect(RelayTestCase):
    async def test_closes_peer_when_dev_leaves(self) -> None:
        dev, device = await self.pair()
        await self.assert_forwards(dev, device, b"x")
        await dev.close()
        self.assertIsNotNone(await device.closed_within(5))

    async def test_closes_peer_when_device_drops_tcp(self) -> None:
        dev, device = await self.pair()
        await self.assert_forwards(dev, device, b"x")
        device.writer.transport.abort()
        self.assertIsNotNone(await dev.closed_within(5))

    async def test_removes_pending_entry_on_disconnect(self) -> None:
        t = token()
        gone = await Client.handshake(self.url, "dev", t)
        await asyncio.sleep(0.2)
        await gone.close()
        await asyncio.sleep(0.3)
        device = await self.client("device", t)
        dev = await self.client("dev", t)
        await self.assert_forwards(device, dev, b"fresh pair")


@unittest.skipIf(EXTERNAL, "this relay's behaviour beyond the spec")
class TestDisplacedWaiter(RelayTestCase):
    async def test_closes_displaced_waiter(self) -> None:
        t = token()
        dev1 = await self.client("dev", t)
        await asyncio.sleep(0.2)
        await self.client("dev", t)
        closed = await dev1.closed_within(3)
        self.assertIsNotNone(closed)
        self.assertEqual((closed.code, closed.reason), (1000, "replaced by a newer connection"))


if __name__ == "__main__":
    unittest.main()
