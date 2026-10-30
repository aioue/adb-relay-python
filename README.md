# adb-relay-python

A WebSocket relay for remote ADB, written in Python with only the standard library. It implements the [adb-relay spec v1](https://github.com/AndroidGradleTools/adb-relay-jvm/blob/main/prompts/specs.md), so it can stand in for [adb-relay-jvm](https://github.com/AndroidGradleTools/adb-relay-jvm) between the Android Gradle Tools [VS Code extension](https://github.com/AndroidGradleTools/android-ide-extension) (the `dev` side) and [adb-relay-android](https://github.com/AndroidGradleTools/adb-relay-android) (the `device` side).

The relay pairs one `dev` and one `device` that present the same token, then copies binary WebSocket messages between them unchanged. It never looks inside them. Messages sent before the peer arrives are buffered and delivered in order.

## Run it

Python 3.10 or later, no dependencies:

```sh
git clone https://github.com/aioue/adb-relay-python.git
cd adb-relay-python
PYTHONPATH=src python3 -m adb_relay            # listens on 0.0.0.0:18765
```

Or install the `adb-relay` command:

```sh
pipx install git+https://github.com/aioue/adb-relay-python.git
adb-relay --port 18765 --token-file /etc/adb-relay/tokens
```

`RELAY_HOST` and `RELAY_PORT` set the defaults, as with adb-relay-jvm. The relay speaks plain `ws://`. For `wss://`, put it behind a reverse proxy or tunnel that terminates TLS and forwards WebSocket upgrades, such as Caddy, nginx, Cloudflare Tunnel or Tailscale Funnel, and bind the relay to `127.0.0.1`.

## Options

| Option | Default | |
| --- | --- | --- |
| `--host` | `0.0.0.0` | Bind address (`RELAY_HOST`) |
| `--port` | `18765` | Listen port (`RELAY_PORT`) |
| `--token-file` | none | Accept only the tokens in this file, one per line (`#` comments allowed). Without it, any token pairs, as the spec describes. |
| `--handshake-timeout` | 30 s | Time from connecting to a valid handshake |
| `--ping-interval` | 15 s | Server pings; `0` turns them off |
| `--ping-timeout` | 15 s | Close a connection that misses a pong for this long |
| `--max-message-bytes` | 16 MiB | Largest message after reassembling fragments |
| `--max-buffer-bytes` | 32 MiB | Data one connection may buffer while waiting for its peer |
| `--max-waiting` | 1024 | Connections not yet paired; beyond this, upgrades get HTTP 503 |
| `--log-level` | `INFO` | Logs never contain tokens or payloads |

`0` turns off a timeout or limit.

## Behaviour

Everything in the spec's compliance checklist (section 10):

- WebSocket upgrade on `/`. Other paths get 404.
- The first message must be a JSON text handshake with `v` exactly `1` (a number, not `"1"` or `true`), `role` `dev` or `device`, and a non-empty string `token`. Unknown keys are ignored. Anything else, including a binary first message, closes the connection with 1003.
- One `dev` and one `device` with the same token are paired. Each side's buffered messages are flushed to the other in order, then every binary message is forwarded unchanged, in order, as one message.
- Text after the handshake closes the connection with 1003.
- When one side of a pair goes away, the other is closed. A waiting connection that disconnects is removed from the pending map.
- Pairing runs on a single asyncio event loop, so it is race-free.

Beyond the spec:

- **Displaced waiters are closed.** If a second `dev` (or `device`) handshakes with a token that already has a waiter of that role, the newer one wins, as spec section 5.3 says. The older one can never be paired, so it is closed with 1000 `replaced by a newer connection` rather than left open.
- **Server pings** release a peer that vanished without closing, such as a phone that changed networks, and close its partner so both can reconnect.
- **Limits** on handshake time, message size, buffering and waiting connections bound what an unauthenticated client can hold. With `--token-file`, only known tokens can pair.
- **RFC 6455 strictness:** unmasked client frames, reserved bits and malformed control frames close the connection with 1002.

## Use as a library

```python
import asyncio
from adb_relay import Relay, RelayConfig

async def main():
    relay = Relay(RelayConfig(host="127.0.0.1", port=0))
    await relay.start()
    print("listening on", relay.port)
    await relay.serve_forever()

asyncio.run(main())
```

## Tests

```sh
python3 -m unittest discover -s tests -v
```

`tests/test_conformance.py` checks the spec's compliance list. Point it at any relay to compare implementations:

```sh
ADB_RELAY_URL=ws://127.0.0.1:18765/ python3 -m unittest tests.test_conformance -v
```

`tests/test_hardening.py` covers the limits and timeouts above against an in-process relay.

## Provenance

This relay grew out of a private single-session relay that gives remote ADB access to one phone over Tailscale Funnel. That relay's WebSocket handling and limits were reworked here into a general implementation of the spec.

## Licence

MIT. See [LICENSE](LICENSE).
