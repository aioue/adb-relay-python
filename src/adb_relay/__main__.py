"""Command line: python -m adb_relay [options]. RELAY_HOST and RELAY_PORT set the defaults."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from . import __version__
from .relay import Relay, RelayConfig, load_tokens


def parse_args(argv: list | None = None) -> argparse.Namespace:
    d = RelayConfig()
    p = argparse.ArgumentParser(
        prog="adb-relay",
        description="WebSocket relay for remote ADB (adb-relay spec v1). "
        "Terminate TLS in front of it (reverse proxy) for wss://.",
    )
    p.add_argument("--host", default=os.environ.get("RELAY_HOST", d.host), help="bind address (env RELAY_HOST, default %(default)s)")
    p.add_argument("--port", type=int, default=int(os.environ.get("RELAY_PORT", d.port)), help="listen port (env RELAY_PORT, default %(default)s)")
    p.add_argument("--token-file", help="only accept the tokens in this file, one per line")
    p.add_argument("--handshake-timeout", type=float, default=d.handshake_timeout, metavar="SECONDS", help="default %(default)s; 0 disables")
    p.add_argument("--ping-interval", type=float, default=d.ping_interval, metavar="SECONDS", help="default %(default)s; 0 disables pings")
    p.add_argument("--ping-timeout", type=float, default=d.ping_timeout, metavar="SECONDS", help="default %(default)s")
    p.add_argument("--max-message-bytes", type=int, default=d.max_message_bytes, metavar="N", help="default %(default)s; 0 unlimited")
    p.add_argument("--max-buffer-bytes", type=int, default=d.max_buffer_bytes, metavar="N", help="per waiting connection, default %(default)s; 0 unlimited")
    p.add_argument("--max-waiting", type=int, default=d.max_waiting, metavar="N", help="unpaired connections, default %(default)s; 0 unlimited")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv: list | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    tokens = None
    if args.token_file:
        try:
            tokens = load_tokens(args.token_file)
        except (OSError, ValueError) as exc:
            print(f"adb-relay: {exc}", file=sys.stderr)
            return 2
    config = RelayConfig(
        host=args.host,
        port=args.port,
        handshake_timeout=args.handshake_timeout,
        ping_interval=args.ping_interval,
        ping_timeout=args.ping_timeout,
        max_message_bytes=args.max_message_bytes,
        max_buffer_bytes=args.max_buffer_bytes,
        max_waiting=args.max_waiting,
        tokens=tokens,
    )
    try:
        asyncio.run(Relay(config).serve_forever())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
