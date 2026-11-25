"""Small standalone OpenScale local CLI.

Examples (on an owner-controlled LAN):

    python -m tools.openscale_cli --host hds.local --status
    python -m tools.openscale_cli --host hds.local --rate 10 --samples 20
    python -m tools.openscale_cli --host hds.local --rate 10 --shot-seconds 30

The CLI only sends status/rate commands.  Shot capture is explicit and emits
JSON; it does not contact Decaid or the E64 and does not send tare/power/event
controls.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from tools.openscale_client import OpenScaleClient, OpenScaleProtocolError, OpenScaleSnapshot
from tools.openscale_shots import OpenScaleShotAccumulator


def _json_default(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"cannot serialize {type(value).__name__}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read a local OpenScale WebSocket")
    parser.add_argument("--host", default="hds.local")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--rate", type=int, choices=(2, 5, 10))
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--status", action="store_true", help="request one status frame")
    parser.add_argument("--samples", type=int, default=1, help="number of snapshots to print")
    parser.add_argument(
        "--shot-seconds",
        type=float,
        help="explicitly capture a shot for this wall-clock duration and print one JSON record",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.samples <= 0:
        raise SystemExit("--samples must be positive")
    if args.shot_seconds is not None and args.shot_seconds <= 0:
        raise SystemExit("--shot-seconds must be positive")
    client = OpenScaleClient(args.host, port=args.port, timeout=args.timeout)
    try:
        if args.rate is not None:
            client.set_rate(args.rate)
        if args.status:
            client.send_safe("status")
            print(json.dumps(client.recv_frame(), default=_json_default, sort_keys=True))
            return 0
        if args.shot_seconds is None:
            for _ in range(args.samples):
                frame = client.recv_frame()
                if not isinstance(frame, OpenScaleSnapshot):
                    continue
                print(json.dumps(frame.raw, sort_keys=True))
            return 0

        accumulator = OpenScaleShotAccumulator(metadata={"host": args.host, "rate_hz": args.rate})
        accumulator.start()
        deadline = time.monotonic() + args.shot_seconds
        while time.monotonic() < deadline:
            frame = client.recv_frame()
            if isinstance(frame, OpenScaleSnapshot):
                accumulator.add_snapshot(frame)
        print(json.dumps(accumulator.finish(), sort_keys=True, default=_json_default))
        return 0
    except (OpenScaleProtocolError, OSError) as exc:
        print(f"OpenScale error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
