#!/usr/bin/env python3
"""Bridge a Decent Open Scale (HDS) shot into the local device-service cloud.

Reads HDS WiFi snapshots ({"grams","ms"}), detects a shot, applies the E64
validity window (>15 s and <= target+15 s) and posts the brew event to the
local cloud control API.

  bridge.py --scale ws://hds.local/ --control http://127.0.0.1:8081
  bridge.py --simulate --control http://127.0.0.1:8081     # no hardware
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request

try:
    import websocket  # websocket-client
except ImportError:
    websocket = None

START_GRAMS = 0.5
STABLE_WINDOW = 1.0
STABLE_DELTA = 0.2


class Shot:
    def __init__(self) -> None:
        self.active = False
        self.start_ms = 0
        self.samples: list[tuple[int, float]] = []

    def feed(self, grams: float, ms: int) -> dict | None:
        if not self.active and grams > START_GRAMS:
            self.active = True
            self.start_ms = ms
            self.samples = [(ms, grams)]
            return None
        if not self.active:
            return None
        self.samples.append((ms, grams))
        now = self.samples[-1]
        recent = [g for m, g in self.samples if m >= now[0] - STABLE_WINDOW * 1000]
        if len(recent) >= 2 and (max(recent) - min(recent)) <= STABLE_DELTA and now[0] - self.start_ms > 3000:
            event = {
                "mass": round(now[1], 2),
                "duration": round((now[0] - self.start_ms) / 1000.0, 1),
            }
            self.active = False
            self.samples = []
            return event
        if grams < 0.2 and self.samples:
            self.active = False
            self.samples = []
        return None


def post(control: str, event: dict) -> None:
    data = json.dumps(event).encode()
    request = urllib.request.Request(
        f"{control.rstrip('/')}/event", data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        print("queued:", response.read().decode()[:160], flush=True)


def run_ws(url: str, control: str, target: float) -> None:
    if websocket is None:
        raise SystemExit("websocket-client is required for live mode")
    ws = websocket.create_connection(url, timeout=10)
    ws.send("rate 10k")
    shot = Shot()
    while True:
        message = ws.recv()
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            continue
        if "grams" not in data:
            continue
        event = shot.feed(float(data["grams"]), int(data.get("ms", time.time() * 1000)))
        if event:
            event["target"] = target
            post(control, event)


def run_sim(control: str, target: float) -> None:
    shot = Shot()
    t0 = time.time()
    for i in range(400):  # 20 s at 20 Hz
        t = (time.time() - t0)
        grams = min(18.0, t * 2.0) if t < 9 else 18.0
        event = shot.feed(grams, int(t * 1000))
        if event:
            event["target"] = target
            print("simulated shot:", event, flush=True)
            post(control, event)
            return
        time.sleep(0.05)
    print('simulation ended without a detected shot', flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scale", default="ws://hds.local/")
    parser.add_argument("--control", default="http://127.0.0.1:8081")
    parser.add_argument("--target", type=float, default=25.0)
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()
    if args.simulate:
        run_sim(args.control, args.target)
    else:
        run_ws(args.scale, args.control, args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
