#!/usr/bin/env python3
"""Capture one read-only E64 WSS grind trace for emulator replay.

This tool only sends ``RequestDriverState`` and ``RequestDriverConfig``.
It never sends a ``GrinderAction``, never writes the database, and never
attempts a login. Supply a token obtained from a legitimate Owner session
with ``--token-file`` (preferred) or ``--token``.

Output:
  <out>.jsonl          one sample per line: wall time, monotonic time, state
  <out>.config.json    the RequestDriverConfig reply, if captured
  <out>.summary.json   transitions, weight/DD/NTC/fan ranges, failures

The live token is single-connection. Do not disconnect or reconnect during
the capture; start it before the grind and stop it afterwards.
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
from pathlib import Path
from typing import Any

try:
    import websocket  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - dependency is checked in main()
    websocket = None

try:
    from e64ws_client import login, login_no_password
except ModuleNotFoundError:  # pragma: no cover - package import path
    from tools.e64ws_client import login, login_no_password


def _ssl_options(insecure: bool, ca_file: str | None) -> dict[str, Any]:
    if insecure and ca_file:
        raise SystemExit("choose --insecure or --ca-file, not both")
    if insecure:
        return {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}
    if ca_file:
        return {"cert_reqs": ssl.CERT_REQUIRED, "ca_certs": ca_file}
    return {"cert_reqs": ssl.CERT_REQUIRED, "check_hostname": True}


def _read_token(path: str | None, literal: str | None) -> str:
    if path:
        token = Path(path).read_text().strip()
    elif literal:
        token = literal.strip()
    else:
        raise SystemExit("provide --token-file or --token")
    if not token:
        raise SystemExit("token is empty")
    return token


def summarize(samples: list[dict[str, Any]]) -> dict[str, Any]:
    if not samples:
        return {"samples": 0}
    states: list[dict[str, Any]] = []
    previous = None
    for sample in samples:
        state = sample.get("state") or {}
        current = state.get("grindState")
        if current != previous:
            states.append({"t": sample.get("t"), "wall": sample.get("wall"),
                           "state": current})
            previous = current
    weights = [float(s["state"]["grindCurrentWeightGr"]) for s in samples
               if isinstance(s.get("state"), dict)
               and isinstance(s["state"].get("grindCurrentWeightGr"), (int, float))]
    dd = [float(s["state"]["ddValueDum"]) for s in samples
          if isinstance(s.get("state"), dict)
          and isinstance(s["state"].get("ddValueDum"), (int, float))]
    ntc1 = [float(s["state"]["ntc1TempDegC"]) for s in samples
            if isinstance(s.get("state"), dict)
            and isinstance(s["state"].get("ntc1TempDegC"), (int, float))]
    fan1 = [float(s["state"]["fan1TachoRpm"]) for s in samples
            if isinstance(s.get("state"), dict)
            and isinstance(s["state"].get("fan1TachoRpm"), (int, float))]
    failures = sorted({str(s["state"].get("grindFailure")) for s in samples
                       if isinstance(s.get("state"), dict)
                       and s["state"].get("grindFailure") not in (None, "None")})
    active = [(s, s.get("state") or {}) for s in samples
              if (s.get("state") or {}).get("grindState")
              in ("Grind", "Grinding", "GbwPostGrind")]
    grind = None
    if active:
        first_sample, first_state = active[0]
        last_sample, last_state = active[-1]
        start_weight = first_state.get("grindStartWeightGr")
        if not isinstance(start_weight, (int, float)) or isinstance(start_weight, bool):
            start_weight = first_state.get("grindCurrentWeightGr")
        final_weight = None
        result_weight = None
        for sample in reversed(samples):
            state = sample.get("state") or {}
            value = state.get("grindFinalWeightGr")
            if final_weight is None and isinstance(value, (int, float)) \
                    and not isinstance(value, bool) and value:
                final_weight = value
            value = state.get("grindResultWeightGr")
            if result_weight is None and isinstance(value, (int, float)) \
                    and not isinstance(value, bool) and value:
                result_weight = value
            if final_weight is not None and result_weight is not None:
                break
        if final_weight is None:
            final_weight = last_state.get("grindCurrentWeightGr")
        if result_weight is None and isinstance(start_weight, (int, float)) \
                and isinstance(final_weight, (int, float)):
            result_weight = round(final_weight - start_weight, 3)
        grind = {
            "start_t": first_sample.get("t"),
            "end_t": last_sample.get("t"),
            "duration_s": round(
                (last_sample.get("t") or 0) - (first_sample.get("t") or 0), 3),
            "start_weight_gr": start_weight,
            "target_weight_gr": first_state.get("grindTargetWeightGr"),
            "result_weight_gr": result_weight,
            "final_weight_gr": final_weight,
        }
    return {
        "samples": len(samples),
        "duration_s": round(samples[-1].get("t", 0) - samples[0].get("t", 0), 3),
        "states": states,
        "grind": grind,
        "weight_gr": {
            "min": min(weights) if weights else None,
            "max": max(weights) if weights else None,
            "first": weights[0] if weights else None,
            "last": weights[-1] if weights else None,
        },
        "ddValueDum": {"min": min(dd) if dd else None,
                       "max": max(dd) if dd else None},
        "ntc1TempDegC": {"min": min(ntc1) if ntc1 else None,
                         "max": max(ntc1) if ntc1 else None},
        "fan1TachoRpm": {"min": min(fan1) if fan1 else None,
                         "max": max(fan1) if fan1 else None},
        "failures": failures,
    }


def request(ws: Any, command: str, msg_id: int) -> dict[str, Any]:
    ws.send(json.dumps({"type": command, "msgId": msg_id, "data": {}},
                       separators=(",", ":")))
    while True:
        raw = ws.recv()
        if isinstance(raw, bytes):
            raise RuntimeError("binary WSS reply while waiting for a JSON result")
        message = json.loads(raw)
        if message.get("refId") == msg_id:
            return message
        if message.get("pong") is True:
            continue
        # Keep waiting for the correlated reply; async events are ignored.
        if message.get("type") == "UnknownType":
            return message


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=9997)
    parser.add_argument("--token-file")
    parser.add_argument("--token")
    parser.add_argument("--login-role", help="log in locally (for example Owner)")
    parser.add_argument("--password-file", help="read the login password from a 0600 file")
    parser.add_argument("--allow-no-password", action="store_true",
                        help="use the documented FW-01 SELECT-only workaround if no password is supplied")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--ca-file")
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--duration", type=float, default=0.0,
                        help="seconds to capture; 0 means until Ctrl-C")
    parser.add_argument("--out", default=None,
                        help="JSONL path; default captures/grind-<timestamp>.jsonl")
    parser.add_argument("--no-config", action="store_true")
    parser.add_argument("--max-samples", type=int, default=100000)
    args = parser.parse_args(argv)
    if websocket is None:
        raise SystemExit(
            "install websocket-client: python3 -m pip install websocket-client")

    if args.token_file or args.token:
        token = _read_token(args.token_file, args.token)
    elif args.login_role:
        if args.allow_no_password:
            print("warning: using the FW-01 SELECT-only no-password workaround; "
                  "use only on an owner-controlled device", file=sys.stderr)
            token = login_no_password(args.host, insecure=args.insecure,
                                      ca_file=args.ca_file)
        else:
            if not args.password_file:
                raise SystemExit("provide --password-file, --token-file or --allow-no-password")
            password = Path(args.password_file).read_text().strip()
            token = login(args.host, args.login_role, password,
                          insecure=args.insecure, ca_file=args.ca_file)
    else:
        raise SystemExit("provide --token-file, --token or --login-role")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = Path(args.out or f"captures/grind-{stamp}.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    config_path = out.with_suffix(".config.json")
    summary_path = out.with_suffix(".summary.json")

    url = f"wss://{args.host}:{args.port}/?token={token}"
    ws = websocket.create_connection(
        url, timeout=10, sslopt=_ssl_options(args.insecure, args.ca_file))
    samples: list[dict[str, Any]] = []
    config: dict[str, Any] | None = None
    msg_id = 0
    started = time.monotonic()
    try:
        if not args.no_config:
            msg_id += 1
            reply = request(ws, "RequestDriverConfig", msg_id)
            if reply.get("type") == "RequestDriverConfigResult":
                config = reply.get("data")
                config_path.write_text(json.dumps(config, indent=2,
                                                  sort_keys=True) + "\n")
        with out.open("w", encoding="utf-8") as handle:
            while True:
                if args.duration and time.monotonic() - started >= args.duration:
                    break
                if len(samples) >= args.max_samples:
                    break
                msg_id += 1
                reply = request(ws, "RequestDriverState", msg_id)
                if reply.get("type") != "RequestDriverStateResult":
                    raise RuntimeError(
                        f"unexpected reply: {reply.get('type', 'unknown')}")
                sample = {
                    "t": round(time.monotonic() - started, 3),
                    "wall": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "state": reply.get("data"),
                }
                samples.append(sample)
                handle.write(json.dumps(sample, sort_keys=True) + "\n")
                handle.flush()
                print(f"\r{len(samples):5d} samples  "
                      f"state={sample['state'].get('grindState')}  "
                      f"weight={sample['state'].get('grindCurrentWeightGr')} g  "
                      f"dd={sample['state'].get('ddValueDum')}",
                      end="", file=sys.stderr, flush=True)
                if args.interval:
                    time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped by user", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - report and keep the capture
        print(f"\ncapture stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        summary = summarize(samples)
        if config is not None:
            summary["config"] = {"path": str(config_path),
                                 "configVersion": config.get("configVersion"),
                                 "id": config.get("id")}
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True)
                                + "\n")
        print(f"\nwrote {out} ({len(samples)} samples)", file=sys.stderr)
        print(f"wrote {summary_path}", file=sys.stderr)
        if config is not None:
            print(f"wrote {config_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
