#!/usr/bin/env python3
"""Minimal local DNS fixture for the official-app emulator test.

It answers only ``sync.mahlkoenig.com`` with the explicitly supplied A
address and returns NXDOMAIN for every other name. It is intentionally not a
general DNS forwarder, so a test using it cannot silently resolve or contact
the public internet.
"""

from __future__ import annotations

import argparse
import ipaddress
import socketserver
import struct
import threading


HOSTNAME = "sync.mahlkoenig.com"


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, sock = self.request
        if len(packet) < 12:
            return
        ident, flags, questions, _answers, _authority, _additional = struct.unpack(
            "!6H", packet[:12]
        )
        if questions != 1:
            return
        offset = 12
        labels: list[str] = []
        try:
            while True:
                length = packet[offset]
                offset += 1
                if length == 0:
                    break
                if length > 63 or offset + length > len(packet):
                    return
                labels.append(packet[offset : offset + length].decode("ascii").lower())
                offset += length
            if offset + 4 > len(packet):
                return
            qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
            question = packet[12 : offset + 4]
        except (UnicodeDecodeError, IndexError):
            return
        name = ".".join(labels)
        answer_ip = self.server.answer_ip  # type: ignore[attr-defined]
        is_a_query = qtype == 1 and qclass == 1 and name == HOSTNAME
        response_flags = 0x8180 if is_a_query else 0x8183
        answers = 1 if is_a_query else 0
        header = struct.pack("!6H", ident, response_flags, 1, answers, 0, 0)
        answer = b""
        if is_a_query:
            answer = struct.pack(
                "!HHHLH4s", 0xC00C, 1, 1, 60, 4, ipaddress.ip_address(answer_ip).packed
            )
        sock.sendto(header + question + answer, self.client_address)


class DnsServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18553)
    parser.add_argument("--answer", default="135.125.89.103")
    args = parser.parse_args()
    ipaddress.ip_address(args.answer)
    server = DnsServer((args.host, args.port), DnsHandler)
    server.answer_ip = args.answer  # type: ignore[attr-defined]
    print(f"DNS fixture: {HOSTNAME} -> {args.answer} on {args.host}:{args.port}")
    print("All other names receive NXDOMAIN; no forwarding is performed.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
