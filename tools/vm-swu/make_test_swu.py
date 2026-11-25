#!/usr/bin/env python3
"""Build a small SWU signed with an owner-generated test key.

This is for the disposable QEMU image only. It does not use, copy or forge any
vendor key. The VM's `/etc/keys/hem-hsg-swupdate-key.pub` is replaced with the
generated public key before the test, which is a deliberate root-only trust
change on a disposable image.

Usage:
    python3 tools/vm-swu/make_test_swu.py --out /tmp/vm-swu-test
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile

DESCRIPTION = """software =
{{
    version = "{version}";
    description = "owner test package for the virtual grinder";
    hardware-compatibility: [ "1.0" ];

    marker: {{
        filename = "marker.txt";
        sha256 = "{sha256}";
    }};
}};
"""


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kwargs)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/vm-swu-test")
    ap.add_argument("--version", default="1.16-24-test")
    ap.add_argument("--key", help="existing RSA private key (default: generate)")
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    key = pathlib.Path(args.key) if args.key else out / "test-signing.key"
    pub = out / "test-signing.pub"

    if not key.exists():
        run(["openssl", "genrsa", "-out", str(key), "2048"])
    run(["openssl", "rsa", "-in", str(key), "-pubout", "-out", str(pub)])

    marker = out / "marker.txt"
    marker.write_text("signed update reached the virtual grinder\n")
    digest = hashlib.sha256(marker.read_bytes()).hexdigest()

    desc = out / "sw-description"
    desc.write_text(DESCRIPTION.format(version=args.version, sha256=digest))
    sig = out / "sw-description.sig"
    run(["openssl", "dgst", "-sha256", "-sign", str(key),
         "-out", str(sig), str(desc)])

    # cpio newc, order matters: sw-description, signature, payload.
    work = out / "cpio"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    for name in ("sw-description", "sw-description.sig", "marker.txt"):
        shutil.copy2(out / name, work / name)
    names = b"sw-description\nsw-description.sig\nmarker.txt\n"
    proc = subprocess.run(["cpio", "-o", "-H", "newc"], cwd=work,
                          input=names, capture_output=True)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return 1
    swu = out / "test-update.swu"
    swu.write_bytes(proc.stdout)

    print(f"key        {key}")
    print(f"public key {pub}")
    print(f"package    {swu} ({swu.stat().st_size} bytes)")
    print(f"marker     {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
