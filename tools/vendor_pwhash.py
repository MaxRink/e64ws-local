"""Reproduce the PHP checkLogin.php password verifier offline.

This module does not perform network login attempts. It is for verifying
candidate passwords against static hashes extracted from an owner-authorized
firmware image.
"""

from __future__ import annotations

import base64
import hashlib


def vendor_hash(password: str, salt: str, rounds: int) -> str:
    value = salt.encode()
    password_bytes = password.encode()
    salt_bytes = salt.encode()
    for _ in range(rounds):
        value = hashlib.sha256(value + password_bytes + salt_bytes + value).digest()
    return base64.b64encode(value).decode().rstrip("=")


def verify(password: str, encoded: str) -> bool:
    version, rounds, salt, expected = encoded.split("$", 3)
    if version != "1":
        return False
    return vendor_hash(password, salt, int(rounds)) == expected


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="check one candidate offline")
    parser.add_argument("password")
    parser.add_argument("encoded")
    args = parser.parse_args()
    print(verify(args.password, args.encoded))
