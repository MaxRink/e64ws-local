#!/usr/bin/env python3
"""make_edpk.py - generate a valid /hde/edpk for the HSG HMI.

WHAT THE HMI DOES WITH EDPK (all observed in NgxUiApp 1.16-24)
-------------------------------------------------------------
`SystemIo::At24c16Driver::readEncryptedDevicePK()` (libNgxUi.so 0x212428) is
only:

    QFile f(basePath + "edpk");            // basePath = "/proc/device-tree/hde/"
    if (!f.open(ReadOnly)) log(...);
    return f.readAll().trimmed();          // raw bytes, no crypto

The decryption lives in NgxUiApp:

    recoverEcPrivateKey(string_view b64)              NgxUiApp 0x1853c
        decoded = base64Decode(b64)                   // standard alphabet
        plain   = decryptPK(decoded)                  // AES-256-ECB, PKCS#7
        blob    = 68-byte template (0x26910)          // 01 00 ... 00
        blob    = plain[0:68]
        len     = blob[1]                             // scalar length
        d       = BN_bin2bn(blob + 2, len)            // big-endian scalar
        return recreateEcPrivateKey(d)                // secp521r1 (NID 730)

    compactifyEcPrivateKey(EC_KEY*)                   NgxUiApp 0x18128
        blob      = template copy
        blob[1]   = ceil(BN_num_bits(d)/8)
        BN_bn2bin(d, blob + 2)
        return base64Encode(encryptPK(blob, 68))

`encryptPK` / `decryptPK` use `EVP_aes_256_ecb()` with a **hard-coded 32-byte
key at NgxUiApp file offset 0x268A0**:

    bd a3 8d fa a1 30 d7 0b a1 18 7f 3a 0f 9f 78 af
    78 e0 fd 9f 87 30 66 41 b6 e5 e9 f3 80 e2 09 9e

So a device key can be minted offline: pick a scalar, build the 68-byte blob,
AES-256-ECB encrypt, base64.  The scalar is interpreted on the P-521 curve
(`OBJ_txt2nid("secp521r1")` at NgxUiApp 0x27440/0x275f0), so a 1..66-byte
scalar is valid; the key that
`SslConfigurationManager::publicKeyForPrivate()` (EVP_PKEY_set1_EC_KEY) and
`QSslKey` accept, which is what removes the HSG crash.

USAGE
    make_edpk.py --out /tmp/stubs/hde
    make_edpk.py --out /tmp/stubs/hde --scalar 000102...1f
    make_edpk.py --verify /tmp/stubs/hde/edpk
    make_edpk.py --selftest
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys

AES_KEY = bytes.fromhex(
    "bda38dfaa130d70ba1187f3a0f9f78af"
    "78e0fd9f87306641b6e5e9f380e2099e"
)
TEMPLATE = b"\x01" + b"\x00" * 67          # NgxUiApp 0x26910, 68 bytes
BLOB_LEN = 68
CURVE = "secp521r1"                        # NID_secp521r1 == 730
SCALAR_MAX = 66                            # P-521 order is 521 bits


def log(msg: str) -> None:
    print(f"edpk: {msg}", flush=True)


# --- crypto backend ----------------------------------------------------------

def _openssl_ecb(data: bytes, decrypt: bool) -> bytes:
    cmd = ["openssl", "enc", "-aes-256-ecb", "-K", AES_KEY.hex(), "-nosalt", "-nopad"]
    if decrypt:
        cmd.append("-d")
    out = subprocess.run(cmd, input=data, capture_output=True, check=True)
    return out.stdout


def pkcs7_pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("not an AES block multiple")
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS#7 padding (wrong key or truncated blob)")
    return data[:-n]


def aes_ecb_encrypt(data: bytes) -> bytes:
    """Raw AES-256-ECB; `data` must already be a block multiple."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(AES_KEY), modes.ECB()).encryptor()
        return enc.update(data) + enc.finalize()
    except ImportError:
        return _openssl_ecb(data, decrypt=False)


def aes_ecb_decrypt(data: bytes) -> bytes:
    """Raw AES-256-ECB; `data` must already be a block multiple."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(AES_KEY), modes.ECB()).decryptor()
        return dec.update(data) + dec.finalize()
    except ImportError:
        return _openssl_ecb(data, decrypt=True)


# --- key blobs ---------------------------------------------------------------

def build_blob(scalar: bytes) -> bytes:
    if not 1 <= len(scalar) <= SCALAR_MAX:
        raise ValueError(f"scalar must be 1..{SCALAR_MAX} bytes")
    blob = bytearray(TEMPLATE)
    blob[1] = len(scalar)
    blob[2:2 + len(scalar)] = scalar
    return bytes(blob)


def parse_blob(blob: bytes) -> bytes:
    if len(blob) != BLOB_LEN:
        raise ValueError(f"plaintext is {len(blob)} bytes, expected {BLOB_LEN}")
    if blob[0] != 0x01:
        raise ValueError(f"unknown edpk version 0x{blob[0]:02x}")
    n = blob[1]
    if not 1 <= n <= SCALAR_MAX:
        raise ValueError(f"bad scalar length {n}")
    return blob[2:2 + n]


def edpk_from_scalar(scalar: bytes) -> str:
    return base64.b64encode(aes_ecb_encrypt(pkcs7_pad(build_blob(scalar)))).decode()


def scalar_from_edpk(text: str) -> bytes:
    raw = base64.b64decode(text.strip(), validate=False)
    if len(raw) % 16:
        raise ValueError(f"ciphertext is {len(raw)} bytes, not an AES block multiple")
    return parse_blob(pkcs7_unpad(aes_ecb_decrypt(raw)))


def public_key_hex(scalar: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    d = int.from_bytes(scalar, "big")
    priv = ec.derive_private_key(d, ec.SECP521R1())
    nums = priv.public_key().public_numbers()
    return "04" + f"{nums.x:0132x}" + f"{nums.y:0132x}"


# --- commands ----------------------------------------------------------------

def cmd_generate(out_dir: str, scalar: bytes | None) -> int:
    if scalar is None:
        # 66 random bytes (P-521); retry the (astronomically rare) out-of-range case.
        while True:
            scalar = secrets.token_bytes(SCALAR_MAX)
            try:
                public_key_hex(scalar)
                break
            except ValueError:
                continue

    blob = build_blob(scalar)
    cipher = aes_ecb_encrypt(pkcs7_pad(blob))
    text = base64.b64encode(cipher).decode()

    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "edpk")
    with open(path, "w", encoding="ascii", newline="\n") as fh:
        fh.write(text)                      # no trailing newline
    info = {
        "format": "HSG-EDPK-v1",
        "curve": CURVE,
        "blob_len": BLOB_LEN,
        "scalar_hex": scalar.hex(),
        "public_key_hex": public_key_hex(scalar),
        "edpk_len": len(text),
        "edpk_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "aes_key_offset": "0x268a0",
    }
    with open(os.path.join(out_dir, "edpk.info.json"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=2)
        fh.write("\n")

    log(f"wrote {path} ({len(text)} base64 chars, {len(cipher)} ciphertext bytes)")
    log(f"scalar     {scalar.hex()}")
    log(f"public key {info['public_key_hex']}")
    return 0


def cmd_verify(path: str) -> int:
    text = open(path, encoding="ascii").read()
    scalar = scalar_from_edpk(text)
    log(f"ok: {path} -> {len(scalar)}-byte scalar {scalar.hex()}")
    log(f"public key {public_key_hex(scalar)}")
    return 0


def cmd_selftest() -> int:
    scalar = bytes(range(1, 33))
    text = edpk_from_scalar(scalar)
    back = scalar_from_edpk(text)
    assert back == scalar, (back.hex(), scalar.hex())
    assert len(base64.b64decode(text)) == 80, len(base64.b64decode(text))
    # the very first byte of the template must survive
    blob = pkcs7_unpad(aes_ecb_decrypt(base64.b64decode(text)))
    assert blob[0] == 0x01 and blob[1] == 32 and blob[34:] == b"\x00" * 34
    log("selftest: OK (build -> AES-256-ECB/PKCS7 -> base64 -> decrypt -> scalar)")
    log(f"example edpk: {text}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="/tmp/stubs/hde")
    p.add_argument("--scalar", help="hex scalar, 1..66 bytes (deterministic key)")
    p.add_argument("--verify", metavar="FILE")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()

    if args.selftest:
        return cmd_selftest()
    if args.verify:
        return cmd_verify(args.verify)
    scalar = bytes.fromhex(args.scalar) if args.scalar else None
    return cmd_generate(args.out, scalar)


if __name__ == "__main__":
    raise SystemExit(main())
