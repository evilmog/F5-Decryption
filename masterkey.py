#!/usr/bin/env python3
"""
Decrypt F5 BIG-IP master key (128-bit) using the unit key (256-bit).

Accepts either:
  • full .unitkey contents in hex (128 hex chars) OR the AES-256 key in hex (64 hex chars)
  • line from /config/bigip/kstore/master (e.g. $S$Iy$......)

Example:
    python3 f5_master_decrypt.py \
        --unit-key "$(xxd -c 32 -s 32 -p /config/bigip/kstore/.unitkey)" \
        --master "$(cat /config/bigip/kstore/master)"
"""

import argparse
import base64
import re
import sys
from binascii import unhexlify

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("pycryptodome is required: pip install pycryptodome")

# ----------------------------------------------------------------------

def normalise_unit_key(hex_blob: str) -> bytes:
    """Return 32-byte AES-256 unit key from input hex string."""
    hex_blob = re.sub(r"\s+", "", hex_blob)

    # full .unitkey file → last 64 hex chars
    if len(hex_blob) == 128:
        hex_blob = hex_blob[-64:]
    elif len(hex_blob) != 64:
        raise ValueError("Unit key must be 64 or 128 hex characters")

    try:
        return unhexlify(hex_blob)
    except Exception as exc:
        raise ValueError(f"Invalid hex for unit key: {exc}") from exc

# ----------------------------------------------------------------------

def decrypt_master_key(unit_key: bytes, master_line: str) -> bytes:
    """Decrypt master key using AES-256-ECB and return 16-byte key."""
    master_line = master_line.strip()

    parts = master_line.split("$")
    if len(parts) != 4 or parts[1] != 'S':
        raise ValueError("Encrypted master must look like: $S$<cc>$<base64>")

    ctrl, b64_blob = parts[2], parts[3]

    try:
        ciphertext = base64.b64decode(b64_blob, validate=True)
    except Exception as exc:
        raise ValueError(f"Master-key portion is not valid base64: {exc}") from exc

    cipher = AES.new(unit_key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    if len(plaintext) < 18 or plaintext[:2].decode('latin1') != ctrl:
        raise ValueError("Control bytes mismatch – wrong unit key or corrupt data")

    return plaintext[2:18]   # 16-byte AES-128 master key

# ----------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(description="Decrypt BIG-IP master key with unit key")
    p.add_argument('--unit-key', required=True,
                   help='Hex of .unitkey (xxd -p) OR 64-hex-char AES-256 key')
    p.add_argument('--master', required=True,
                   help='Line from /config/bigip/kstore/master, e.g. $S$Iy$...')
    args = p.parse_args()

    try:
        unit_key = normalise_unit_key(args.unit_key)
        master_key = decrypt_master_key(unit_key, args.master)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("✔ Decryption successful\n")
    print(f"Master key (hex) : {master_key.hex()}")
    print(f"Master key (b64) : {base64.b64encode(master_key).decode()}")
    print("\nYou can compare this with 'f5mku -K' output on the device.")

if __name__ == '__main__':
    main()
