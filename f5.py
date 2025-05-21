#!/usr/bin/env python3
# example keys
# F5 Master decryption key: Zh1XXgA6MzxdTC1bOJEgSg==
# Service Password of 'Password': $M$qD$B+Sk64kVHBE5tQ0XnkkWhA==
"""
MIT License

Copyright (c) 2025 International Business Machines Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

================================================================================
F5 Encrypted Password Decryption Overview
================================================================================

Encrypted passwords on F5 systems follow this format:

    $M$<salt>$<base64>

Where:
    - "$M$" is a fixed identifier for encrypted strings
    - "<salt>" is a 2-character salt (e.g., qD)
    - "<base64>" is the AES-ECB-encrypted password, base64-encoded

Decryption requires the F5 master key retrieved using:
    f5mku -K

The process works like this:

             ┌──────────────────────────────────────────────────────┐
             │ Encrypted Password:                                  │
             │   $M$qD$B+Sk64kVHBE5tQ0XnkkWhA==                      │
             └──────────────────────────────────────────────────────┘
                          │
                          ▼
             ┌──────────────────────────────┐
             │ Parse Salt Prefix: "qD"      │  ← characters after "$M$"
             └──────────────────────────────┘
                          │
                          ▼
             ┌─────────────────────────────────────────────────────────────┐
             │ Base64 Decode Ciphertext:                                   │
             │   base64("B+Sk64kVHBE5tQ0XnkkWhA==")                         │
             │ → raw_cipher_bytes (binary AES-encrypted data)              │
             └─────────────────────────────────────────────────────────────┘
                          │
                          ▼
             ┌─────────────────────────────────────────────────────────────┐
             │ Get AES Key:                                                │
             │   Run `f5mku -K` on the F5 box                               │
             │   Example Output: Zh1XXgA6MzxdTC1bOJEgSg== (base64)          │
             │   Decode this → master_key_bytes                            │
             └─────────────────────────────────────────────────────────────┘
                          │
                          ▼
             ┌─────────────────────────────────────────────────────────────┐
             │ Decrypt:                                                    │
             │   AES_ECB_Decrypt(raw_cipher_bytes, master_key_bytes)       │
             │ → raw_plaintext: e.g., "qDPassword"                         │
             └─────────────────────────────────────────────────────────────┘
                          │
                          ▼
             ┌──────────────────────────────┐
             │ Strip Salt Prefix: "qD"      │
             │ Remaining string: "Password" │
             └──────────────────────────────┘
                          │
                          ▼
             ┌──────────────────────────────┐
             │ Final Output: "Password"     │
             └──────────────────────────────┘

Important Notes:
----------------
- The AES mode is ECB (used by F5 for service account secrets).
- The 2-character salt (after $M$) is prepended to the plaintext before encryption.
- This script strips it back out after decrypting.
"""


import base64
from Crypto.Cipher import AES

def get_master_key():
    print("[*] Please run this command on your F5 device and paste the result below:\n")
    print("    f5mku -K\n")
    master_key_b64 = input("[?] Paste base64 master key: ").strip()
    try:
        return base64.b64decode(master_key_b64)
    except Exception as e:
        print(f"[!] Invalid base64 input for master key: {e}")
        exit(1)

def decrypt_password(master_key, encrypted_password):
    if not encrypted_password.startswith("$M$"):
        print("[!] Encrypted password must start with '$M$'")
        exit(1)

    try:
        # Encrypted portion begins after the $M$xx$ prefix
        prefix = encrypted_password[3:6]  # "$M$xx$" → "xx"
        b64_data = encrypted_password[6:]
        ciphertext = base64.b64decode(b64_data)

        # Decrypt using AES ECB
        cipher = AES.new(master_key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext).decode("utf-8", errors="ignore")

        # Remove salt prefix (xx from $M$xx$)
        salt = encrypted_password[3:5]
        if plaintext.startswith(salt):
            plaintext = plaintext[len(salt):]

        return plaintext.strip()
    except Exception as e:
        print(f"[!] Error decrypting password: {e}")
        exit(1)

def main():
    print("=== F5 Encrypted Password Decrypter ===")
    master_key = get_master_key()
    enc_pass = input("[?] Enter encrypted password (starting with $M$): ").strip()
    decrypted = decrypt_password(master_key, enc_pass)
    print(f"[+] Decrypted Password: {decrypted}")

if __name__ == '__main__':
    main()

