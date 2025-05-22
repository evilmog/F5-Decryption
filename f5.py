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
             │ Parse Salt Prefix: "qD"      │
             └──────────────────────────────┘
                          │
                          ▼
             ┌─────────────────────────────────────────────────────────────┐
             │ Base64 Decode Ciphertext                                    │
             │   → raw_cipher_bytes (binary AES-encrypted data)           │
             └─────────────────────────────────────────────────────────────┘
                          │
                          ▼
             ┌─────────────────────────────────────────────────────────────┐
             │ Get AES Key from `f5mku -K` output (base64 decoded)         │
             └─────────────────────────────────────────────────────────────┘
                          │
                          ▼
             ┌─────────────────────────────────────────────────────────────┐
             │ Decrypt using AES-ECB                                       │
             │   → "qDPassword"                                            │
             └─────────────────────────────────────────────────────────────┘
                          │
                          ▼
             ┌──────────────────────────────┐
             │ Remove Salt Prefix "qD"      │
             └──────────────────────────────┘
                          │
                          ▼
             ┌──────────────────────────────┐
             │ Final Output: "Password"     │
             └──────────────────────────────┘
"""

import os
import base64
import argparse
from Crypto.Cipher import AES

def get_master_key(master_key_b64=None):
    """
    Gets and decodes the base64-encoded F5 master key.

    Priority order:
      1. Argument passed to function
      2. Environment variable F5_MASTER_KEY
      3. User prompt (interactive)

    Args:
        master_key_b64 (str, optional): base64 string from f5mku -K

    Returns:
        bytes: decoded master key

    Raises:
        ValueError: if decoding fails or input is missing
    """
    # Step 1: Check env var if argument isn't passed
    if not master_key_b64:
        master_key_b64 = os.getenv("F5_MASTER_KEY")

    # Step 2: If key is available, attempt to decode
    if master_key_b64:
        try:
            return base64.b64decode(master_key_b64.strip())
        except Exception as e:
            raise ValueError(f"Invalid master key (from input or F5_MASTER_KEY): {e}")

    # Step 3: Prompt user if nothing is provided
    print("[*] Please run this command on your F5 device and paste the result below:\n")
    print("    f5mku -K\n")
    master_key_b64 = input("[?] Paste base64 master key: ").strip()

    try:
        return base64.b64decode(master_key_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 input for master key: {e}")

def decrypt_password(master_key, encrypted_password=None):
    """
    Decrypts an F5-encrypted password using AES ECB and salt stripping.

    Priority order for password:
      1. Argument passed to function
      2. Environment variable F5_PASSWORD

    Args:
        master_key (bytes): AES decryption key
        encrypted_password (str, optional): Encrypted string ($M$xx$...)

    Returns:
        str: Decrypted plaintext password

    Raises:
        ValueError: if format is invalid or decryption fails
    """
    # Step 1: Check env var if no password provided
    if not encrypted_password:
        encrypted_password = os.getenv("F5_PASSWORD")

    if not encrypted_password:
        raise ValueError("No encrypted password provided and F5_PASSWORD is not set.")

    if not encrypted_password.startswith("$M$"):
        raise ValueError("Encrypted password must start with '$M$'")

    try:
        # Extract salt (xx) and base64 portion from $M$xx$<base64>
        salt = encrypted_password[3:5]
        b64_data = encrypted_password[6:]

        # Decode base64 to ciphertext bytes
        ciphertext = base64.b64decode(b64_data)

        # Initialize AES cipher with master key in ECB mode
        cipher = AES.new(master_key, AES.MODE_ECB)

        # Decrypt and decode to string
        plaintext = cipher.decrypt(ciphertext).decode("utf-8", errors="ignore")

        # Strip the salt prefix from plaintext
        if plaintext.startswith(salt):
            plaintext = plaintext[len(salt):]

        return plaintext.strip()

    except Exception as e:
        raise ValueError(f"Failed to decrypt password: {e}")

def main():
    """
    Command-line interface for the F5 decryption tool.
    Accepts --password and --master-key as optional arguments.
    Falls back to environment variables or user prompts.
    """
    parser = argparse.ArgumentParser(description="F5 Encrypted Password Decrypter")
    parser.add_argument("--password", help="Encrypted password string (e.g. $M$xx$...)")
    parser.add_argument("--master-key", help="Base64-encoded F5 master key (output of f5mku -K)")
    args = parser.parse_args()

    print("=== F5 Encrypted Password Decrypter ===")
    try:
        # Get and decode the master key
        master_key = get_master_key(args.master_key)

        # Use CLI arg or env var for password, or fall back to prompt
        encrypted_password = args.password or os.getenv("F5_PASSWORD")
        if not encrypted_password:
            encrypted_password = input("[?] Enter encrypted password (starting with $M$): ").strip()

        # Decrypt the password and display it
        decrypted = decrypt_password(master_key, encrypted_password)
        print(f"[+] Decrypted Password: {decrypted}")

    except ValueError as e:
        print(f"[!] Error: {e}")
        exit(1)

if __name__ == '__main__':
    main()

