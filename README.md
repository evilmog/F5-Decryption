# F5-Decryption
F5 Service Password Decryption

# Intro
I discovered this technique in 2022, and have held onto it as the request of a number of groups, now that threat actors know about it, and  I'm talking about it at BSidesLV I am officially publishing this.

# References
[Working with Master Keys - F5 TechDocs](https://techdocs.f5.com/en-us/bigip-13-1-0/big-ip-secure-vault-administration/working-with-master-keys.html)


# Details
```
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
```

# 🔐 F5 Service Account Password Decryption Tool

This tool decrypts F5 service account passwords stored in the `$M$<salt>$<base64>` format using the master decryption key retrieved from the F5 device (`f5mku -K`).

---

## 🧰 Requirements

- Python 3.6+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/)

Install with:

```bash
pip install pycryptodome
```

---

## 🛠️ Usage

### 📦 Example Keys

- **F5 Master Decryption Key**:  
  `Zh1XXgA6MzxdTC1bOJEgSg==`

- **Encrypted Password for `Password`**:  
  `$M$qD$B+Sk64kVHBE5tQ0XnkkWhA==`

---

### ▶️ Basic Command-Line Usage

You can provide the key and password directly via CLI:

```bash
python3 f5-new.py \
  --master-key 'Zh1XXgA6MzxdTC1bOJEgSg==' \
  --password '$M$qD$B+Sk64kVHBE5tQ0XnkkWhA=='
```

---

### 🌍 Environment Variable Support

You can also set values using environment variables instead of CLI args:

```bash
export F5_MASTER_KEY='Zh1XXgA6MzxdTC1bOJEgSg=='
export F5_PASSWORD='$M$qD$B+Sk64kVHBE5tQ0XnkkWhA=='

python3 f5-new.py
```

---

### 🧑‍💻 Interactive Mode

If neither CLI args nor environment variables are provided, the script will prompt you interactively for:

- The master key (base64 from `f5mku -K`)
- The encrypted password string

---

## ⚠️ Notes

- The encrypted password **must start with `$M$`**.
- Ensure the encrypted string is wrapped in **single quotes** (`'...'`) to avoid shell expansion issues (especially on macOS or Zsh).
- AES decryption is performed in **ECB mode**, as used internally by F5.
- An additional tool was added to decrypt the master key using the unit key if you want to avoid f5mku -K
---
