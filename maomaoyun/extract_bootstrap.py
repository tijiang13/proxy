#!/usr/bin/env python3
"""
extract_bootstrap.py — recover the maomao app's hidden bootstrap URL(s).

Background (what the app does):
  1. RetrofitHelper holds StringFog-XOR'd byte arrays -> base64 ciphertext tokens.
  2. com.mt.Core.queryConfiguration() (native, libcore.so) base64-decodes a token
     and 3DES-EDE3-CBC *decrypts* it with a constant key/IV built from the literal
     "KEY" at the top of the function. The recovered seed is b"NIMAMAIB":
         key = b"NIMAMAIB" + b"\\x00"*16   (24-byte 3DES key, k2=k3=0)
         iv  = b"NIMAMAIB"
  3. The plaintext is an Alibaba OSS URL (android.txt) listing the live, rotating
     API domains. The app fetches it, speed-tests the domains, and uses the fastest.

This script reproduces step 2 offline: give it base64 token(s) and it prints the
decrypted bootstrap URL(s). The seed itself was recovered by emulating libcore.so
(see emulate_seed.py); re-run that if a future apk changes it.

Requires: cryptography  (pip install cryptography)
Usage:
  python extract_bootstrap.py <base64-token> [<base64-token> ...]
  python extract_bootstrap.py            # decrypts the known v2.3.1 controlFirst token
"""
import sys, base64
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

SEED = b"NIMAMAIB"                 # recovered from libcore.so via emulate_seed.py
KEY  = SEED + b"\x00" * 16         # 24-byte 3DES key (k1=seed, k2=k3=0)
IV   = SEED                        # 8-byte CBC IV

# Known token embedded in maomao 2.3.1 (controlFirst), for reference/testing.
KNOWN = "FC2DA1LM7hZqVUElEvU1uLIJAQdb7Gx5UFhx2QgKrITv72Guwa8cqEvE/zZ0h991rUzjUcO1jSkcnPcpcWSMmg=="

def decrypt_token(b64_token: str) -> str:
    ct = base64.b64decode(b64_token)
    dec = Cipher(TripleDES(KEY), modes.CBC(IV)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]                    # strip PKCS#7
    if 1 <= pad <= 8:
        pt = pt[:-pad]
    return pt.decode("utf-8", "replace")

if __name__ == "__main__":
    tokens = sys.argv[1:] or [KNOWN]
    for t in tokens:
        print(decrypt_token(t))
