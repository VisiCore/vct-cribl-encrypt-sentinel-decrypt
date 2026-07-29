"""
Cribl C.Crypto field decryption — pure-Python, dependency: `cryptography`.

This reproduces what Cribl's Splunk `| cribldecrypt` command does at search time:
given a value encrypted by Cribl's `C.Crypto.encrypt()` and the matching key
material, return the plaintext.

Spec (from Cribl docs + the third-party-decrypt knowledge-base article):
  - Algorithm: AES-256-CBC (default) or AES-256-GCM.
  - Key: 32 bytes, supplied as 64 hex chars. Shown ONCE in the Cribl UI at
    key creation (Group Settings -> Security -> Encryption Keys), or exported
    via the "Get Key Bundle" download (keys.json) on the Leader.
  - Token wire format (VERIFIED June 2026 against live `C.Crypto.encrypt()` output
    on a Cribl worker — note the namespace is `C.Crypto`, not `C.Crypt`):
        #<keyId>:<iv_b64>:<ciphertext_b64>#
    The surrounding '#' are field markers Cribl uses to locate encrypted
    substrings within a larger string. The middle field is the IV:
      * EMPTY when the key has useIV=false  -> decrypt with a 16-byte zero IV.
      * base64 of a random 16-byte IV when useIV=true.
    There is NO keyclass and NO HMAC in the token. The keyId selects the key.

NOTE: `decrypt_value` accepts either a full `#keyId:iv:ct#` token or a bare
base64 ciphertext (e.g. Cribl's KB example) and auto-detects. The per-token IV
field is authoritative — the key's use_iv flag is informational only.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ZERO_IV = b"\x00" * 16


@dataclass(frozen=True)
class CriblKey:
    """One entry from a Cribl key bundle.

    keyId is an alphanumeric string (e.g. "smSLT3"), confirmed against the live
    Cribl `system/keys` API — NOT an integer.
    """

    key_id: str
    key_bytes: bytes  # 32 bytes for AES-256
    algorithm: str = "aes-256-cbc"  # or "aes-256-gcm"
    use_iv: bool = False
    key_class: int = 0

    @classmethod
    def from_hex(cls, key_id: str, key_hex: str, **kw) -> "CriblKey":
        kb = bytes.fromhex(key_hex.strip())
        if len(kb) != 32:
            raise ValueError(f"expected 32-byte (64-hex) AES-256 key, got {len(kb)} bytes")
        return cls(key_id=key_id, key_bytes=kb, **kw)


def _b64decode_padded(s: str) -> bytes:
    """Cribl emits unpadded base64; restore '=' padding before decoding."""
    s = s.strip()
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.b64decode(s)


def _strip_pkcs7(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= 16 and data[-pad_len:] == bytes([pad_len]) * pad_len:
        return data[:-pad_len]
    return data  # not PKCS7-padded (e.g. GCM); return as-is


# Real Cribl C.Crypto token:  #<keyId>:<iv_b64>:<ciphertext_b64>#
# keyId is an alphanumeric string (e.g. "smSLT3"). The IV field is empty for
# useIV=false keys and base64 of a 16-byte IV for useIV=true keys. The wrapping
# '#' are optional in our matcher so a stripped/embedded token still parses.
_TOKEN_RE = re.compile(
    r"^#?(?P<keyid>[A-Za-z0-9]+):(?P<iv>[A-Za-z0-9+/=]*):(?P<ct>[A-Za-z0-9+/=]+)#?$"
)


@dataclass
class ParsedToken:
    key_id: str | None
    iv_b64: str | None  # None/empty -> zero IV (useIV=false); else base64 of the IV
    ciphertext_b64: str


def parse_token(value: str) -> ParsedToken:
    """Split a full Cribl token, or treat the input as a bare base64 ciphertext."""
    m = _TOKEN_RE.match(value.strip())
    if m:
        return ParsedToken(
            key_id=m.group("keyid"),
            iv_b64=m.group("iv") or None,
            ciphertext_b64=m.group("ct"),
        )
    return ParsedToken(key_id=None, iv_b64=None, ciphertext_b64=value.strip())


def decrypt_value(value: str, key: CriblKey, iv: bytes | None = None) -> str:
    """
    Decrypt a single Cribl-encrypted value.

    `value` may be a full token (`#keyId:iv:ct#`) or a bare base64 ciphertext.
    `iv` overrides the token's IV field; otherwise the IV comes from the token's
    middle field (empty -> 16-byte zero IV, as Cribl uses for useIV=false keys).
    """
    parsed = parse_token(value)
    ct = _b64decode_padded(parsed.ciphertext_b64)

    if iv is None:
        iv = _b64decode_padded(parsed.iv_b64) if parsed.iv_b64 else ZERO_IV

    algo = key.algorithm.lower()
    if algo == "aes-256-cbc":
        cipher = Cipher(algorithms.AES(key.key_bytes), modes.CBC(iv))
        dec = cipher.decryptor()
        plaintext = dec.update(ct) + dec.finalize()
        return _strip_pkcs7(plaintext).decode("utf-8")
    if algo == "aes-256-gcm":
        # GCM: last 16 bytes are the auth tag.
        ct_body, tag = ct[:-16], ct[-16:]
        cipher = Cipher(algorithms.AES(key.key_bytes), modes.GCM(iv, tag))
        dec = cipher.decryptor()
        return (dec.update(ct_body) + dec.finalize()).decode("utf-8")
    raise ValueError(f"unsupported algorithm: {key.algorithm}")
