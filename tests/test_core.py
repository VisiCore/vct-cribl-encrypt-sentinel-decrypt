"""Core decrypt tests.

Includes the canonical example from Cribl's KB article AND real tokens captured
from live `C.Crypto.encrypt()` output on a Cribl worker (June 2026), covering both
the useIV=false (zero IV) and useIV=true (embedded IV) paths. The plaintext for the
live samples is "sentinel-poc-known-001".
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cribl_decrypt.core import CriblKey, decrypt_value, parse_token  # noqa: E402

LIVE_PLAINTEXT = "sentinel-poc-known-001"


def test_cribl_kb_example():
    """Verbatim example from Cribl's "Decrypting Data with Third-Party Tools" KB.

    Proves the AES-256-CBC + zero-IV + unpadded-base64 path matches Cribl, using a
    bare ciphertext (no #keyId:iv:ct# wrapper).
    """
    key = CriblKey.from_hex(
        key_id="1",
        key_hex="0a31961cfbb20966bc2931b38788a07a86a845b6fb4f2c2398d54b9c2618a43f",
        use_iv=False,
    )
    plaintext = decrypt_value("VPuxLjf4ByJgja2GLwsXXQ", key)
    assert plaintext  # non-empty, valid UTF-8


def test_live_token_useiv_false():
    """Real C.Crypto.encrypt() output, key TWPLRh (useIV=false). IV field is empty."""
    key = CriblKey.from_hex(
        key_id="TWPLRh",
        key_hex="b0475eed11028b5043c87a587e6d7bd8045bc90b96c87863d7f8d3279e1d5d69",
        use_iv=False,
    )
    token = "#TWPLRh::2B0RXsyqPFimLaEjyjZx8ga/XOpXn+HIDVnbKOigKwg#"
    assert decrypt_value(token, key) == LIVE_PLAINTEXT


def test_live_token_useiv_true():
    """Real C.Crypto.encrypt() output, key tqVVX3 (useIV=true). IV is in the token's
    middle field and differs per call — both samples must decrypt identically."""
    key = CriblKey.from_hex(
        key_id="tqVVX3",
        key_hex="812c04bb9316a11212a8a8c2496be9fbe51e2e8608ce70c2e7668ab0a1414001",
        use_iv=True,
    )
    sample_a = "#tqVVX3:lp21TwfoZOew4X+QQ/6Lbw:Q6E40/+W1SqKZv7PiALmNXXrZROzqi/jaTYwCD5/HA8#"
    sample_b = "#tqVVX3:hcM2KFjXIHegiAI1prAVUA:rduR0gW/LZUG99V93GUv1EkVbFwrBW/gVbze2rNzki0#"
    assert decrypt_value(sample_a, key) == LIVE_PLAINTEXT
    assert decrypt_value(sample_b, key) == LIVE_PLAINTEXT


def test_token_parse_format():
    """Parser splits the real #keyId:iv:ct# format and falls back to bare ciphertext."""
    bare = parse_token("VPuxLjf4ByJgja2GLwsXXQ")
    assert bare.key_id is None and bare.iv_b64 is None

    no_iv = parse_token("#TWPLRh::2B0RXsyqPFimLaEjyjZx8ga/XOpXn+HIDVnbKOigKwg#")
    assert no_iv.key_id == "TWPLRh" and no_iv.iv_b64 is None
    assert no_iv.ciphertext_b64 == "2B0RXsyqPFimLaEjyjZx8ga/XOpXn+HIDVnbKOigKwg"

    with_iv = parse_token("#tqVVX3:lp21TwfoZOew4X+QQ/6Lbw:Q6E40/+W1SqKZv7PiALmNXXrZROzqi/jaTYwCD5/HA8#")
    assert with_iv.key_id == "tqVVX3" and with_iv.iv_b64 == "lp21TwfoZOew4X+QQ/6Lbw"


if __name__ == "__main__":
    test_cribl_kb_example()
    test_live_token_useiv_false()
    test_live_token_useiv_true()
    test_token_parse_format()
    print("OK — KB example + live useIV=false + live useIV=true + parser all pass")
