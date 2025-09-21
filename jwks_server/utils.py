# jwks_server/utils.py
"""
Small helpers.
"""

import base64


def base64url_encode_int(value: int) -> str:
    """
    Encode a big integer (like RSA n or e) as base64url without padding (RFC7517 style).
    """
    # convert integer to big-endian bytes
    length = (value.bit_length() + 7) // 8
    b = value.to_bytes(length, "big") if length > 0 else b'\x00'
    s = base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    return s
