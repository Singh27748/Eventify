"""
Security helpers for TOTP-based 2FA.
"""

from __future__ import annotations

import base64
import hmac
import os
import secrets
import struct
import time
from hashlib import sha1
from io import BytesIO
from urllib.parse import quote

import qrcode


TOTP_DIGITS = 6
TOTP_STEP_SECONDS = 30


def generate_totp_secret(length: int = 20) -> str:
    raw_secret = os.urandom(max(10, int(length or 20)))
    encoded = base64.b32encode(raw_secret).decode("ascii").rstrip("=")
    return encoded


def generate_backup_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(4).upper() for _ in range(max(1, int(count or 10)))]


def build_totp_uri(secret: str, account_name: str, issuer: str = "Eventify") -> str:
    account_label = quote(f"{issuer}:{account_name}")
    issuer_value = quote(issuer)
    return (
        f"otpauth://totp/{account_label}"
        f"?secret={secret}&issuer={issuer_value}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"
    )


def build_qr_code_data_uri(value: str) -> str:
    image = qrcode.make(value)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _normalize_secret(secret: str) -> str:
    normalized = "".join((secret or "").split()).upper()
    if not normalized:
        raise ValueError("Missing TOTP secret.")
    padding = "=" * ((8 - (len(normalized) % 8)) % 8)
    return normalized + padding


def _generate_totp_at(secret: str, for_timestamp: int) -> str:
    key = base64.b32decode(_normalize_secret(secret), casefold=True)
    counter = int(for_timestamp // TOTP_STEP_SECONDS)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    otp = binary % (10**TOTP_DIGITS)
    return f"{otp:0{TOTP_DIGITS}d}"


def generate_totp_code(secret: str, for_timestamp: int | None = None) -> str:
    current_time = int(for_timestamp if for_timestamp is not None else time.time())
    return _generate_totp_at(secret, current_time)


def verify_totp_code(secret: str, code: str, window: int = 1, at_time: int | None = None) -> bool:
    normalized_code = "".join((code or "").split())
    if not normalized_code.isdigit() or len(normalized_code) != TOTP_DIGITS:
        return False

    current_time = int(at_time if at_time is not None else time.time())
    for offset in range(-abs(int(window or 0)), abs(int(window or 0)) + 1):
        candidate = _generate_totp_at(secret, current_time + (offset * TOTP_STEP_SECONDS))
        if secrets.compare_digest(candidate, normalized_code):
            return True
    return False
