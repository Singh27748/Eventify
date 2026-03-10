"""
Transport Crypto - Data encryption aur decryption ke liye use hota hai.
Mobile app se server ko data bhejne ke time encryption use hota hai taaki data secure rahe.
AES-GCM encryption algorithm use kiya gaya hai.
"""

import base64
import binascii
import hashlib
import json
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Encryption settings - AES-GCM ke liye constants
TRANSPORT_AAD = b"eventify-panel-v1"  # Additional authenticated data
TRANSPORT_KEY_PREFIX = "eventify:"  # Key derive karne ke liye prefix
IV_LENGTH = 12  # Initialization vector ki length
TAG_LENGTH = 16  # Authentication tag ki length


class PanelPayloadError(ValueError):
    """Raised when encrypted panel payload is invalid."""


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}")


def _derive_key(csrf_token: str) -> bytes:
    token = (csrf_token or "").strip()
    if not token:
        raise PanelPayloadError("Missing CSRF token for encrypted payload.")

    material = f"{TRANSPORT_KEY_PREFIX}{token}".encode("utf-8")
    return hashlib.sha256(material).digest()


def _serialize_payload(payload: dict[str, Any]) -> bytes:
    try:
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PanelPayloadError("Encrypted payload data must be JSON serializable.") from exc


def encrypt_panel_payload(payload: dict[str, Any], csrf_token: str) -> str:
    iv = secrets.token_bytes(IV_LENGTH)
    key = _derive_key(csrf_token)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(iv, _serialize_payload(payload), TRANSPORT_AAD)
    return _base64url_encode(iv + ciphertext)


def decrypt_panel_payload(token: str, csrf_token: str) -> dict[str, Any]:
    encrypted = (token or "").strip()
    if not encrypted:
        raise PanelPayloadError("Encrypted payload is missing.")

    try:
        raw = _base64url_decode(encrypted)
    except (binascii.Error, ValueError) as exc:
        raise PanelPayloadError("Encrypted payload is not valid base64.") from exc

    if len(raw) < IV_LENGTH + TAG_LENGTH:
        raise PanelPayloadError("Encrypted payload is too short.")

    iv = raw[:IV_LENGTH]
    ciphertext = raw[IV_LENGTH:]
    cipher = AESGCM(_derive_key(csrf_token))

    try:
        plaintext = cipher.decrypt(iv, ciphertext, TRANSPORT_AAD)
    except InvalidTag as exc:
        # Backward compatibility for clients that encrypted without AAD.
        try:
            plaintext = cipher.decrypt(iv, ciphertext, b"")
        except InvalidTag as legacy_exc:
            raise PanelPayloadError("Encrypted payload failed authentication.") from legacy_exc

    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PanelPayloadError("Encrypted payload is not valid JSON.") from exc

    if not isinstance(data, dict):
        raise PanelPayloadError("Decrypted payload must be a JSON object.")

    return data
