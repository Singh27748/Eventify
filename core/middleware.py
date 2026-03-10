"""
Middleware - Request aur response ke beech ka code jo har request ke saath chalega.
Yahan hum encrypted data handle karte hain mobile app ke liye.
"""

import json
from datetime import datetime
from typing import Any

from django.contrib import messages
from django.contrib.auth import logout
from django.http import HttpResponseBadRequest, JsonResponse, QueryDict
from django.shortcuts import redirect
from django.utils import timezone

from .security_controls import (
    get_session_timeout_seconds,
    initialize_secure_session,
    record_audit_log,
)
from .transport_crypto import PanelPayloadError, decrypt_panel_payload, encrypt_panel_payload


class PanelTransportEncryptionMiddleware:
    """
    Decrypts encrypted POST form payloads and optionally encrypts JSON responses.

    Request:
    - Send encrypted form fields in "__enc_payload".
    - Keep "csrfmiddlewaretoken" as plain text.

    Response:
    - Send header "X-Panel-Encryption: 1" to request encrypted JSON response.
    """

    encrypted_field_name = "__enc_payload"
    encryption_request_header = "HTTP_X_PANEL_ENCRYPTION"
    encrypted_response_header = "X-Panel-Encrypted"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        error_response = self._maybe_decrypt_request_payload(request)
        if error_response is not None:
            return error_response

        response = self.get_response(request)
        return self._maybe_encrypt_json_response(request, response)

    def _maybe_decrypt_request_payload(self, request):
        if request.method != "POST":
            return None

        encrypted_payload = request.POST.get(self.encrypted_field_name)
        if not encrypted_payload:
            return None

        csrf_token = self._resolve_csrf_token(request)
        if not csrf_token:
            return HttpResponseBadRequest("Missing CSRF token for encrypted request.")

        try:
            decrypted_payload = decrypt_panel_payload(encrypted_payload, csrf_token)
        except PanelPayloadError:
            return HttpResponseBadRequest("Invalid encrypted request payload.")

        merged = request.POST.copy()
        merged.pop(self.encrypted_field_name, None)
        self._merge_payload_into_querydict(merged, decrypted_payload)
        request._post = merged
        return None

    def _maybe_encrypt_json_response(self, request, response):
        if request.META.get(self.encryption_request_header) != "1":
            return response

        if response.status_code == 304:
            return response

        content_type = response.get("Content-Type", "")
        if "application/json" not in content_type:
            return response

        csrf_token = self._resolve_csrf_token(request)
        if not csrf_token:
            return response

        try:
            payload = json.loads(response.content.decode(response.charset or "utf-8"))
            encrypted_payload = encrypt_panel_payload(payload, csrf_token)
        except (UnicodeDecodeError, json.JSONDecodeError, PanelPayloadError):
            return response

        data = {"payload": encrypted_payload}
        encrypted_response = JsonResponse(data, status=response.status_code, safe=True)

        for header, value in response.items():
            if header.lower() in {"content-type", "content-length"}:
                continue
            encrypted_response[header] = value

        encrypted_response[self.encrypted_response_header] = "1"
        return encrypted_response

    @staticmethod
    def _resolve_csrf_token(request) -> str:
        csrf_from_post = ""
        if request.method == "POST":
            csrf_from_post = request.POST.get("csrfmiddlewaretoken", "")

        return (
            csrf_from_post
            or request.META.get("HTTP_X_CSRFTOKEN")
            or request.COOKIES.get("csrftoken")
            or ""
        )

    @staticmethod
    def _normalize_value(value: Any) -> str:
        if value is None:
            return ""
        return str(value)

    def _merge_payload_into_querydict(self, querydict: QueryDict, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            if isinstance(value, list):
                querydict.setlist(key, [self._normalize_value(item) for item in value])
                continue
            querydict[key] = self._normalize_value(value)


class SecurityHeadersMiddleware:
    """Adds defensive response headers to every response."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("X-XSS-Protection", "1; mode=block")
        response.setdefault("Referrer-Policy", "same-origin")
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        return response


class SessionSecurityMiddleware:
    """Logs users out after a period of inactivity."""

    session_key = "last_activity_at"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        timeout_response = self._maybe_expire_session(request)
        if timeout_response is not None:
            return timeout_response
        response = self.get_response(request)
        self._refresh_activity_window(request)
        return response

    def _maybe_expire_session(self, request):
        if not getattr(request, "user", None) or not request.user.is_authenticated:
            return None

        timeout_seconds = get_session_timeout_seconds()
        if timeout_seconds <= 0:
            return None

        last_activity_raw = request.session.get(self.session_key)
        if not last_activity_raw:
            initialize_secure_session(request)
            return None

        try:
            last_activity = datetime.fromisoformat(last_activity_raw)
        except ValueError:
            initialize_secure_session(request)
            return None

        if timezone.is_naive(last_activity):
            last_activity = timezone.make_aware(last_activity, timezone.get_current_timezone())

        now = timezone.now()
        if (now - last_activity).total_seconds() <= timeout_seconds:
            return None

        expired_user = request.user
        record_audit_log(
            action="session_timeout",
            summary="Session expired after inactivity timeout.",
            category="auth",
            status="info",
            request=request,
            user=expired_user,
        )
        logout(request)
        if request.path.startswith("/api/"):
            return JsonResponse(
                {"ok": False, "error": "Session expired after inactivity. Please log in again."},
                status=401,
            )
        timeout_minutes = max(1, int(round(timeout_seconds / 60)))
        messages.warning(
            request,
            f"Session expired after {timeout_minutes} minute(s) of inactivity. Please sign in again.",
        )
        return redirect("auth_page")

    def _refresh_activity_window(self, request):
        if not getattr(request, "user", None) or not request.user.is_authenticated:
            return
        initialize_secure_session(request)
