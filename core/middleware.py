import json
from typing import Any

from django.http import HttpResponseBadRequest, JsonResponse, QueryDict

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
