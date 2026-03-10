"""
External provider integrations: OAuth and Razorpay.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings


class IntegrationError(Exception):
    pass


def _read_json_response(response):
    payload = response.read().decode("utf-8")
    return json.loads(payload or "{}")


def _http_json_request(url: str, *, method: str = "GET", headers: dict | None = None, data=None):
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body = data.encode("utf-8")
        else:
            body = data

    request = Request(url, data=body, headers=request_headers, method=method.upper())
    try:
        with urlopen(request, timeout=15) as response:
            return _read_json_response(response)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise IntegrationError(detail or f"{method} {url} failed with status {exc.code}.") from exc
    except URLError as exc:
        raise IntegrationError(str(exc.reason) or f"Could not reach {url}.") from exc


@dataclass(frozen=True)
class OAuthProviderConfig:
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    scope: str

def get_google_oauth_config() -> OAuthProviderConfig:
    return OAuthProviderConfig(
        name="Google",
        client_id=(getattr(settings, "GOOGLE_OAUTH_CLIENT_ID", "") or "").strip(),
        client_secret=(getattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", "") or "").strip(),
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        scope="openid email profile",
    )


def get_github_oauth_config() -> OAuthProviderConfig:
    return OAuthProviderConfig(
        name="GitHub",
        client_id=(getattr(settings, "GITHUB_OAUTH_CLIENT_ID", "") or "").strip(),
        client_secret=(getattr(settings, "GITHUB_OAUTH_CLIENT_SECRET", "") or "").strip(),
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        scope="read:user user:email",
    )


def oauth_provider_ready(provider: OAuthProviderConfig) -> bool:
    return bool(provider.client_id and provider.client_secret)


def generate_oauth_state() -> str:
    return secrets.token_urlsafe(32)


def build_google_auth_url(redirect_uri: str, state: str) -> str:
    provider = get_google_oauth_config()
    params = {
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": provider.scope,
        "state": state,
        "access_type": "online",
        "include_granted_scopes": "true",
        "prompt": "select_account",
    }
    return f"{provider.authorize_url}?{urlencode(params)}"


def exchange_google_code(code: str, redirect_uri: str) -> dict:
    provider = get_google_oauth_config()
    return _http_json_request(
        provider.token_url,
        method="POST",
        data={
            "code": code,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
    )


def fetch_google_profile(access_token: str) -> dict:
    return _http_json_request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )


def build_github_auth_url(redirect_uri: str, state: str) -> str:
    provider = get_github_oauth_config()
    params = {
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "scope": provider.scope,
        "state": state,
        "allow_signup": "true",
    }
    return f"{provider.authorize_url}?{urlencode(params)}"


def exchange_github_code(code: str, redirect_uri: str) -> dict:
    provider = get_github_oauth_config()
    return _http_json_request(
        provider.token_url,
        method="POST",
        headers={"Accept": "application/json"},
        data={
            "code": code,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "redirect_uri": redirect_uri,
        },
    )


def fetch_github_profile(access_token: str) -> dict:
    return _http_json_request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "Eventify OAuth",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )


def fetch_github_emails(access_token: str) -> list[dict]:
    response = _http_json_request(
        "https://api.github.com/user/emails",
        headers={
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "Eventify OAuth",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    return response if isinstance(response, list) else []


def razorpay_ready() -> bool:
    return bool(getattr(settings, "RAZORPAY_KEY_ID", "") and getattr(settings, "RAZORPAY_KEY_SECRET", ""))


def _razorpay_auth_header() -> str:
    token = f"{settings.RAZORPAY_KEY_ID}:{settings.RAZORPAY_KEY_SECRET}".encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")


def create_razorpay_order(amount_rupees: int, receipt: str, notes: dict | None = None) -> dict:
    amount_value = max(0, int(amount_rupees or 0)) * 100
    if amount_value <= 0:
        raise IntegrationError("Invalid amount for Razorpay order.")

    return _http_json_request(
        "https://api.razorpay.com/v1/orders",
        method="POST",
        headers={"Authorization": _razorpay_auth_header()},
        data={
            "amount": amount_value,
            "currency": getattr(settings, "RAZORPAY_CURRENCY", "INR"),
            "receipt": receipt[:40],
            "notes": notes or {},
        },
    )


def verify_razorpay_signature(order_id: str, payment_id: str, signature: str) -> bool:
    payload = f"{order_id}|{payment_id}".encode("utf-8")
    expected_signature = hmac.new(
        getattr(settings, "RAZORPAY_KEY_SECRET", "").encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return secrets.compare_digest(expected_signature, (signature or "").strip())
