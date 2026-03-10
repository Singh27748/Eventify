from __future__ import annotations

import hashlib
import re
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.html import strip_tags

from .models import LoginThrottle, SecurityAuditLog


CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def sanitize_text_input(value, *, max_length=None):
    text = strip_tags(str(value or ""))
    text = CONTROL_CHAR_PATTERN.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.strip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if max_length is not None:
        text = text[:max_length]
    return text


def validate_user_password(password, user=None):
    validate_password(password, user=user)


def get_client_ip(request):
    forwarded_for = (request.META.get("HTTP_X_FORWARDED_FOR") or "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return (request.META.get("REMOTE_ADDR") or "").strip() or None


def record_audit_log(
    *,
    action,
    summary,
    category=SecurityAuditLog.CATEGORY_AUTH,
    status=SecurityAuditLog.STATUS_INFO,
    request=None,
    user=None,
    actor_contact="",
    metadata=None,
):
    resolved_contact = (actor_contact or "").strip()
    if not resolved_contact and user:
        resolved_contact = (
            getattr(getattr(user, "profile", None), "contact", "")
            or user.email
            or user.username
            or ""
        ).strip()

    SecurityAuditLog.objects.create(
        user=user if getattr(user, "pk", None) else None,
        category=(category or SecurityAuditLog.CATEGORY_AUTH)[:30],
        action=(action or "unknown")[:60],
        status=(status or SecurityAuditLog.STATUS_INFO)[:20],
        actor_contact=resolved_contact[:150],
        summary=(summary or action or "Security event")[:255],
        ip_address=get_client_ip(request) if request else None,
        user_agent=((request.META.get("HTTP_USER_AGENT") or "")[:255] if request else ""),
        path=((request.path or "")[:255] if request else ""),
        metadata=metadata or {},
    )


def initialize_secure_session(request):
    timeout_seconds = int(getattr(settings, "SESSION_INACTIVITY_TIMEOUT", 1800) or 1800)
    if timeout_seconds > 0:
        request.session.set_expiry(timeout_seconds)
        request.session["last_activity_at"] = timezone.now().isoformat()


def get_session_timeout_seconds():
    return int(getattr(settings, "SESSION_INACTIVITY_TIMEOUT", 1800) or 1800)


def get_login_lock_settings():
    failure_limit = int(getattr(settings, "LOGIN_LOCKOUT_ATTEMPTS", 5) or 5)
    lockout_minutes = int(getattr(settings, "LOGIN_LOCKOUT_MINUTES", 10) or 10)
    return max(1, failure_limit), max(1, lockout_minutes)


def _build_login_key(role, contact):
    normalized_role = (role or "").strip().lower()
    normalized_contact = (contact or "").strip().lower()
    digest = hashlib.sha256(f"{normalized_role}|{normalized_contact}".encode("utf-8")).hexdigest()
    return digest


def get_login_throttle(role, contact):
    normalized_role = (role or "").strip().lower()
    normalized_contact = (contact or "").strip().lower()
    if not normalized_role or not normalized_contact:
        return None

    throttle, _ = LoginThrottle.objects.get_or_create(
        key=_build_login_key(normalized_role, normalized_contact),
        defaults={"role": normalized_role, "contact": normalized_contact},
    )
    now = timezone.now()
    if throttle.locked_until and throttle.locked_until <= now:
        throttle.failed_attempts = 0
        throttle.locked_until = None
        throttle.save(update_fields=["failed_attempts", "locked_until", "last_attempt_at"])
    return throttle


def get_login_lockout(role, contact):
    throttle = get_login_throttle(role, contact)
    if not throttle or not throttle.locked_until or throttle.locked_until <= timezone.now():
        return None, 0
    remaining_seconds = max(1, int((throttle.locked_until - timezone.now()).total_seconds()))
    return throttle, remaining_seconds


def record_failed_login(role, contact):
    normalized_role = (role or "").strip().lower()
    normalized_contact = (contact or "").strip().lower()
    if not normalized_role or not normalized_contact:
        return None

    max_failures, lockout_minutes = get_login_lock_settings()
    with transaction.atomic():
        throttle = (
            LoginThrottle.objects.select_for_update()
            .filter(key=_build_login_key(normalized_role, normalized_contact))
            .first()
        )
        if not throttle:
            throttle = LoginThrottle.objects.create(
                key=_build_login_key(normalized_role, normalized_contact),
                role=normalized_role,
                contact=normalized_contact,
            )

        now = timezone.now()
        if throttle.locked_until and throttle.locked_until <= now:
            throttle.failed_attempts = 0
            throttle.locked_until = None

        throttle.failed_attempts = int(throttle.failed_attempts or 0) + 1
        throttle.last_attempt_at = now
        if throttle.failed_attempts >= max_failures:
            throttle.locked_until = now + timedelta(minutes=lockout_minutes)
        throttle.save(update_fields=["failed_attempts", "locked_until", "last_attempt_at"])
    return throttle


def clear_failed_logins(role, contact):
    normalized_role = (role or "").strip().lower()
    normalized_contact = (contact or "").strip().lower()
    if not normalized_role or not normalized_contact:
        return
    LoginThrottle.objects.filter(
        key=_build_login_key(normalized_role, normalized_contact)
    ).delete()


def format_lockout_message(remaining_seconds):
    remaining_minutes = max(1, (int(remaining_seconds) + 59) // 60)
    return (
        f"Too many failed login attempts. Try again in {remaining_minutes} minute(s)."
    )
