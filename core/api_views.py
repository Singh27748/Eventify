import hashlib
import json
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.db.models import Q
from django.http import JsonResponse
from django.utils import timezone

from .models import Event, OTPRequest, Profile
from .services import create_notification, generate_otp


def _json_error(message: str, status: int = 400):
    return JsonResponse({"ok": False, "error": message}, status=status)


def _load_request_payload(request):
    content_type = (request.content_type or "").lower()

    if "application/json" in content_type:
        if not request.body:
            return {}
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Request body must be valid JSON.")
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object.")
        return payload

    payload: dict[str, Any] = {}
    for key, values in request.POST.lists():
        payload[key] = values if len(values) > 1 else values[0]
    return payload


def _value(payload: dict[str, Any], key: str, default: str = "") -> str:
    raw = payload.get(key, default)
    if isinstance(raw, list):
        if not raw:
            return default
        raw = raw[0]
    if raw is None:
        return default
    return str(raw)


def _build_auth_username(contact: str, role: str) -> str:
    normalized_contact = (contact or "").strip().lower() or "user"
    normalized_role = (role or "").strip().lower() or "user"
    max_len = User._meta.get_field("username").max_length
    base = f"{normalized_contact}::{normalized_role}"
    if len(base) <= max_len:
        return base

    digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
    role_part = normalized_role[:20]
    reserved = len(role_part) + len(digest) + 4
    contact_len = max(8, max_len - reserved)
    return f"{normalized_contact[:contact_len]}::{role_part}::{digest}"[:max_len]


def _build_unique_auth_username(contact: str, role: str) -> str:
    candidate = _build_auth_username(contact, role)
    if not User.objects.filter(username__iexact=candidate).exists():
        return candidate

    suffix_seed = hashlib.sha1(
        f"{contact}|{role}|{timezone.now().timestamp()}".encode("utf-8")
    ).hexdigest()[:8]
    idx = 0
    while True:
        extra = f"{suffix_seed}{idx}" if idx else suffix_seed
        candidate = _build_auth_username(f"{contact}-{extra}", role)
        if not User.objects.filter(username__iexact=candidate).exists():
            return candidate
        idx += 1


def _find_profile_by_contact_role(contact: str, role: str):
    return (
        Profile.objects.select_related("user")
        .filter(role=role)
        .filter(
            Q(contact=contact)
            | Q(user__username__iexact=contact)
            | Q(user__email__iexact=contact)
        )
        .order_by("-id")
        .first()
    )


def _serialize_event(event: Event):
    return {
        "id": event.id,
        "title": event.title,
        "category": event.category,
        "location": event.location,
        "date": event.date.isoformat(),
        "time": event.time,
        "price": event.price,
        "description": event.description,
        "image": event.image_source,
        "organizer": {
            "name": event.organizer_name,
            "phone": event.organizer_phone,
            "email": event.organizer_email,
        },
    }


def api_login(request):
    if request.method != "POST":
        return _json_error("Method not allowed.", status=405)

    try:
        payload = _load_request_payload(request)
    except ValueError as exc:
        return _json_error(str(exc), status=400)

    role = _value(payload, "role").strip()
    contact = _value(payload, "contact").strip().lower()
    password = _value(payload, "password")

    if not role or not contact or not password:
        return _json_error("role, contact and password are required.", status=400)

    profile = _find_profile_by_contact_role(contact, role)
    if not profile:
        return _json_error("Invalid credentials for selected role.", status=401)

    user = authenticate(request, username=profile.user.username, password=password)
    if not user:
        return _json_error("Invalid credentials for selected role.", status=401)

    login(request, user)
    return JsonResponse(
        {
            "ok": True,
            "message": "Login successful.",
            "user": {
                "id": user.id,
                "name": user.first_name or user.username,
                "role": profile.role,
                "contact": profile.contact,
            },
        }
    )


def api_register_send_otp(request):
    if request.method != "POST":
        return _json_error("Method not allowed.", status=405)

    try:
        payload = _load_request_payload(request)
    except ValueError as exc:
        return _json_error(str(exc), status=400)

    role = _value(payload, "role").strip()
    name = _value(payload, "name").strip()
    contact = _value(payload, "contact").strip().lower()
    password = _value(payload, "password")
    confirm_password = _value(payload, "confirmPassword")

    if not all([role, name, contact, password, confirm_password]):
        return _json_error("Please fill all registration fields.", status=400)

    if password != confirm_password:
        return _json_error("Password and confirm password do not match.", status=400)

    if len(password) < 6:
        return _json_error("Password must be at least 6 characters.", status=400)

    if Profile.objects.filter(contact=contact, role=role).exists():
        return _json_error(
            "This email/phone is already registered for selected role.",
            status=409,
        )

    otp_value = generate_otp()
    otp_request = OTPRequest.objects.create(
        purpose=OTPRequest.PURPOSE_REGISTER,
        contact=contact,
        role=role,
        name=name,
        password_hash=make_password(password),
        otp=otp_value,
        expires_at=timezone.now() + timedelta(minutes=10),
    )

    response_payload: dict[str, Any] = {
        "ok": True,
        "message": "OTP sent successfully.",
        "request_id": otp_request.id,
        "expires_at": otp_request.expires_at.isoformat(),
    }
    if settings.DEBUG:
        response_payload["otp_preview"] = otp_value

    return JsonResponse(response_payload, status=201)


def api_register_verify_otp(request):
    if request.method != "POST":
        return _json_error("Method not allowed.", status=405)

    try:
        payload = _load_request_payload(request)
    except ValueError as exc:
        return _json_error(str(exc), status=400)

    request_id = _value(payload, "request_id").strip()
    entered_otp = _value(payload, "otp").strip()
    if not request_id or not entered_otp:
        return _json_error("request_id and otp are required.", status=400)

    otp_request = OTPRequest.objects.filter(id=request_id).first()
    if not otp_request or otp_request.is_used:
        return _json_error("OTP request not found or already used.", status=404)

    if otp_request.purpose != OTPRequest.PURPOSE_REGISTER:
        return _json_error("This endpoint only verifies register OTP requests.", status=400)

    if otp_request.is_expired():
        return _json_error("OTP expired. Please request a new OTP.", status=410)

    if otp_request.otp != entered_otp:
        return _json_error("Invalid OTP.", status=400)

    if Profile.objects.filter(contact=otp_request.contact, role=otp_request.role).exists():
        otp_request.is_used = True
        otp_request.save(update_fields=["is_used"])
        return _json_error(
            "This email/phone is already registered for selected role.",
            status=409,
        )

    username = _build_unique_auth_username(otp_request.contact, otp_request.role)
    user = User.objects.create(
        username=username,
        first_name=username,
        last_name="",
        email=otp_request.contact if "@" in otp_request.contact else "",
        password=otp_request.password_hash,
    )
    profile, _ = Profile.objects.update_or_create(
        user=user,
        defaults={
            "role": otp_request.role,
            "contact": otp_request.contact,
            "phone": "" if "@" in otp_request.contact else otp_request.contact,
        },
    )
    create_notification(
        user,
        "Welcome to Eventify",
        "Your account is verified and ready. Start browsing events.",
        "system",
    )
    otp_request.is_used = True
    otp_request.save(update_fields=["is_used"])
    login(request, user)

    return JsonResponse(
        {
            "ok": True,
            "message": "OTP verified. Account created and login successful.",
            "user": {
                "id": user.id,
                "name": user.first_name or user.username,
                "role": profile.role,
                "contact": profile.contact,
            },
        },
        status=201,
    )


def api_events(request):
    if request.method != "GET":
        return _json_error("Method not allowed.", status=405)

    search = (request.GET.get("search") or "").strip()
    category = (request.GET.get("category") or "").strip()
    location = (request.GET.get("location") or "").strip()

    events = Event.objects.all()
    if request.user.is_authenticated:
        profile = getattr(request.user, "profile", None)
        if profile and profile.role == Profile.ROLE_ORGANIZER:
            events = events.filter(created_by=request.user)

    if search:
        events = events.filter(
            Q(title__icontains=search)
            | Q(category__icontains=search)
            | Q(location__icontains=search)
        )
    if category:
        events = events.filter(category=category)
    if location:
        events = events.filter(location__icontains=location)

    events = events.order_by("date", "id")
    categories = list(
        events.values_list("category", flat=True).distinct().order_by("category")
    )

    return JsonResponse(
        {
            "ok": True,
            "count": events.count(),
            "categories": categories,
            "events": [_serialize_event(event) for event in events],
        }
    )
