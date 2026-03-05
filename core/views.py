from datetime import datetime, timedelta
import hashlib
from html import escape
from io import BytesIO
import mimetypes
from pathlib import Path
import re
import socket

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.mail import EmailMessage
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import Count, Prefetch, Q, Sum
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.core import signing
from django.core.signing import BadSignature, SignatureExpired
from django.utils.text import slugify
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils import timezone
from django.utils.dateparse import parse_date
from PIL import Image as PILImage, ImageDraw, ImageFont, ImageOps

from .decorators import role_required
from .models import (
    Booking,
    Event,
    EventActivitySlot,
    EventHelperSlot,
    Notification,
    OTPRequest,
    Payment,
    PrivateEventPayment,
    Profile,
    SupportTicket,
)
from .services import (
    create_notification,
    generate_invoice_no,
    generate_otp,
    menu_by_role,
    normalize_language,
    seed_demo_data,
    ui_labels,
)

_seed_checked = False
PRIVATE_EVENT_EMAIL_FEE = 10


def ensure_seeded():
    global _seed_checked
    if _seed_checked:
        return
    seed_demo_data()
    _seed_checked = True


def get_or_create_profile(user):
    profile, _ = Profile.objects.get_or_create(
        user=user,
        defaults={
            "role": Profile.ROLE_USER,
            "contact": user.username,
        },
    )
    if not profile.contact:
        profile.contact = user.username
        profile.save(update_fields=["contact"])
    return profile


def validate_event_image(uploaded_image):
    if not uploaded_image:
        return None

    ext = Path(uploaded_image.name).suffix.lower()
    allowed_exts = {".jpg", ".jpeg", ".png", ".webp"}
    if ext not in allowed_exts:
        return "Only JPG, JPEG, PNG, or WEBP image is allowed."

    if uploaded_image.size > 5 * 1024 * 1024:
        return "Event image size must be less than 5MB."

    return None


def parse_required_count(raw_value):
    try:
        count = int(raw_value or 0)
    except (TypeError, ValueError):
        return None
    if count < 0:
        return None
    return count


def build_active_activity_form_rows(event=None):
    if event:
        existing_rows = list(event.active_activity_slots.values("id", "name", "required_count"))
        if existing_rows:
            return existing_rows

        legacy_required = max(0, int(event.active_participants_required or 0))
        legacy_name = (event.active_participants_usage or "").strip()
        if legacy_required > 0 or legacy_name:
            return [{"id": "", "name": legacy_name, "required_count": legacy_required}]

    return [{"id": "", "name": "", "required_count": 0}]


def parse_active_activity_slots_from_post(request):
    slot_ids = request.POST.getlist("activeActivityId[]") or request.POST.getlist("activeActivityId")
    slot_names = request.POST.getlist("activeActivityName[]") or request.POST.getlist("activeActivityName")
    slot_counts = request.POST.getlist("activeActivityRequired[]") or request.POST.getlist("activeActivityRequired")

    if not slot_ids and not slot_names and not slot_counts:
        legacy_name = (request.POST.get("activeParticipantsUsage") or "").strip()
        legacy_count = request.POST.get("activeParticipantsRequired")
        if legacy_name or legacy_count not in (None, ""):
            slot_ids = [""]
            slot_names = [legacy_name]
            slot_counts = [legacy_count or "0"]
        else:
            return [], None

    max_rows = max(len(slot_ids), len(slot_names), len(slot_counts))
    parsed_slots = []
    for index in range(max_rows):
        raw_slot_id = (slot_ids[index] if index < len(slot_ids) else "").strip()
        slot_name = (slot_names[index] if index < len(slot_names) else "").strip()
        raw_count = (slot_counts[index] if index < len(slot_counts) else "").strip()

        if not raw_slot_id and not slot_name and not raw_count:
            continue

        if raw_count == "":
            return None, "Please enter required user count for each activity."

        required_count = parse_required_count(raw_count)
        if required_count is None:
            return None, "Activity user counts must be 0 or greater numbers."

        if required_count > 0 and not slot_name:
            return None, "Please enter activity name for all active participant requirements."

        if required_count <= 0:
            continue

        slot_id = None
        if raw_slot_id:
            try:
                slot_id = int(raw_slot_id)
            except ValueError:
                return None, "Invalid activity row received."
            if slot_id <= 0:
                return None, "Invalid activity row received."

        parsed_slots.append(
            {
                "id": slot_id,
                "name": slot_name,
                "required_count": required_count,
            }
        )

    return parsed_slots, None


def summarize_active_activity_slots(active_activity_slots):
    total_required = sum(slot["required_count"] for slot in active_activity_slots)
    names = [slot["name"] for slot in active_activity_slots if slot.get("name")]
    summary = ", ".join(names).strip()
    if len(summary) > 220:
        summary = summary[:217].rstrip(", ") + "..."
    return total_required, summary


def build_helper_activity_form_rows(event=None):
    if event:
        existing_rows = list(event.helper_activity_slots.values("id", "name", "required_count"))
        if existing_rows:
            return existing_rows

        legacy_required = max(0, int(event.helpers_required or 0))
        legacy_name = (event.helpers_usage or "").strip()
        if legacy_required > 0 or legacy_name:
            return [{"id": "", "name": legacy_name, "required_count": legacy_required}]

    return [{"id": "", "name": "", "required_count": 0}]


def parse_helper_activity_slots_from_post(request):
    slot_ids = request.POST.getlist("helperActivityId[]") or request.POST.getlist("helperActivityId")
    slot_names = request.POST.getlist("helperActivityName[]") or request.POST.getlist("helperActivityName")
    slot_counts = request.POST.getlist("helperActivityRequired[]") or request.POST.getlist("helperActivityRequired")

    if not slot_ids and not slot_names and not slot_counts:
        legacy_name = (request.POST.get("helpersUsage") or "").strip()
        legacy_count = request.POST.get("helpersRequired")
        if legacy_name or legacy_count not in (None, ""):
            slot_ids = [""]
            slot_names = [legacy_name]
            slot_counts = [legacy_count or "0"]
        else:
            return [], None

    max_rows = max(len(slot_ids), len(slot_names), len(slot_counts))
    parsed_slots = []
    for index in range(max_rows):
        raw_slot_id = (slot_ids[index] if index < len(slot_ids) else "").strip()
        slot_name = (slot_names[index] if index < len(slot_names) else "").strip()
        raw_count = (slot_counts[index] if index < len(slot_counts) else "").strip()

        if not raw_slot_id and not slot_name and not raw_count:
            continue

        if raw_count == "":
            return None, "Please enter required user count for each organizer help activity."

        required_count = parse_required_count(raw_count)
        if required_count is None:
            return None, "Organizer help user counts must be 0 or greater numbers."

        if required_count > 0 and not slot_name:
            return None, "Please enter organizer help activity name for all required rows."

        if required_count <= 0:
            continue

        slot_id = None
        if raw_slot_id:
            try:
                slot_id = int(raw_slot_id)
            except ValueError:
                return None, "Invalid organizer help row received."
            if slot_id <= 0:
                return None, "Invalid organizer help row received."

        parsed_slots.append(
            {
                "id": slot_id,
                "name": slot_name,
                "required_count": required_count,
            }
        )

    return parsed_slots, None


def summarize_helper_activity_slots(helper_activity_slots):
    total_required = sum(slot["required_count"] for slot in helper_activity_slots)
    names = [slot["name"] for slot in helper_activity_slots if slot.get("name")]
    summary = ", ".join(names).strip()
    if len(summary) > 220:
        summary = summary[:217].rstrip(", ") + "..."
    return total_required, summary


def sync_event_active_activity_slots(event, active_activity_slots):
    existing_slots = {slot.id: slot for slot in event.active_activity_slots.all()}
    incoming_ids = {slot["id"] for slot in active_activity_slots if slot.get("id")}

    invalid_id = next((slot_id for slot_id in incoming_ids if slot_id not in existing_slots), None)
    if invalid_id:
        return "Invalid activity row selected. Please refresh and try again."

    for slot_id, slot in existing_slots.items():
        if slot_id in incoming_ids:
            continue
        applied_count = (
            Booking.objects.filter(
                event=event,
                application_role=Booking.ROLE_ACTIVE_PARTICIPANT,
                active_activity_slot=slot,
            )
            .exclude(status=Booking.STATUS_CANCELLED)
            .count()
        )
        if applied_count > 0:
            return (
                f"Cannot remove activity '{slot.name}' because "
                f"{applied_count} user(s) are already registered."
            )

    removable_ids = [slot_id for slot_id in existing_slots if slot_id not in incoming_ids]
    if removable_ids:
        EventActivitySlot.objects.filter(id__in=removable_ids).delete()

    for slot_data in active_activity_slots:
        slot_id = slot_data.get("id")
        if slot_id:
            slot = existing_slots[slot_id]
            applied_count = (
                Booking.objects.filter(
                    event=event,
                    application_role=Booking.ROLE_ACTIVE_PARTICIPANT,
                    active_activity_slot=slot,
                )
                .exclude(status=Booking.STATUS_CANCELLED)
                .count()
            )
            if slot_data["required_count"] < applied_count:
                return (
                    f"Required users for '{slot.name}' cannot be less than "
                    f"already registered count ({applied_count})."
                )
            update_fields = []
            if slot.name != slot_data["name"]:
                slot.name = slot_data["name"]
                update_fields.append("name")
            if slot.required_count != slot_data["required_count"]:
                slot.required_count = slot_data["required_count"]
                update_fields.append("required_count")
            if update_fields:
                slot.save(update_fields=update_fields)
            continue

        EventActivitySlot.objects.create(
            event=event,
            name=slot_data["name"],
            required_count=slot_data["required_count"],
        )

    return None


def sync_event_helper_activity_slots(event, helper_activity_slots):
    existing_slots = {slot.id: slot for slot in event.helper_activity_slots.all()}
    incoming_ids = {slot["id"] for slot in helper_activity_slots if slot.get("id")}

    invalid_id = next((slot_id for slot_id in incoming_ids if slot_id not in existing_slots), None)
    if invalid_id:
        return "Invalid organizer help row selected. Please refresh and try again."

    for slot_id, slot in existing_slots.items():
        if slot_id in incoming_ids:
            continue
        applied_count = (
            Booking.objects.filter(
                event=event,
                application_role=Booking.ROLE_HELPER_TEAM,
                helper_activity_slot=slot,
            )
            .exclude(status=Booking.STATUS_CANCELLED)
            .count()
        )
        if applied_count > 0:
            return (
                f"Cannot remove organizer help '{slot.name}' because "
                f"{applied_count} user(s) are already registered."
            )

    removable_ids = [slot_id for slot_id in existing_slots if slot_id not in incoming_ids]
    if removable_ids:
        EventHelperSlot.objects.filter(id__in=removable_ids).delete()

    for slot_data in helper_activity_slots:
        slot_id = slot_data.get("id")
        if slot_id:
            slot = existing_slots[slot_id]
            applied_count = (
                Booking.objects.filter(
                    event=event,
                    application_role=Booking.ROLE_HELPER_TEAM,
                    helper_activity_slot=slot,
                )
                .exclude(status=Booking.STATUS_CANCELLED)
                .count()
            )
            if slot_data["required_count"] < applied_count:
                return (
                    f"Required users for organizer help '{slot.name}' cannot be less than "
                    f"already registered count ({applied_count})."
                )
            update_fields = []
            if slot.name != slot_data["name"]:
                slot.name = slot_data["name"]
                update_fields.append("name")
            if slot.required_count != slot_data["required_count"]:
                slot.required_count = slot_data["required_count"]
                update_fields.append("required_count")
            if update_fields:
                slot.save(update_fields=update_fields)
            continue

        EventHelperSlot.objects.create(
            event=event,
            name=slot_data["name"],
            required_count=slot_data["required_count"],
        )

    return None


def normalize_security_answer(raw_value):
    return " ".join((raw_value or "").strip().lower().split())


def save_security_question(request):
    question = (request.POST.get("securityQuestion") or "").strip()
    answer = normalize_security_answer(request.POST.get("securityAnswer"))
    if not question or not answer:
        messages.error(request, "Please enter both security question and answer.")
        return redirect("settings")

    if len(question) > 255:
        messages.error(request, "Security question is too long.")
        return redirect("settings")

    if len(answer) < 2:
        messages.error(request, "Security answer is too short.")
        return redirect("settings")

    profile = get_or_create_profile(request.user)
    profile.security_question = question
    profile.security_answer_hash = make_password(answer)
    profile.save(update_fields=["security_question", "security_answer_hash"])
    messages.success(request, "Security question saved successfully.")
    return redirect("settings")


EVENT_EMAIL_SPLIT_PATTERN = re.compile(r"[\n,;]+")


def parse_event_email_list(raw_value):
    candidates = [
        part.strip()
        for part in EVENT_EMAIL_SPLIT_PATTERN.split((raw_value or "").strip())
        if part.strip()
    ]

    valid_emails = []
    invalid_emails = []
    seen = set()
    for candidate in candidates:
        lowered_candidate = candidate.lower()
        try:
            validate_email(lowered_candidate)
        except ValidationError:
            invalid_emails.append(candidate)
            continue
        if lowered_candidate in seen:
            continue
        seen.add(lowered_candidate)
        valid_emails.append(lowered_candidate)

    normalized_text = ", ".join(valid_emails)
    return valid_emails, invalid_emails, normalized_text


def send_private_event_invitation_emails(request, event, recipients, is_update=False):
    if not recipients:
        return 0, 0

    sender_email = (
        (getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip()
        or (getattr(settings, "EMAIL_HOST_USER", "") or "").strip()
        or "webmaster@localhost"
    )
    # Always generate a mobile/LAN-usable link (never localhost in emails).
    event_link = f"{build_qr_base_url(request)}{reverse('event_detail', args=[event.id])}"
    event_date_value = event.date
    if isinstance(event_date_value, str):
        parsed_event_date = parse_date(event_date_value)
        event_date = (
            parsed_event_date.strftime("%d %b %Y") if parsed_event_date else event_date_value
        )
    else:
        event_date = event_date_value.strftime("%d %b %Y")
    subject_prefix = "Updated Invitation" if is_update else "Invitation"
    subject = f"{subject_prefix}: {event.title} | Eventify"
    body_lines = [
        "You are invited to a private event on Eventify.",
        "",
        f"Event: {event.title}",
        f"Category: {event.category}",
        f"Date: {event_date}",
        f"Time: {event.time}",
        f"Location: {event.location}",
        f"Organizer: {event.organizer_name}",
        "",
        "Open event details:",
        event_link,
    ]
    body = "\n".join(body_lines)

    sent_count = 0
    failed_count = 0
    for recipient in recipients:
        try:
            EmailMessage(
                subject=subject,
                body=body,
                from_email=sender_email,
                to=[recipient],
            ).send(fail_silently=False)
            sent_count += 1
        except Exception:
            failed_count += 1

    return sent_count, failed_count


def calculate_private_event_creation_amount(guest_count):
    return max(0, int(guest_count or 0)) * PRIVATE_EVENT_EMAIL_FEE


def build_event_role_slots(event):
    active_booking_qs = Booking.objects.filter(
        event=event,
        application_role=Booking.ROLE_ACTIVE_PARTICIPANT,
    ).exclude(status=Booking.STATUS_CANCELLED)
    helper_booking_qs = Booking.objects.filter(
        event=event,
        application_role=Booking.ROLE_HELPER_TEAM,
    ).exclude(status=Booking.STATUS_CANCELLED)
    activity_slots = list(event.active_activity_slots.all())
    slot_applied_map = {
        row["active_activity_slot_id"]: row["applied"]
        for row in active_booking_qs.values("active_activity_slot_id").annotate(applied=Count("id"))
    }
    active_activities = []
    if activity_slots:
        for slot in activity_slots:
            required = max(0, int(slot.required_count or 0))
            applied = int(slot_applied_map.get(slot.id, 0))
            remaining = max(0, required - applied)
            active_activities.append(
                {
                    "id": slot.id,
                    "name": slot.name,
                    "required": required,
                    "applied": applied,
                    "remaining": remaining,
                    "available": required > 0 and remaining > 0,
                }
            )

        unassigned_applied = int(slot_applied_map.get(None, 0))
        if unassigned_applied > 0:
            active_activities.append(
                {
                    "id": None,
                    "name": "Legacy (Unassigned)",
                    "required": unassigned_applied,
                    "applied": unassigned_applied,
                    "remaining": 0,
                    "available": False,
                }
            )
    else:
        legacy_required = max(0, int(event.active_participants_required or 0))
        legacy_name = (event.active_participants_usage or "").strip() or "General Activity"
        if legacy_required > 0:
            legacy_applied = active_booking_qs.count()
            active_activities.append(
                {
                    "id": None,
                    "name": legacy_name,
                    "required": legacy_required,
                    "applied": legacy_applied,
                    "remaining": max(0, legacy_required - legacy_applied),
                    "available": legacy_required > legacy_applied,
                }
            )

    active_required = sum(item["required"] for item in active_activities)
    active_applied = sum(item["applied"] for item in active_activities)
    helper_slots = list(event.helper_activity_slots.all())
    helper_slot_applied_map = {
        row["helper_activity_slot_id"]: row["applied"]
        for row in helper_booking_qs.values("helper_activity_slot_id").annotate(applied=Count("id"))
    }
    helper_activities = []
    if helper_slots:
        for slot in helper_slots:
            required = max(0, int(slot.required_count or 0))
            applied = int(helper_slot_applied_map.get(slot.id, 0))
            remaining = max(0, required - applied)
            helper_activities.append(
                {
                    "id": slot.id,
                    "name": slot.name,
                    "required": required,
                    "applied": applied,
                    "remaining": remaining,
                    "available": required > 0 and remaining > 0,
                }
            )

        unassigned_applied = int(helper_slot_applied_map.get(None, 0))
        if unassigned_applied > 0:
            helper_activities.append(
                {
                    "id": None,
                    "name": "Legacy (Unassigned)",
                    "required": unassigned_applied,
                    "applied": unassigned_applied,
                    "remaining": 0,
                    "available": False,
                }
            )
    else:
        legacy_required = max(0, int(event.helpers_required or 0))
        legacy_name = (event.helpers_usage or "").strip() or "General Organizer Help"
        if legacy_required > 0:
            legacy_applied = helper_booking_qs.count()
            helper_activities.append(
                {
                    "id": None,
                    "name": legacy_name,
                    "required": legacy_required,
                    "applied": legacy_applied,
                    "remaining": max(0, legacy_required - legacy_applied),
                    "available": legacy_required > legacy_applied,
                }
            )

    helper_required = sum(item["required"] for item in helper_activities)
    helper_applied = sum(item["applied"] for item in helper_activities)
    active_remaining = max(0, active_required - active_applied)
    helper_remaining = max(0, helper_required - helper_applied)

    return {
        "show_role_choice": active_required > 0 or helper_required > 0,
        "active_activities": active_activities,
        "helper_activities": helper_activities,
        "active_participant": {
            "required": active_required,
            "applied": active_applied,
            "remaining": active_remaining,
            "available": active_required > 0 and active_remaining > 0,
        },
        "helper_team": {
            "required": helper_required,
            "applied": helper_applied,
            "remaining": helper_remaining,
            "available": helper_required > 0 and helper_remaining > 0,
        },
    }


def _to_24h_time(raw_value):
    value = (raw_value or "").strip()
    if not value:
        return ""

    normalized = value.upper().replace(".", "")
    patterns = ("%H:%M", "%I:%M %p", "%I:%M%p", "%I %p", "%H")
    for pattern in patterns:
        try:
            parsed = datetime.strptime(normalized, pattern)
            return parsed.strftime("%H:%M")
        except ValueError:
            continue
    return ""


def split_event_time_for_picker(raw_time):
    text = (raw_time or "").strip()
    if not text:
        return "", ""

    if "-" in text:
        start_text, end_text = [part.strip() for part in text.split("-", 1)]
    else:
        start_text, end_text = text, ""

    return _to_24h_time(start_text), _to_24h_time(end_text)


def build_event_time_from_post(request):
    start_time = (request.POST.get("startTime") or "").strip()
    end_time = (request.POST.get("endTime") or "").strip()
    legacy_time = (request.POST.get("time") or "").strip()

    if not start_time and not end_time:
        return legacy_time
    if not start_time or not end_time:
        return ""

    start_24 = _to_24h_time(start_time)
    end_24 = _to_24h_time(end_time)
    if not start_24 or not end_24:
        return ""

    start_display = datetime.strptime(start_24, "%H:%M").strftime("%I:%M %p").lstrip("0")
    end_display = datetime.strptime(end_24, "%H:%M").strftime("%I:%M %p").lstrip("0")
    return f"{start_display} - {end_display}"


def build_auth_username(contact, role):
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


def build_unique_auth_username(contact, role):
    candidate = build_auth_username(contact, role)
    if not User.objects.filter(username__iexact=candidate).exists():
        return candidate

    suffix_seed = hashlib.sha1(
        f"{contact}|{role}|{timezone.now().timestamp()}".encode("utf-8")
    ).hexdigest()[:8]
    idx = 0
    while True:
        extra = f"{suffix_seed}{idx}" if idx else suffix_seed
        candidate = build_auth_username(f"{contact}-{extra}", role)
        if not User.objects.filter(username__iexact=candidate).exists():
            return candidate
        idx += 1


def find_profile_by_contact_role(contact, role):
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


def _load_font(size, bold=False):
    if bold:
        candidates = ["arialbd.ttf", "DejaVuSans-Bold.ttf"]
    else:
        candidates = ["arial.ttf", "DejaVuSans.ttf"]

    for font_name in candidates:
        try:
            return ImageFont.truetype(font_name, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _wrap_text(draw, text, font, max_width):
    words = (text or "").split()
    if not words:
        return [""]

    lines = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if draw.textlength(candidate, font=font) <= max_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def generate_ticket_token(booking):
    payload = {
        "booking_id": booking.id,
        "user_id": booking.user_id,
        "event_id": booking.event_id,
        "invoice_no": booking.invoice_no or "",
        "ticket_reference": booking.ticket_reference,
    }
    return signing.dumps(payload, salt="eventify-ticket-qr")


def parse_ticket_token(token):
    try:
        return signing.loads(
            token,
            salt="eventify-ticket-qr",
            max_age=60 * 60 * 24 * 365 * 5,
        )
    except (BadSignature, SignatureExpired):
        return None


TICKET_REFERENCE_PATTERN = re.compile(r"^TKT-E([A-Z0-9]+)-B([A-Z0-9]+)$", re.IGNORECASE)
TICKET_REFERENCE_LEGACY_PATTERN = re.compile(r"^TKT-(\d+)-(\d+)$", re.IGNORECASE)
PUBLIC_SCAN_MEDIA_ALLOWED_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".gif",
    ".bmp",
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
    ".m4v",
    ".3gp",
}
PUBLIC_SCAN_MEDIA_MAX_SIZE = 20 * 1024 * 1024


def parse_ticket_reference(value):
    candidate = (value or "").strip().upper()
    match = TICKET_REFERENCE_PATTERN.fullmatch(candidate)
    if match:
        try:
            event_id = int(match.group(1), 36)
            booking_id = int(match.group(2), 36)
        except ValueError:
            return None
    else:
        legacy_match = TICKET_REFERENCE_LEGACY_PATTERN.fullmatch(candidate)
        if not legacy_match:
            return None
        event_id = int(legacy_match.group(1))
        booking_id = int(legacy_match.group(2))

    if event_id <= 0 or booking_id <= 0:
        return None

    return candidate, event_id, booking_id


def get_event_organizer_email(event):
    direct_email = (event.organizer_email or "").strip()
    if direct_email:
        return direct_email

    if event.created_by_id:
        fallback_email = (event.created_by.email or "").strip()
        if fallback_email:
            return fallback_email

    return ""


def validate_public_scan_media(uploaded_file):
    if not uploaded_file:
        return "Please upload an image or video file."

    file_name = Path(uploaded_file.name or "").name
    extension = Path(file_name).suffix.lower()
    if extension not in PUBLIC_SCAN_MEDIA_ALLOWED_EXTENSIONS:
        return "Only image/video files are allowed."

    if uploaded_file.size > PUBLIC_SCAN_MEDIA_MAX_SIZE:
        return "File size must be 20MB or less."

    content_type = (uploaded_file.content_type or "").lower()
    if content_type and not (
        content_type.startswith("image/") or content_type.startswith("video/")
    ):
        return "Upload a valid image or video file."

    return ""


def send_public_scan_media_to_organizer(request, booking, uploaded_file, note_text):
    organizer_email = get_event_organizer_email(booking.event)
    if not organizer_email:
        return False, "Organizer email is not configured for this event."

    system_from_email = (
        (getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip()
        or "webmaster@localhost"
    )
    sender_name = "Guest Scanner"
    sender_contact = "Anonymous"
    sender_email = ""
    reply_to = []
    if request.user.is_authenticated:
        sender_name = (
            request.user.first_name
            or request.user.get_full_name().strip()
            or request.user.username
        )
        sender_contact = request.user.email or request.user.username
        if request.user.email:
            sender_email = request.user.email.strip()
            reply_to = [sender_email]

    attachment_name = Path(uploaded_file.name or "scan-file").name
    attachment_content_type = (
        uploaded_file.content_type
        or mimetypes.guess_type(attachment_name)[0]
        or "application/octet-stream"
    )

    subject = f"Ticket Scan Media | {booking.ticket_reference} | {booking.event.title}"
    lines = [
        "A ticket scan media file was submitted.",
        "",
        f"Ticket ID: {booking.ticket_reference}",
        f"Event: {booking.event.title}",
        f"User: {booking.user.first_name or booking.user.username}",
        f"Organizer: {booking.event.organizer_name or '-'}",
        f"Scanned by: {sender_name}",
        f"Scanner contact: {sender_contact}",
    ]
    cleaned_note = (note_text or "").strip()
    if cleaned_note:
        lines.extend(["", "Message:", cleaned_note])

    email_body = "\n".join(lines)
    attachment_bytes = uploaded_file.read()
    preferred_from_email = sender_email or system_from_email

    def _build_email(from_email):
        message = EmailMessage(
            subject=subject,
            body=email_body,
            from_email=from_email,
            to=[organizer_email],
            reply_to=reply_to,
        )
        message.attach(
            attachment_name,
            attachment_bytes,
            attachment_content_type,
        )
        return message

    try:
        _build_email(preferred_from_email).send(fail_silently=False)
    except Exception:
        if preferred_from_email == system_from_email:
            return False, "Unable to send email right now. Please try again."

        try:
            _build_email(system_from_email).send(fail_silently=False)
        except Exception:
            return False, "Unable to send email right now. Please try again."

    if booking.event.created_by_id:
        create_notification(
            booking.event.created_by,
            "Ticket Media Received",
            f"New media was sent for ticket {booking.ticket_reference}.",
            "booking",
        )

    return True, "File sent to organizer successfully."


def _get_lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip_address = sock.getsockname()[0]
            if ip_address:
                return ip_address
    except OSError:
        pass
    return "127.0.0.1"


def build_qr_base_url(request):
    configured_base = (getattr(settings, "QR_BASE_URL", "") or "").strip().rstrip("/")
    if configured_base:
        return configured_base

    scheme = "https" if request.is_secure() else "http"
    host = request.get_host()
    host_name = host.split(":")[0].lower()

    if host_name in {"127.0.0.1", "localhost", "0.0.0.0"}:
        port = request.get_port()
        default_port = "443" if scheme == "https" else "80"
        port_suffix = f":{port}" if port and port != default_port else ""
        return f"{scheme}://{_get_lan_ip()}{port_suffix}"

    return f"{scheme}://{host}"


def build_ticket_pdf(booking, holder_name, user_photo, qr_url):
    page_width, page_height = 1240, 1754
    page = PILImage.new("RGB", (page_width, page_height), "#eef2ff")
    draw = ImageDraw.Draw(page)

    title_font = _load_font(54, bold=True)
    section_font = _load_font(34, bold=True)
    body_font = _load_font(28)
    small_font = _load_font(24)

    outer = (60, 70, page_width - 60, page_height - 70)
    draw.rounded_rectangle(outer, radius=36, fill="#ffffff", outline="#d5dff8", width=3)
    draw.rounded_rectangle((60, 70, page_width - 60, 260), radius=36, fill="#1f4fb9")
    draw.text((96, 124), "EVENTIFY TICKET", fill="#ffffff", font=title_font)

    resampling = PILImage.Resampling.LANCZOS if hasattr(PILImage, "Resampling") else PILImage.LANCZOS
    avatar_size = 210
    avatar_x, avatar_y = page_width - 60 - avatar_size - 60, 315
    avatar = ImageOps.fit(user_photo.convert("RGB"), (avatar_size, avatar_size), method=resampling)
    avatar_mask = PILImage.new("L", (avatar_size, avatar_size), 0)
    ImageDraw.Draw(avatar_mask).ellipse((0, 0, avatar_size, avatar_size), fill=255)
    page.paste(avatar, (avatar_x, avatar_y), avatar_mask)
    draw.ellipse(
        (avatar_x - 6, avatar_y - 6, avatar_x + avatar_size + 6, avatar_y + avatar_size + 6),
        outline="#1f4fb9",
        width=4,
    )

    content_x = 96
    content_y = 320
    draw.text((content_x, content_y), "Ticket Holder", fill="#1f4fb9", font=small_font)
    draw.text((content_x, content_y + 36), holder_name, fill="#182342", font=section_font)

    details_top = 620
    details = [
        ("Ticket ID", booking.ticket_reference),
        ("Booking ID", f"#{booking.id}"),
        ("Invoice No", booking.invoice_no or "-"),
        ("Holder", holder_name),
        ("Applied Role", booking.applied_role_label),
        ("Event", booking.event.title),
        ("Event Date", booking.event.date.strftime("%d %b %Y")),
        ("Event Time", booking.event.time),
        ("Location", booking.event.location),
        ("Tickets", str(booking.tickets)),
        ("Amount", f"INR {booking.total_amount:,}"),
        ("Payment", booking.payment_status.title()),
    ]

    qr_size = 270
    qr_x = page_width - 60 - qr_size - 70
    qr_y = 620

    try:
        import qrcode

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr_payload = (qr_url or "").strip() or booking.ticket_reference
        qr.add_data(qr_payload)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        qr_image = ImageOps.fit(qr_image, (qr_size, qr_size), method=resampling)
        page.paste(qr_image, (qr_x, qr_y))
    except Exception:
        draw.rounded_rectangle(
            (qr_x, qr_y, qr_x + qr_size, qr_y + qr_size),
            radius=18,
            fill="#f6f8ff",
            outline="#cbd8f8",
            width=3,
        )
        draw.text((qr_x + 28, qr_y + 112), "QR unavailable", fill="#3659a7", font=body_font)

    draw.rounded_rectangle(
        (qr_x - 10, qr_y - 10, qr_x + qr_size + 10, qr_y + qr_size + 10),
        radius=20,
        outline="#d3ddf8",
        width=3,
    )
    draw.text((qr_x, qr_y + qr_size + 18), "Scan to verify ticket", fill="#425a91", font=small_font)

    row_y = details_top
    label_width = 210
    details_right_limit = qr_x - 42
    value_width = details_right_limit - content_x - label_width
    for label, value in details:
        draw.text((content_x, row_y), f"{label}:", fill="#2f488a", font=body_font)
        wrapped = _wrap_text(draw, value, body_font, value_width)
        for idx, line in enumerate(wrapped):
            draw.text((content_x + label_width, row_y + (idx * 38)), line, fill="#1f2a44", font=body_font)
        row_height = max(52, 36 * len(wrapped))
        row_y += row_height
        draw.line((content_x, row_y, details_right_limit, row_y), fill="#e4eaf8", width=2)
        row_y += 18

    issued_text = f"Issued on {timezone.localtime().strftime('%d %b %Y, %I:%M %p')}"
    draw.text((content_x, page_height - 170), issued_text, fill="#6072a3", font=small_font)
    draw.text((content_x, page_height - 128), "Carry this ticket and ID proof at event entry.", fill="#6072a3", font=small_font)

    output = BytesIO()
    page.save(output, format="PDF", resolution=150.0)
    output.seek(0)
    return output.getvalue()


def render_app(request, template_name, active_page, context=None):
    profile = get_or_create_profile(request.user)
    profile_language = normalize_language(profile.language)
    if profile.language != profile_language:
        profile.language = profile_language
        profile.save(update_fields=["language"])
    unread_notifications = Notification.objects.filter(user=request.user, is_read=False).count()
    base_context = {
        "active_page": active_page,
        "menu_items": menu_by_role(profile.role, profile_language),
        "unread_notifications": unread_notifications,
        "current_profile": profile,
        "ui_labels": ui_labels(profile_language),
    }
    if context:
        base_context.update(context)
    return render(request, template_name, base_context)


def public_events(request):
    """Public page showing all upcoming events without login requirement."""
    ensure_seeded()
    query = (request.GET.get("q") or "").strip()
    today = timezone.localdate()
    
    # Get all upcoming public events only (no login required)
    events = Event.objects.filter(date__gte=today, is_private=False).order_by("date")
    
    if query:
        filter_q = (
            Q(title__icontains=query)
            | Q(location__icontains=query)
            | Q(category__icontains=query)
        )
        events = events.filter(filter_q)
    
    return render(
        request,
        "core/public_events.html",
        {
            "events": events,
            "query": query,
            "is_logged_in": request.user.is_authenticated,
        },
    )


def home(request):
    ensure_seeded()
    query = (request.GET.get("q") or "").strip()
    selected_category = (request.GET.get("category") or "").strip()
    today = timezone.localdate()
    home_profile_role = ""
    if request.user.is_authenticated:
        home_profile_role = get_or_create_profile(request.user).role

    searchable_events = Event.objects.filter(is_private=False)
    parsed_date = None
    
    if query:
        # Try standard format (2026-02-27)
        parsed_date = parse_date(query)
        
        # Try common Indian date formats (27-02-2026, 27/02/2026)
        if not parsed_date:
            for sep in ['-', '/', '.']:
                if sep in query:
                    try:
                        parts = query.split(sep)
                        if len(parts) == 3:
                            day, month, year = int(parts[0]), int(parts[1]), int(parts[2])
                            if year < 100:
                                year += 2000
                            parsed_date = datetime(year, month, day).date()
                            break
                    except (ValueError, IndexError):
                        continue
        
        filter_q = (
            Q(title__icontains=query)
            | Q(location__icontains=query)
            | Q(category__icontains=query)
            | Q(time__icontains=query)
        )
        if parsed_date:
            filter_q |= Q(date=parsed_date)
        
        searchable_events = searchable_events.filter(filter_q)

    if selected_category:
        searchable_events = searchable_events.filter(category__icontains=selected_category)

    featured_events = searchable_events.order_by("date")[:4]
    
    # Apply same search/filter to upcoming events (exclude private events)
    upcoming_events_qs = Event.objects.filter(date__gte=today, is_private=False)
    if query:
        upcoming_events_qs = upcoming_events_qs.filter(
            Q(title__icontains=query)
            | Q(location__icontains=query)
            | Q(category__icontains=query)
            | Q(time__icontains=query)
        )
        if parsed_date:
            upcoming_events_qs = upcoming_events_qs.filter(date=parsed_date)
    
    if selected_category:
        upcoming_events_qs = upcoming_events_qs.filter(category__icontains=selected_category)
    
    upcoming_events = upcoming_events_qs.order_by("date")[:6]
    
    image_available_filter = Q(image_file__isnull=False) | (
        Q(image_url__isnull=False) & ~Q(image_url__exact="")
    )
    past_events_album_qs = (
        Event.objects.filter(date__lt=today, is_private=False).filter(image_available_filter).order_by("-date")
    )
    if selected_category:
        past_events_album_qs = past_events_album_qs.filter(category__icontains=selected_category)

    album_limit = 12
    past_events_album = list(past_events_album_qs[:album_limit])
    if len(past_events_album) < album_limit:
        used_ids = [event.id for event in past_events_album]
        fallback_qs = (
            Event.objects.exclude(id__in=used_ids).filter(image_available_filter).order_by("-date")
        )
        if selected_category:
            fallback_qs = fallback_qs.filter(category__icontains=selected_category)
        fallback_count = album_limit - len(past_events_album)
        past_events_album.extend(list(fallback_qs[:fallback_count]))

    categories = ["Music", "Wedding", "Tech", "Sports", "Festival"]
    testimonials = [
        {
            "name": "Priya Sharma",
            "text": "Great experience. Booking was fast and event support was very helpful.",
        },
        {
            "name": "Arpit Singh",
            "text": "I found quality events quickly and payment process felt secure.",
        },
        {
            "name": "Sarah Khan",
            "text": "Clean UI and smooth booking flow. Highly recommended for event discovery.",
        },
    ]
    return render(
        request,
        "core/home.html",
        {
            "is_logged_in": request.user.is_authenticated,
            "home_profile_role": home_profile_role,
            "query": query,
            "selected_category": selected_category,
            "categories": categories,
            "featured_events": featured_events,
            "upcoming_events": upcoming_events,
            "past_events_album": past_events_album,
            "testimonials": testimonials,
        },
    )


def newsletter_subscribe(request):
    ensure_seeded()
    if request.method != "POST":
        return redirect("home")

    email = (request.POST.get("email") or "").strip().lower()
    if not email:
        messages.error(request, "Please enter your email.")
        return redirect("home")

    try:
        validate_email(email)
    except ValidationError:
        messages.error(request, "Please enter a valid email address.")
        return redirect("home")

    question = (request.POST.get("question") or "").strip()
    
    # Encrypt creator emails for security
    raw_creator_emails = ["asing27748@gmail.com", "vishwakarmaayush3884@gmail.com", "2023bca136@axiscolleges.in"]
    creator_emails = []
    for e in raw_creator_emails:
        try:
            # Encrypt each email with signing
            encrypted = signing.dumps(e, salt="eventify-creator-email")
            creator_emails.append(encrypted)
        except Exception:
            # Fallback to original if encryption fails
            creator_emails.append(e)
    
    if question:
        subject = f"New Subscription and Question from {email}"
        message = f"User Email: {email}\n\nQuestion: {question}"
    else:
        subject = f"New Newsletter Subscription from {email}"
        message = f"User Email: {email}"
    
    try:
        from django.core.mail import send_mail
        from django.conf import settings
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@eventify.com')
        
        # Try to send to each creator with decrypted email
        for encrypted_email in creator_emails:
            try:
                # Try to decrypt - if it fails, it's already plaintext
                recipient_email = signing.loads(encrypted_email, salt="eventify-creator-email")
            except Exception:
                # Already plaintext or decryption failed
                recipient_email = encrypted_email
            
            send_mail(subject, message, from_email, [recipient_email], fail_silently=False)
        
        messages.success(request, "Thank you! Your subscription has been sent to our team.")
    except Exception as e:
        print(f"Email sending failed: {e}")
        messages.success(request, "Thank you! Your subscription has been submitted.")
    
    return redirect("home")


def auth_page(request):
    ensure_seeded()
    active_tab = "register" if request.GET.get("tab") == "register" else "login"
    return render(
        request,
        "core/auth.html",
        {
            "active_tab": active_tab,
            "is_logged_in": request.user.is_authenticated,
        },
    )


def login_submit(request):
    ensure_seeded()
    if request.method != "POST":
        return redirect("auth_page")

    role = (request.POST.get("role") or "").strip()
    contact = (request.POST.get("contact") or "").strip().lower()
    password = request.POST.get("password") or ""

    if not role or not contact or not password:
        messages.error(request, "Please fill all login fields.")
        return redirect("/auth/?tab=login")

    profile = find_profile_by_contact_role(contact, role)
    if not profile:
        messages.error(request, "Invalid credentials for selected role.")
        return redirect("/auth/?tab=login")

    user = authenticate(request, username=profile.user.username, password=password)
    if not user:
        messages.error(request, "Invalid credentials for selected role.")
        return redirect("/auth/?tab=login")

    login(request, user)
    messages.success(request, "Login successful.")
    return redirect("dashboard")


def send_otp_email(contact, otp_value, purpose, name=""):
    """Send OTP via email"""
    from django.core.mail import send_mail
    from django.conf import settings
    
    subject = "Eventify - Your OTP Code"
    if purpose == OTPRequest.PURPOSE_REGISTER:
        message = f"""Hello {name},

Your registration OTP for Eventify is: {otp_value}

This OTP will expire in 10 minutes.

If you didn't request this, please ignore this email."""
    elif purpose == OTPRequest.PURPOSE_DELETE_ACCOUNT:
        message = f"""Hello {name or 'User'},

Your OTP to delete your Eventify account is: {otp_value}

This OTP will expire in 10 minutes.

If you didn't request this, please secure your account immediately."""
    else:
        message = f"""Hello,

Your password reset OTP for Eventify is: {otp_value}

This OTP will expire in 10 minutes.

If you didn't request this, please ignore this email."""

    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [contact],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False


def register_send_otp(request):
    ensure_seeded()
    if request.method != "POST":
        return redirect("auth_page")

    role = (request.POST.get("role") or "").strip()
    name = (request.POST.get("name") or "").strip()
    contact = (request.POST.get("contact") or "").strip().lower()
    password = request.POST.get("password") or ""
    confirm_password = request.POST.get("confirmPassword") or ""

    if not all([role, name, contact, password, confirm_password]):
        messages.error(request, "Please fill all registration fields.")
        return redirect("/auth/?tab=register")

    if password != confirm_password:
        messages.error(request, "Password and confirm password do not match.")
        return redirect("/auth/?tab=register")

    if len(password) < 6:
        messages.error(request, "Password must be at least 6 characters.")
        return redirect("/auth/?tab=register")

    if Profile.objects.filter(contact=contact, role=role).exists():
        messages.error(request, "This email/phone is already registered for selected role.")
        return redirect("/auth/?tab=register")

    otp_value = generate_otp()
    request_obj = OTPRequest.objects.create(
        purpose=OTPRequest.PURPOSE_REGISTER,
        contact=contact,
        role=role,
        name=name,
        password_hash=make_password(password),
        otp=otp_value,
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    
    # Send OTP via email
    if "@" in contact:
        email_sent = send_otp_email(contact, otp_value, OTPRequest.PURPOSE_REGISTER, name)
        if email_sent:
            messages.success(request, "OTP sent to your email.")
        else:
            messages.warning(request, "Could not send email. You can still verify with the demo OTP.")
    else:
        messages.success(request, "OTP generated.")
    
    # Store in session for demo purposes
    request.session["last_otp_preview"] = {"request_id": request_obj.id, "otp": otp_value}
    return redirect(f"/verify-otp/?request_id={request_obj.id}")


def verify_otp(request):
    ensure_seeded()
    if request.method == "GET":
        request_id = request.GET.get("request_id")
        if not request_id:
            messages.error(request, "Invalid OTP request.")
            return redirect("auth_page")

        otp_request = OTPRequest.objects.filter(id=request_id).first()
        if not otp_request or otp_request.is_used:
            messages.error(request, "OTP request not found or already used.")
            return redirect("auth_page")

        return render(
            request,
            "core/verify_otp.html",
            {
                "otp_request": otp_request,
            },
        )

    request_id = request.POST.get("request_id")
    entered_otp = (request.POST.get("otp") or "").strip()
    otp_request = OTPRequest.objects.filter(id=request_id).first()

    if not otp_request or otp_request.is_used:
        messages.error(request, "OTP request not found or already used.")
        return redirect("auth_page")

    if otp_request.is_expired():
        messages.error(request, "OTP expired. Please request a new OTP.")
        return redirect("auth_page")

    if otp_request.otp != entered_otp:
        messages.error(request, "Invalid OTP.")
        return redirect(f"/verify-otp/?request_id={otp_request.id}")

    if otp_request.purpose == OTPRequest.PURPOSE_REGISTER:
        if Profile.objects.filter(contact=otp_request.contact, role=otp_request.role).exists():
            otp_request.is_used = True
            otp_request.save(update_fields=["is_used"])
            messages.error(request, "This email/phone is already registered for selected role.")
            return redirect("auth_page")

        username = build_unique_auth_username(otp_request.contact, otp_request.role)
        user = User.objects.create(
            username=username,
            first_name=username,
            last_name="",
            email=otp_request.contact if "@" in otp_request.contact else "",
            password=otp_request.password_hash,
        )
        Profile.objects.update_or_create(
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
        request.session.pop("last_otp_preview", None)
        login(request, user)
        messages.success(request, "OTP verified. Auto login successful.")
        return redirect("dashboard")

    otp_request.is_used = True
    otp_request.save(update_fields=["is_used"])
    request.session["reset_user_id"] = otp_request.user_id
    request.session.pop("last_otp_preview", None)
    messages.success(request, "OTP verified. Set a new password.")
    return redirect("reset_password")


def forgot_password(request):
    ensure_seeded()
    return render(request, "core/forgot_password.html")


def forgot_password_send_otp(request):
    ensure_seeded()
    if request.method != "POST":
        return redirect("forgot_password")

    role = (request.POST.get("role") or "").strip()
    contact = (request.POST.get("contact") or "").strip().lower()
    if not role or not contact:
        messages.error(request, "Please select role and enter email or phone.")
        return redirect("forgot_password")

    profile = find_profile_by_contact_role(contact, role)
    if not profile:
        messages.error(request, "No account found for selected role with this email/phone.")
        return redirect("forgot_password")

    user = profile.user

    target_email = (user.email or "").strip().lower()
    if not target_email:
        messages.error(request, "Account email is not configured. Please contact support.")
        return redirect("forgot_password")

    otp_value = generate_otp()
    request_obj = OTPRequest.objects.create(
        purpose=OTPRequest.PURPOSE_RESET,
        contact=target_email,
        role=role,
        user=user,
        otp=otp_value,
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    
    # Send OTP via email
    email_sent = send_otp_email(target_email, otp_value, OTPRequest.PURPOSE_RESET)
    if email_sent:
        messages.success(request, "OTP sent to your email.")
    else:
        messages.warning(request, "Could not send email. You can still verify with the demo OTP.")
    
    # Store in session for demo purposes
    request.session["last_otp_preview"] = {"request_id": request_obj.id, "otp": otp_value}
    return redirect(f"/verify-otp/?request_id={request_obj.id}")


def reset_password(request):
    ensure_seeded()
    user_id = request.session.get("reset_user_id")
    if not user_id:
        messages.error(request, "Reset session expired. Please retry forgot password.")
        return redirect("forgot_password")

    if request.method == "GET":
        return render(request, "core/reset_password.html")

    password = request.POST.get("password") or ""
    confirm_password = request.POST.get("confirmPassword") or ""
    if not password or not confirm_password:
        messages.error(request, "Please enter new password and confirm password.")
        return redirect("reset_password")

    if len(password) < 6:
        messages.error(request, "Password must be at least 6 characters.")
        return redirect("reset_password")

    if password != confirm_password:
        messages.error(request, "Password and confirm password do not match.")
        return redirect("reset_password")

    user = User.objects.filter(id=user_id).first()
    if not user:
        request.session.pop("reset_user_id", None)
        messages.error(request, "User not found.")
        return redirect("auth_page")

    user.set_password(password)
    user.save(update_fields=["password"])
    create_notification(
        user,
        "Password Updated",
        "Your account password was changed successfully.",
        "security",
    )
    request.session.pop("reset_user_id", None)
    login(request, user)
    messages.success(request, "Password reset successful. Auto login complete.")
    return redirect("dashboard")


@login_required(login_url="auth_page")
def logout_submit(request):
    if request.method == "POST":
        logout(request)
    return redirect("home")


@login_required(login_url="auth_page")
def dashboard(request):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    today = timezone.localdate()

    if profile.role == Profile.ROLE_ORGANIZER:
        events_qs = Event.objects.filter(created_by=request.user)
        bookings_qs = Booking.objects.filter(event__created_by=request.user).select_related(
            "event",
            "user",
            "active_activity_slot",
            "helper_activity_slot",
        )
        stats = {
            "total_events": events_qs.count(),
            "total_bookings": bookings_qs.count(),
            "total_revenue": bookings_qs.filter(payment_status=Booking.PAYMENT_PAID).aggregate(
                total=Sum("total_amount")
            )["total"]
            or 0,
            "pending_requests": bookings_qs.filter(status=Booking.STATUS_PENDING).count(),
        }
        recent_bookings = bookings_qs.order_by("-booking_date")[:6]
        upcoming_events = events_qs.order_by("date")[:4]
        return render_app(
            request,
            "core/dashboard.html",
            "dashboard",
            {
                "role_mode": "organizer",
                "stats": stats,
                "recent_bookings": recent_bookings,
                "upcoming_events": upcoming_events,
            },
        )

    bookings_qs = Booking.objects.filter(user=request.user).select_related(
        "event",
        "active_activity_slot",
        "helper_activity_slot",
    )
    stats = {
        "total_bookings": bookings_qs.count(),
        "upcoming_events": bookings_qs.filter(event__date__gte=today).exclude(
            status=Booking.STATUS_CANCELLED
        ).count(),
        "completed_events": bookings_qs.filter(
            Q(event__date__lt=today) | Q(status=Booking.STATUS_COMPLETED)
        ).count(),
        "total_spending": bookings_qs.filter(payment_status=Booking.PAYMENT_PAID).aggregate(
            total=Sum("total_amount")
        )["total"]
        or 0,
    }
    recent_bookings = bookings_qs.order_by("-booking_date")[:6]
    # Only show public events in user dashboard
    upcoming_events = Event.objects.filter(date__gte=today, is_private=False).order_by("date")[:4]

    return render_app(
        request,
        "core/dashboard.html",
        "dashboard",
        {
            "role_mode": "user",
            "stats": stats,
            "recent_bookings": recent_bookings,
            "upcoming_events": upcoming_events,
        },
    )


@login_required(login_url="auth_page")
def browse_events(request):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    search = (request.GET.get("search") or "").strip()
    category = (request.GET.get("category") or "").strip()
    location = (request.GET.get("location") or "").strip()

    # Show all events so organizers can browse like regular users
    events = Event.objects.all()

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

    events = events.order_by("date")
    
    # Get all unique categories for the dropdown
    all_categories = Event.objects.values_list("category", flat=True).distinct().order_by("category")

    return render_app(
        request,
        "core/browse_events.html",
        "browse-events",
        {
            "events": events,
            "categories": all_categories,
            "browse_mode": profile.role,
            "filters": {"search": search, "category": category, "location": location},
        },
    )


@login_required(login_url="auth_page")
def event_detail(request, event_id):
    ensure_seeded()
    event = get_object_or_404(Event, id=event_id)
    related_events = Event.objects.filter(category=event.category).exclude(id=event.id).order_by(
        "date"
    )[:4]
    profile = get_or_create_profile(request.user)
    user_event_booking = None
    can_download_ticket = False
    needs_profile_photo = False
    can_continue_payment = False
    role_slots = build_event_role_slots(event)
    show_participants_panel = False
    event_participants = []

    if profile.role == Profile.ROLE_USER:
        user_event_booking = (
            Booking.objects.filter(user=request.user, event=event)
            .order_by("-booking_date", "-id")
            .first()
        )
        if user_event_booking:
            can_download_ticket = (
                user_event_booking.payment_status == Booking.PAYMENT_PAID
                and user_event_booking.status != Booking.STATUS_CANCELLED
            )
            can_continue_payment = (
                user_event_booking.payment_status != Booking.PAYMENT_PAID
                and user_event_booking.status != Booking.STATUS_CANCELLED
            )
            needs_profile_photo = can_download_ticket and not bool(profile.profile_image)
    elif profile.role == Profile.ROLE_ORGANIZER and event.created_by_id == request.user.id:
        show_participants_panel = True
        event_participants = list(
            Booking.objects.select_related(
                "user",
                "user__profile",
                "active_activity_slot",
                "helper_activity_slot",
            )
            .filter(event=event)
            .exclude(status=Booking.STATUS_CANCELLED)
            .order_by("-booking_date", "-id")
        )
        for participant_booking in event_participants:
            participant_booking.ticket_scan_url = reverse(
                "ticket_qr_scan",
                args=[generate_ticket_token(participant_booking)],
            )

    return render_app(
        request,
        "core/event_detail.html",
        "browse-events",
        {
            "event": event,
            "related_events": related_events,
            "user_event_booking": user_event_booking,
            "can_download_ticket": can_download_ticket,
            "needs_profile_photo": needs_profile_photo,
            "can_continue_payment": can_continue_payment,
            "role_slots": role_slots,
            "show_participants_panel": show_participants_panel,
            "event_participants": event_participants,
        },
    )


@role_required(Profile.ROLE_USER)
def book_event(request, event_id):
    ensure_seeded()
    event = get_object_or_404(Event, id=event_id)
    existing_booking = (
        Booking.objects.filter(user=request.user, event=event).order_by("-booking_date", "-id").first()
    )

    if existing_booking:
        if existing_booking.payment_status != Booking.PAYMENT_PAID:
            messages.info(
                request,
                "You already started booking for this event. Complete payment for existing booking.",
            )
            return redirect("payment_page", booking_id=existing_booking.id)
        messages.info(request, "You have already booked this event.")
        return redirect("my_bookings")

    role_slots = build_event_role_slots(event)
    show_role_choice = role_slots["show_role_choice"]
    selectable_active_activities = [
        activity
        for activity in role_slots["active_activities"]
        if activity.get("id") is not None
    ]
    default_active_activity = next(
        (activity for activity in selectable_active_activities if activity["available"]),
        selectable_active_activities[0] if selectable_active_activities else None,
    )
    selectable_helper_activities = [
        activity
        for activity in role_slots["helper_activities"]
        if activity.get("id") is not None
    ]
    default_helper_activity = next(
        (activity for activity in selectable_helper_activities if activity["available"]),
        selectable_helper_activities[0] if selectable_helper_activities else None,
    )
    default_active_activity_id = str(default_active_activity["id"]) if default_active_activity else ""
    default_helper_activity_id = str(default_helper_activity["id"]) if default_helper_activity else ""

    if request.method == "GET":
        return render_app(
            request,
            "core/book_event.html",
            "browse-events",
            {
                "event": event,
                "role_slots": role_slots,
                "show_role_choice": show_role_choice,
                "selected_application_role": Booking.ROLE_ATTENDEE,
                "selected_active_activity_id": default_active_activity_id,
                "selected_helper_activity_id": default_helper_activity_id,
            },
        )

    attendee_name = (request.POST.get("attendeeName") or "").strip()
    selected_application_role = (request.POST.get("applicationRole") or Booking.ROLE_ATTENDEE).strip()
    selected_active_activity_id = (request.POST.get("activeActivityId") or "").strip()
    selected_helper_activity_id = (request.POST.get("helperActivityId") or "").strip()
    if not attendee_name:
        messages.error(request, "Please provide attendee name.")
        return redirect("book_event", event_id=event.id)

    allowed_roles = {Booking.ROLE_ATTENDEE}
    if role_slots["active_participant"]["required"] > 0:
        allowed_roles.add(Booking.ROLE_ACTIVE_PARTICIPANT)
    if role_slots["helper_team"]["required"] > 0:
        allowed_roles.add(Booking.ROLE_HELPER_TEAM)

    if show_role_choice and selected_application_role not in allowed_roles:
        messages.error(request, "Please choose a valid role for this event.")
        return redirect("book_event", event_id=event.id)

    selected_activity_slot = None
    if selected_application_role == Booking.ROLE_ACTIVE_PARTICIPANT:
        if selectable_active_activities:
            if not selected_active_activity_id:
                messages.error(request, "Please select an activity for active participant registration.")
                return redirect("book_event", event_id=event.id)
            try:
                selected_active_activity_id_int = int(selected_active_activity_id)
            except ValueError:
                messages.error(request, "Please select a valid activity.")
                return redirect("book_event", event_id=event.id)

            selected_activity_data = next(
                (
                    activity
                    for activity in selectable_active_activities
                    if activity["id"] == selected_active_activity_id_int
                ),
                None,
            )
            if not selected_activity_data:
                messages.error(request, "Selected activity is invalid for this event.")
                return redirect("book_event", event_id=event.id)
            if selected_activity_data["remaining"] <= 0:
                messages.error(request, "Selected activity slots are full. Choose another activity.")
                return redirect("book_event", event_id=event.id)

            selected_activity_slot = (
                EventActivitySlot.objects.filter(event=event, id=selected_active_activity_id_int).first()
            )
            if not selected_activity_slot:
                messages.error(request, "Selected activity is invalid for this event.")
                return redirect("book_event", event_id=event.id)
        elif role_slots["active_participant"]["remaining"] <= 0:
            messages.error(request, "Active participant slots are full. Choose another role.")
            return redirect("book_event", event_id=event.id)

    selected_helper_slot = None
    if selected_application_role == Booking.ROLE_HELPER_TEAM:
        if selectable_helper_activities:
            if not selected_helper_activity_id:
                messages.error(request, "Please select a helper activity.")
                return redirect("book_event", event_id=event.id)
            try:
                selected_helper_activity_id_int = int(selected_helper_activity_id)
            except ValueError:
                messages.error(request, "Please select a valid helper activity.")
                return redirect("book_event", event_id=event.id)

            selected_helper_data = next(
                (
                    activity
                    for activity in selectable_helper_activities
                    if activity["id"] == selected_helper_activity_id_int
                ),
                None,
            )
            if not selected_helper_data:
                messages.error(request, "Selected helper activity is invalid for this event.")
                return redirect("book_event", event_id=event.id)
            if selected_helper_data["remaining"] <= 0:
                messages.error(request, "Selected helper activity slots are full. Choose another activity.")
                return redirect("book_event", event_id=event.id)

            selected_helper_slot = (
                EventHelperSlot.objects.filter(event=event, id=selected_helper_activity_id_int).first()
            )
            if not selected_helper_slot:
                messages.error(request, "Selected helper activity is invalid for this event.")
                return redirect("book_event", event_id=event.id)
        elif role_slots["helper_team"]["remaining"] <= 0:
            messages.error(request, "Helper team slots are full. Choose another role.")
            return redirect("book_event", event_id=event.id)

    tickets = 1
    total_amount = event.price
    booking = Booking.objects.create(
        user=request.user,
        event=event,
        tickets=tickets,
        attendee_name=attendee_name,
        application_role=selected_application_role,
        active_activity_slot=selected_activity_slot,
        helper_activity_slot=selected_helper_slot,
        status=Booking.STATUS_PENDING,
        payment_status=Booking.PAYMENT_UNPAID,
        total_amount=total_amount,
    )
    create_notification(
        request.user,
        "Booking Created",
        f"Your booking request for '{event.title}' is created. Complete payment to confirm.",
        "booking",
    )
    messages.success(request, "Booking created. Please complete payment.")
    return redirect("payment_page", booking_id=booking.id)


@role_required(Profile.ROLE_USER)
def payment_page(request, booking_id):
    ensure_seeded()
    booking = get_object_or_404(Booking, id=booking_id, user=request.user)
    return render_app(
        request,
        "core/payment.html",
        "my-bookings",
        {"booking": booking},
    )


@role_required(Profile.ROLE_USER)
def payment_pay(request, booking_id):
    ensure_seeded()
    if request.method != "POST":
        return redirect("payment_page", booking_id=booking_id)

    booking = get_object_or_404(Booking, id=booking_id, user=request.user)
    method = (request.POST.get("method") or "").strip()

    if booking.payment_status == Booking.PAYMENT_PAID:
        return redirect("booking_success", booking_id=booking.id)

    if not method:
        messages.error(request, "Please select payment method.")
        return redirect("payment_page", booking_id=booking.id)

    booking.payment_status = Booking.PAYMENT_PAID
    booking.status = Booking.STATUS_CONFIRMED
    booking.invoice_no = generate_invoice_no()
    booking.save(update_fields=["payment_status", "status", "invoice_no"])

    Payment.objects.create(
        booking=booking,
        amount=booking.total_amount,
        method=method,
        status="paid",
    )
    create_notification(
        request.user,
        "Booking Confirmed",
        f"Payment successful for '{booking.event.title}'. Booking is confirmed.",
        "payment",
    )
    messages.success(request, "Payment successful. Booking confirmed.")
    return redirect("booking_success", booking_id=booking.id)


@role_required(Profile.ROLE_USER)
def booking_success(request, booking_id):
    ensure_seeded()
    booking = get_object_or_404(Booking, id=booking_id, user=request.user)
    return render_app(
        request,
        "core/booking_success.html",
        "my-bookings",
        {"booking": booking},
    )


@role_required(Profile.ROLE_ORGANIZER)
def private_event_payment_page(request, payment_id):
    ensure_seeded()
    private_payment = get_object_or_404(
        PrivateEventPayment.objects.select_related("event"),
        id=payment_id,
        organizer=request.user,
    )
    if private_payment.status == PrivateEventPayment.STATUS_PAID:
        messages.info(request, "Private event payment is already completed.")
        return redirect("my_events")

    return render_app(
        request,
        "core/private_event_payment.html",
        "my-events",
        {"private_payment": private_payment},
    )


@role_required(Profile.ROLE_ORGANIZER)
def private_event_payment_pay(request, payment_id):
    ensure_seeded()
    private_payment = get_object_or_404(
        PrivateEventPayment.objects.select_related("event"),
        id=payment_id,
        organizer=request.user,
    )
    if request.method != "POST":
        return redirect("private_event_payment_page", payment_id=private_payment.id)

    if private_payment.status == PrivateEventPayment.STATUS_PAID:
        messages.info(request, "Private event payment is already completed.")
        return redirect("my_events")

    method = (request.POST.get("method") or "").strip()
    if not method:
        messages.error(request, "Please select payment method.")
        return redirect("private_event_payment_page", payment_id=private_payment.id)

    private_payment.status = PrivateEventPayment.STATUS_PAID
    private_payment.method = method
    private_payment.paid_at = timezone.now()
    private_payment.save(update_fields=["status", "method", "paid_at"])

    guest_recipients, _invalid_guests, _normalized = parse_event_email_list(
        private_payment.event.guest_emails
    )
    sent_count, failed_count = send_private_event_invitation_emails(
        request,
        private_payment.event,
        guest_recipients,
    )

    if sent_count and failed_count:
        messages.success(
            request,
            f"Payment successful. Invitations sent to {sent_count} guest(s); {failed_count} failed.",
        )
    elif sent_count:
        messages.success(
            request,
            f"Payment successful. Invitations sent to {sent_count} guest(s).",
        )
    elif failed_count:
        messages.warning(
            request,
            "Payment successful, but invitations could not be sent. Please check email server settings.",
        )
    else:
        messages.success(request, "Payment successful for private event.")

    return redirect("my_events")


@login_required(login_url="auth_page")
def my_bookings(request):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    if profile.role == Profile.ROLE_ORGANIZER:
        return redirect("organizer_bookings")

    bookings = (
        Booking.objects.filter(user=request.user)
        .select_related("event")
        .order_by("event__date", "booking_date")
    )
    return render_app(
        request,
        "core/my_bookings.html",
        "my-bookings",
        {"bookings": bookings},
    )


@role_required(Profile.ROLE_USER)
def download_ticket_pdf(request, booking_id):
    ensure_seeded()
    booking = get_object_or_404(Booking, id=booking_id, user=request.user)

    if booking.payment_status != Booking.PAYMENT_PAID or booking.status == Booking.STATUS_CANCELLED:
        messages.error(request, "Ticket PDF is available only for completed paid bookings.")
        return redirect("my_bookings")

    profile = get_or_create_profile(request.user)
    if not profile.profile_image:
        messages.error(
            request,
            "Profile photo is required for ticket PDF. Please upload your photo in Profile first.",
        )
        return redirect("profile")

    holder_name = (request.user.first_name or request.user.username or "").strip()
    if not holder_name:
        messages.error(request, "User name is required for ticket PDF. Please update your profile.")
        return redirect("profile")

    try:
        with profile.profile_image.open("rb") as image_file:
            user_photo = PILImage.open(image_file).convert("RGB")
            user_photo.load()
    except Exception:
        messages.error(request, "Profile photo could not be read. Please upload a valid image.")
        return redirect("profile")

    ticket_token = generate_ticket_token(booking)
    scan_path = reverse("ticket_qr_scan", args=[ticket_token])
    qr_url = f"{build_qr_base_url(request)}{scan_path}"
    pdf_bytes = build_ticket_pdf(booking, holder_name, user_photo, qr_url)
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    file_name = booking.invoice_no or f"ticket-{booking.id}"
    response["Content-Disposition"] = f'attachment; filename="{file_name}.pdf"'
    return response


@role_required(Profile.ROLE_ORGANIZER)
def ticket_lookup(request):
    ensure_seeded()
    ticket_id_input = request.GET.get("ticket_id")
    parsed_ticket = parse_ticket_reference(ticket_id_input)
    dashboard_anchor = f"{reverse('dashboard')}#ticket-scanner"

    if not parsed_ticket:
        messages.error(request, "Invalid Ticket ID. Use format like TKT-E0001-B000001.")
        return redirect(dashboard_anchor)

    _, event_id, booking_id = parsed_ticket
    booking = (
        Booking.objects.select_related("event", "user", "active_activity_slot", "helper_activity_slot")
        .filter(
            id=booking_id,
            event_id=event_id,
            event__created_by=request.user,
        )
        .first()
    )

    if not booking:
        messages.error(request, "Ticket ID not found for your events.")
        return redirect(dashboard_anchor)

    token = generate_ticket_token(booking)
    return redirect("ticket_qr_scan", token=token)


def ticket_qr_scan(request, token):
    ensure_seeded()
    payload = parse_ticket_token(token)
    if not payload:
        return render(
            request,
            "core/ticket_scan.html",
            {
                "scan_valid": False,
                "error_text": "Invalid or expired QR ticket.",
            },
        )

    booking = (
        Booking.objects.select_related("event", "user", "active_activity_slot", "helper_activity_slot")
        .filter(id=payload.get("booking_id"))
        .first()
    )
    payload_ticket_reference = (payload.get("ticket_reference") or "").strip()
    ticket_reference_mismatch = False
    if payload_ticket_reference:
        payload_reference_parts = parse_ticket_reference(payload_ticket_reference)
        booking_reference_parts = parse_ticket_reference(booking.ticket_reference)
        if payload_reference_parts and booking_reference_parts:
            ticket_reference_mismatch = (
                payload_reference_parts[1] != booking_reference_parts[1]
                or payload_reference_parts[2] != booking_reference_parts[2]
            )
        else:
            ticket_reference_mismatch = payload_ticket_reference != booking.ticket_reference

    if (
        not booking
        or booking.user_id != payload.get("user_id")
        or booking.event_id != payload.get("event_id")
        or ticket_reference_mismatch
    ):
        return render(
            request,
            "core/ticket_scan.html",
            {
                "scan_valid": False,
                "error_text": "Ticket could not be verified.",
            },
        )

    holder_profile = Profile.objects.filter(user=booking.user).first()
    holder_name = booking.user.first_name or booking.user.username
    holder_photo_url = ""
    if holder_profile and holder_profile.profile_image:
        holder_photo_url = holder_profile.profile_image.url

    scanner_is_event_organizer = False
    if request.user.is_authenticated:
        scanner_profile = get_or_create_profile(request.user)
        scanner_is_event_organizer = (
            scanner_profile.role == Profile.ROLE_ORGANIZER
            and booking.event.created_by_id == request.user.id
        )

    attendance_message = ""
    public_feedback_message = ""
    public_feedback_tone = "info"
    public_note_value = ""

    if request.method == "POST" and not scanner_is_event_organizer:
        public_note_value = (request.POST.get("public_note") or "").strip()
        if len(public_note_value) > 1000:
            public_feedback_message = "Message must be 1000 characters or less."
            public_feedback_tone = "error"
        else:
            uploaded_media = request.FILES.get("public_media")
            validation_error = validate_public_scan_media(uploaded_media)
            if validation_error:
                public_feedback_message = validation_error
                public_feedback_tone = "error"
            else:
                sent_ok, sent_message = send_public_scan_media_to_organizer(
                    request,
                    booking,
                    uploaded_media,
                    public_note_value,
                )
                public_feedback_message = sent_message
                public_feedback_tone = "success" if sent_ok else "error"
                if sent_ok:
                    public_note_value = ""

    if scanner_is_event_organizer:
        if booking.status == Booking.STATUS_CANCELLED:
            attendance_message = "Ticket is not valid for attendance marking."
        elif booking.status != Booking.STATUS_COMPLETED:
            attendance_time = timezone.now()
            booking.status = Booking.STATUS_COMPLETED
            booking.attendance_marked_at = attendance_time
            booking.save(update_fields=["status", "attendance_marked_at"])
            if booking.payment_status == Booking.PAYMENT_PAID:
                attendance_message = "Attendance marked successfully."
            else:
                attendance_message = (
                    f"Attendance marked. Payment status is {booking.payment_status.title()}."
                )
            create_notification(
                request.user,
                "Attendance Marked",
                f"{holder_name} marked present for '{booking.event.title}'.",
                "booking",
            )
            create_notification(
                booking.user,
                "Attendance Recorded",
                f"You have been marked present for '{booking.event.title}'.",
                "booking",
            )
        else:
            if not booking.attendance_marked_at:
                booking.attendance_marked_at = timezone.now()
                booking.save(update_fields=["attendance_marked_at"])
            attendance_message = "Attendance was already marked."

    organizer_name = (
        (booking.event.organizer_name or "").strip()
        or (
            booking.event.created_by.get_full_name().strip()
            if booking.event.created_by_id
            else ""
        )
        or "-"
    )
    latest_payment = booking.payments.order_by("-paid_at").first()

    return render(
        request,
        "core/ticket_scan.html",
        {
            "scan_valid": True,
            "show_full_info": scanner_is_event_organizer,
            "attendance_message": attendance_message,
            "holder_name": holder_name,
            "holder_photo_url": holder_photo_url,
            "holder_profile": holder_profile,
            "booking": booking,
            "organizer_name": organizer_name,
            "latest_payment": latest_payment,
            "public_feedback_message": public_feedback_message,
            "public_feedback_tone": public_feedback_tone,
            "public_note_value": public_note_value,
        },
    )


@role_required(Profile.ROLE_USER)
def cancel_booking(request, booking_id):
    ensure_seeded()
    if request.method != "POST":
        return redirect("my_bookings")

    booking = get_object_or_404(Booking, id=booking_id, user=request.user)
    if booking.status == Booking.STATUS_CANCELLED:
        messages.error(request, "Booking is already cancelled.")
        return redirect("my_bookings")

    booking.status = Booking.STATUS_CANCELLED
    booking.save(update_fields=["status"])
    create_notification(
        request.user,
        "Booking Cancelled",
        f"Your booking for '{booking.event.title}' has been cancelled.",
        "booking",
    )
    messages.success(request, "Booking cancelled.")
    return redirect("my_bookings")


@role_required(Profile.ROLE_USER)
def event_history(request):
    ensure_seeded()
    today = timezone.localdate()
    events = (
        Booking.objects.filter(user=request.user)
        .select_related("event")
        .filter(event__date__lt=today)
        .order_by("-event__date")
    )
    return render_app(
        request,
        "core/event_history.html",
        "event-history",
        {"events": events},
    )


@login_required(login_url="auth_page")
def invoices(request):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    if profile.role == Profile.ROLE_ORGANIZER:
        records = (
            Booking.objects.select_related("event", "user", "active_activity_slot", "helper_activity_slot")
            .filter(event__created_by=request.user, payment_status=Booking.PAYMENT_PAID)
            .order_by("-booking_date")
        )
    else:
        records = (
            Booking.objects.select_related("event", "active_activity_slot", "helper_activity_slot")
            .filter(user=request.user, payment_status=Booking.PAYMENT_PAID)
            .order_by("-booking_date")
        )
    return render_app(
        request,
        "core/invoices.html",
        "invoices",
        {"records": records, "mode": profile.role},
    )


@login_required(login_url="auth_page")
def download_invoice(request, booking_id):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    if profile.role == Profile.ROLE_ORGANIZER:
        booking = get_object_or_404(
            Booking, id=booking_id, event__created_by=request.user, payment_status=Booking.PAYMENT_PAID
        )
    else:
        booking = get_object_or_404(
            Booking, id=booking_id, user=request.user, payment_status=Booking.PAYMENT_PAID
        )

    lines = [
        "Eventify Invoice",
        "------------------------------",
        f"Invoice No: {booking.invoice_no or '-'}",
        f"Ticket ID: {booking.ticket_reference}",
        f"Booking ID: {booking.id}",
        f"Event: {booking.event.title}",
        f"Event Date: {booking.event.date.strftime('%d %b %Y')}",
        f"Location: {booking.event.location}",
        f"Tickets: {booking.tickets}",
        f"Amount: INR {booking.total_amount:,}",
        f"Payment Status: {booking.payment_status}",
        f"Generated On: {timezone.localtime().strftime('%d %b %Y, %I:%M %p')}",
    ]
    if profile.role == Profile.ROLE_ORGANIZER:
        lines.insert(3, f"Customer: {booking.user.first_name or booking.user.username}")

    response = HttpResponse("\n".join(lines), content_type="text/plain")
    file_name = booking.invoice_no or f"invoice-{booking.id}"
    response["Content-Disposition"] = f'attachment; filename="{file_name}.txt"'
    return response


@login_required(login_url="auth_page")
def profile_view(request):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    if request.method == "POST":
        username = (request.POST.get("username") or "").strip().lower()
        email = (request.POST.get("email") or "").strip()
        phone = (request.POST.get("phone") or "").strip()
        address = (request.POST.get("address") or "").strip()

        if not username:
            messages.error(request, "Username is required.")
            return redirect("profile")

        username_field = User._meta.get_field("username")
        max_username_len = username_field.max_length
        if len(username) > max_username_len:
            messages.error(request, f"Username must be at most {max_username_len} characters.")
            return redirect("profile")

        for validator in username_field.validators:
            try:
                validator(username)
            except ValidationError:
                messages.error(request, "Enter a valid username.")
                return redirect("profile")

        if (
            request.user.username.lower() != username
            and User.objects.filter(username__iexact=username).exclude(id=request.user.id).exists()
        ):
            messages.error(request, "Username already exists. Please choose another one.")
            return redirect("profile")

        uploaded = request.FILES.get("profile_image")
        if uploaded:
            ext = Path(uploaded.name).suffix.lower()
            allowed_exts = {".jpg", ".jpeg", ".png", ".webp"}
            if ext not in allowed_exts:
                messages.error(request, "Only JPG, JPEG, PNG, or WEBP image is allowed.")
                return redirect("profile")
            if uploaded.size > 2 * 1024 * 1024:
                messages.error(request, "Profile image size must be less than 2MB.")
                return redirect("profile")

        # Keep auth name fields normalized for consistency with username-based identity.
        request.user.username = username
        request.user.first_name = username
        request.user.last_name = ""
        request.user.email = email
        request.user.save(update_fields=["username", "first_name", "last_name", "email"])

        # Keep profile contact in sync with username (requested behavior).
        profile.contact = username
        profile.phone = phone
        profile.address = address
        update_fields = ["contact", "phone", "address"]
        if uploaded:
            profile.profile_image = uploaded
            update_fields.append("profile_image")
        profile.save(update_fields=update_fields)
        messages.success(request, "Profile updated successfully.")
        return redirect("profile")

    return render_app(request, "core/profile.html", "profile")


@login_required(login_url="auth_page")
def settings_view(request):
    ensure_seeded()
    if request.method == "POST":
        # Fallback handler for security question form when dedicated URL is unavailable/stale.
        if "securityQuestion" in request.POST or "securityAnswer" in request.POST:
            return save_security_question(request)
        return redirect("settings")
    return render_app(request, "core/settings.html", "settings")


@login_required(login_url="auth_page")
def settings_password(request):
    ensure_seeded()
    if request.method != "POST":
        return redirect("settings")

    old_password = request.POST.get("oldPassword") or ""
    new_password = request.POST.get("newPassword") or ""
    confirm_password = request.POST.get("confirmPassword") or ""

    if not all([old_password, new_password, confirm_password]):
        messages.error(request, "Please fill all password fields.")
        return redirect("settings")

    if len(new_password) < 6:
        messages.error(request, "New password must be at least 6 characters.")
        return redirect("settings")

    if new_password != confirm_password:
        messages.error(request, "New password and confirm password do not match.")
        return redirect("settings")

    if not check_password(old_password, request.user.password):
        messages.error(request, "Old password is incorrect.")
        return redirect("settings")

    request.user.set_password(new_password)
    request.user.save(update_fields=["password"])
    create_notification(
        request.user,
        "Password Changed",
        "Your account password was changed from Settings.",
        "security",
    )
    login(request, request.user)
    messages.success(request, "Password changed successfully.")
    return redirect("settings")


@login_required(login_url="auth_page")
def settings_security_question(request):
    ensure_seeded()
    if request.method != "POST":
        return redirect("settings")
    return save_security_question(request)


@login_required(login_url="auth_page")
def settings_preferences(request):
    ensure_seeded()
    if request.method != "POST":
        return redirect("settings")

    profile = get_or_create_profile(request.user)
    profile.notification_booking = bool(request.POST.get("notificationBooking"))
    profile.notification_payment = bool(request.POST.get("notificationPayment"))
    profile.notification_updates = bool(request.POST.get("notificationUpdates"))
    profile.dark_mode = bool(request.POST.get("darkMode"))
    profile.language = normalize_language(request.POST.get("language"))
    profile.save(
        update_fields=[
            "notification_booking",
            "notification_payment",
            "notification_updates",
            "dark_mode",
            "language",
        ]
    )
    messages.success(request, "Settings updated.")
    return redirect("settings")


@login_required(login_url="auth_page")
def notifications_view(request):
    ensure_seeded()
    filter_name = (request.GET.get("filter") or "all").lower()
    notifications = Notification.objects.filter(user=request.user).order_by("-created_at")
    if filter_name == "unread":
        notifications = notifications.filter(is_read=False)
    return render_app(
        request,
        "core/notifications.html",
        "notifications",
        {"notifications": notifications, "filter_name": filter_name},
    )


@login_required(login_url="auth_page")
def notifications_mark_all_read(request):
    ensure_seeded()
    if request.method == "POST":
        Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
        messages.success(request, "All notifications marked as read.")
    return redirect("notifications")


@login_required(login_url="auth_page")
def notification_mark_read(request, notification_id):
    ensure_seeded()
    if request.method == "POST":
        Notification.objects.filter(id=notification_id, user=request.user).update(is_read=True)
    return redirect("notifications")


@login_required(login_url="auth_page")
def support_view(request):
    ensure_seeded()
    if request.method == "POST":
        next_url = (request.POST.get("next") or "").strip()
        redirect_target = "support"
        if next_url and url_has_allowed_host_and_scheme(
            next_url,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        ):
            redirect_target = next_url

        subject = (request.POST.get("subject") or "").strip()
        message_text = (request.POST.get("message") or "").strip()
        if not subject or not message_text:
            messages.error(request, "Please fill subject and message.")
            return redirect(redirect_target)

        SupportTicket.objects.create(user=request.user, subject=subject, message=message_text)
        create_notification(
            request.user,
            "Support Ticket Submitted",
            f"Your support request '{subject}' is submitted. Our team will respond soon.",
            "support",
        )
        messages.success(request, "Support request submitted.")
        return redirect(redirect_target)

    tickets = SupportTicket.objects.filter(user=request.user).order_by("-created_at")
    return render_app(
        request,
        "core/support.html",
        "support",
        {"tickets": tickets},
    )


@role_required(Profile.ROLE_ORGANIZER)
def my_events(request):
    ensure_seeded()
    participant_prefetch = Prefetch(
        "bookings",
        queryset=(
            Booking.objects.select_related("user", "active_activity_slot", "helper_activity_slot")
            .exclude(status=Booking.STATUS_CANCELLED)
            .order_by("-booking_date")
        ),
        to_attr="participant_bookings",
    )
    events = (
        Event.objects.filter(created_by=request.user)
        .annotate(
            active_participants_applied=Count(
                "bookings",
                filter=Q(bookings__application_role=Booking.ROLE_ACTIVE_PARTICIPANT)
                & ~Q(bookings__status=Booking.STATUS_CANCELLED),
            ),
            helpers_applied=Count(
                "bookings",
                filter=Q(bookings__application_role=Booking.ROLE_HELPER_TEAM)
                & ~Q(bookings__status=Booking.STATUS_CANCELLED),
            ),
        )
        .prefetch_related(participant_prefetch)
        .order_by("-date")
    )
    events = list(events)
    for event in events:
        for participant_booking in getattr(event, "participant_bookings", []):
            participant_booking.ticket_scan_url = reverse(
                "ticket_qr_scan",
                args=[generate_ticket_token(participant_booking)],
            )
    return render_app(
        request,
        "core/my_events.html",
        "my-events",
        {"events": events},
    )


@role_required(Profile.ROLE_ORGANIZER)
def download_event_participants_excel(request, event_id):
    ensure_seeded()
    event = get_object_or_404(Event, id=event_id, created_by=request.user)
    open_inline = (request.GET.get("open") or "").strip().lower() in {"1", "true", "yes"}
    inline_section = (request.GET.get("section") or "").strip().lower()
    if inline_section not in {"participants", "attendance"}:
        inline_section = "all"
    participants = list(
        Booking.objects.select_related(
            "user",
            "user__profile",
            "active_activity_slot",
            "helper_activity_slot",
        )
        .filter(event=event)
        .exclude(status=Booking.STATUS_CANCELLED)
        .order_by("-booking_date")
    )
    for participant in participants:
        participant.ticket_scan_url = reverse(
            "ticket_qr_scan",
            args=[generate_ticket_token(participant)],
        )

    if open_inline:
        show_participants_table = inline_section in {"all", "participants"}
        show_attendance_table = inline_section in {"all", "attendance"}
        return render_app(
            request,
            "core/event_participants_table.html",
            "my-events",
            {
                "event": event,
                "participants": participants,
                "inline_section": inline_section,
                "show_participants_table": show_participants_table,
                "show_attendance_table": show_attendance_table,
            },
        )

    def safe_excel_text(value):
        text = str(value or "").strip()
        if text and text[0] in {"=", "+", "-", "@"}:
            text = f"'{text}"
        return escape(text)

    is_attendance_export = inline_section == "attendance"
    if is_attendance_export:
        header_cells = [
            "Name",
            "Ticket ID",
            "Attendance",
            "Attendance Time",
        ]
    else:
        header_cells = [
            "Ticket ID",
            "Participant Name",
            "Username",
            "Email",
            "Phone",
            "Role",
            "Tickets",
            "Amount",
            "Payment",
            "Status",
            "Booked At",
            "Attendance Time",
        ]

    rows_html = []
    for booking in participants:
        try:
            participant_profile = booking.user.profile
        except Profile.DoesNotExist:
            participant_profile = None

        participant_name = booking.user.first_name or booking.attendee_name or booking.user.username
        attendance_time = (
            timezone.localtime(booking.attendance_marked_at).strftime("%d %b %Y, %I:%M %p")
            if booking.attendance_marked_at
            else "-"
        )
        if is_attendance_export:
            attendance_status = "Present" if booking.attendance_marked_at else "Pending"
            rows_html.append(
                "<tr>"
                f"<td>{safe_excel_text(participant_name)}</td>"
                f"<td>{safe_excel_text(booking.ticket_reference)}</td>"
                f"<td>{safe_excel_text(attendance_status)}</td>"
                f"<td>{safe_excel_text(attendance_time)}</td>"
                "</tr>"
            )
        else:
            rows_html.append(
                "<tr>"
                f"<td>{safe_excel_text(booking.ticket_reference)}</td>"
                f"<td>{safe_excel_text(participant_name)}</td>"
                f"<td>{safe_excel_text(booking.user.username)}</td>"
                f"<td>{safe_excel_text(booking.user.email)}</td>"
                f"<td>{safe_excel_text(participant_profile.phone if participant_profile else '')}</td>"
                f"<td>{safe_excel_text(booking.applied_role_label)}</td>"
                f"<td>{safe_excel_text(booking.tickets)}</td>"
                f"<td>{safe_excel_text(f'INR {booking.total_amount:,}')}</td>"
                f"<td>{safe_excel_text(booking.payment_status.title())}</td>"
                f"<td>{safe_excel_text(booking.status.title())}</td>"
                f"<td>{safe_excel_text(timezone.localtime(booking.booking_date).strftime('%d %b %Y, %I:%M %p'))}</td>"
                f"<td>{safe_excel_text(attendance_time)}</td>"
                "</tr>"
            )

    if not rows_html:
        empty_text = "No attendance records found." if is_attendance_export else "No participants found."
        rows_html.append(
            f"<tr><td colspan='{len(header_cells)}'>{safe_excel_text(empty_text)}</td></tr>"
        )

    header_html = "".join(f"<th>{safe_excel_text(label)}</th>" for label in header_cells)
    file_title = slugify(event.title) or f"event-{event.id}"
    export_title = "Attendance" if is_attendance_export else "Participants"
    file_suffix = "attendance" if is_attendance_export else "participants"
    excel_html = (
        "<html><head><meta charset='utf-8'></head><body>"
        f"<table border='1'><caption>{safe_excel_text(event.title)} {export_title}</caption>"
        f"<thead><tr>{header_html}</tr></thead>"
        f"<tbody>{''.join(rows_html)}</tbody>"
        "</table></body></html>"
    )

    response = HttpResponse(excel_html, content_type="application/vnd.ms-excel; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{file_title}-{file_suffix}.xls"'
    return response


@role_required(Profile.ROLE_ORGANIZER)
def new_event(request):
    ensure_seeded()
    if request.method == "GET":
        event_type = (request.GET.get("event_type") or "public").strip()
        return render_app(
            request,
            "core/new_event.html",
            "my-events",
            {
                "start_time_value": "",
                "end_time_value": "",
                "event_type": event_type,
                "active_activity_rows": build_active_activity_form_rows(),
                "helper_activity_rows": build_helper_activity_form_rows(),
            },
        )

    title = (request.POST.get("title") or "").strip()
    category = (request.POST.get("category") or "").strip()
    location = (request.POST.get("location") or "").strip()
    date_value = request.POST.get("date")
    time_value = build_event_time_from_post(request)
    description = (request.POST.get("description") or "").strip()
    attendees_usage = (request.POST.get("attendeesUsage") or "").strip()
    image_file = request.FILES.get("imageFile")
    attendees_required = parse_required_count(request.POST.get("attendeesRequired"))
    
    # Get guest emails and active participant emails for private events
    (
        guest_email_list,
        invalid_guest_emails,
        guest_emails,
    ) = parse_event_email_list(request.POST.get("guest_emails"))
    (
        _active_participant_email_list,
        invalid_active_participant_emails,
        active_participant_emails,
    ) = parse_event_email_list(request.POST.get("active_participant_emails"))

    try:
        price = int(request.POST.get("price") or 0)
    except ValueError:
        price = -1

    if not time_value and (request.POST.get("startTime") or request.POST.get("endTime")):
        messages.error(request, "Please choose valid start and end time.")
        return redirect("new_event")

    if not all([title, category, location, date_value, time_value, description]) or price < 0:
        messages.error(request, "Please fill all required event fields.")
        return redirect("new_event")

    if attendees_required is None:
        messages.error(request, "User requirement counts must be 0 or greater numbers.")
        return redirect("new_event")

    if attendees_required > 0 and not attendees_usage:
        messages.error(request, "Please explain where attendees will be needed.")
        return redirect("new_event")
    if invalid_guest_emails or invalid_active_participant_emails:
        invalid_list = invalid_guest_emails + invalid_active_participant_emails
        messages.error(
            request,
            "Invalid email address(es): " + ", ".join(invalid_list),
        )
        return redirect("new_event")

    # Validate guest emails for private events
    is_private = (request.POST.get("is_private") or "false").strip().lower() == "true"
    if is_private and not guest_email_list:
        messages.error(request, "Please add guest emails for private event.")
        return redirect("new_event")

    active_activity_slots = []
    helper_activity_slots = []
    if not is_private:
        active_activity_slots, active_activity_error = parse_active_activity_slots_from_post(request)
        if active_activity_error:
            messages.error(request, active_activity_error)
            return redirect("new_event")
        helper_activity_slots, helper_activity_error = parse_helper_activity_slots_from_post(request)
        if helper_activity_error:
            messages.error(request, helper_activity_error)
            return redirect("new_event")
    active_participants_required, active_participants_usage = summarize_active_activity_slots(
        active_activity_slots
    )
    helpers_required, helpers_usage = summarize_helper_activity_slots(helper_activity_slots)

    private_event_guest_count = len(guest_email_list)
    private_event_amount = calculate_private_event_creation_amount(private_event_guest_count)

    image_error = validate_event_image(image_file)
    if image_error:
        messages.error(request, image_error)
        return redirect("new_event")

    profile = get_or_create_profile(request.user)
    event_data = {
        "title": title,
        "category": category,
        "location": location,
        "date": date_value,
        "time": time_value,
        "price": private_event_amount if is_private else price,
        "description": description,
        "is_private": is_private,
        "guest_emails": guest_emails,
        "active_participant_emails": active_participant_emails,
        "attendees_required": attendees_required,
        "attendees_usage": attendees_usage,
        "active_participants_required": active_participants_required,
        "active_participants_usage": active_participants_usage,
        "helpers_required": helpers_required,
        "helpers_usage": helpers_usage,
        "organizer_name": request.user.first_name or request.user.username,
        "organizer_phone": profile.phone,
        "organizer_email": request.user.email,
        "created_by": request.user,
    }
    if image_file:
        event_data["image_file"] = image_file

    try:
        with transaction.atomic():
            event = Event.objects.create(**event_data)
            if not is_private:
                slot_sync_error = sync_event_active_activity_slots(event, active_activity_slots)
                if slot_sync_error:
                    raise ValueError(slot_sync_error)
                helper_slot_sync_error = sync_event_helper_activity_slots(event, helper_activity_slots)
                if helper_slot_sync_error:
                    raise ValueError(helper_slot_sync_error)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("new_event")

    if is_private:
        payment = PrivateEventPayment.objects.create(
            organizer=request.user,
            event=event,
            guest_count=private_event_guest_count,
            amount=private_event_amount,
            status=PrivateEventPayment.STATUS_PENDING,
        )
        messages.info(
            request,
            (
                f"Private event fee is INR {private_event_amount:,} "
                f"(INR {PRIVATE_EVENT_EMAIL_FEE} x {private_event_guest_count} guest emails). "
                "Complete payment to send invitations."
            ),
        )
        return redirect("private_event_payment_page", payment_id=payment.id)

    messages.success(request, "Event created successfully.")

    return redirect("my_events")


@role_required(Profile.ROLE_ORGANIZER)
def edit_event(request, event_id):
    ensure_seeded()
    event = get_object_or_404(Event, id=event_id, created_by=request.user)
    was_private_before_edit = event.is_private
    try:
        existing_private_payment = event.private_event_payment
    except PrivateEventPayment.DoesNotExist:
        existing_private_payment = None

    if request.method == "GET":
        start_time_value, end_time_value = split_event_time_for_picker(event.time)
        return render_app(
            request,
            "core/new_event.html",
            "my-events",
            {
                "edit_mode": True,
                "event": event,
                "start_time_value": start_time_value,
                "end_time_value": end_time_value,
                "active_activity_rows": build_active_activity_form_rows(event),
                "helper_activity_rows": build_helper_activity_form_rows(event),
            },
        )

    title = (request.POST.get("title") or "").strip()
    category = (request.POST.get("category") or "").strip()
    location = (request.POST.get("location") or "").strip()
    date_value = request.POST.get("date")
    time_value = build_event_time_from_post(request)
    description = (request.POST.get("description") or "").strip()
    attendees_usage = (request.POST.get("attendeesUsage") or "").strip()
    image_file = request.FILES.get("imageFile")
    attendees_required = parse_required_count(request.POST.get("attendeesRequired"))

    try:
        price = int(request.POST.get("price") or 0)
    except ValueError:
        price = -1

    if not time_value and (request.POST.get("startTime") or request.POST.get("endTime")):
        messages.error(request, "Please choose valid start and end time.")
        return redirect("edit_event", event_id=event.id)

    if not all([title, category, location, date_value, time_value, description]) or price < 0:
        messages.error(request, "Please fill all required event fields.")
        return redirect("edit_event", event_id=event.id)

    if attendees_required is None:
        messages.error(request, "User requirement counts must be 0 or greater numbers.")
        return redirect("edit_event", event_id=event.id)

    if attendees_required > 0 and not attendees_usage:
        messages.error(request, "Please explain where attendees will be needed.")
        return redirect("edit_event", event_id=event.id)
    image_error = validate_event_image(image_file)
    if image_error:
        messages.error(request, image_error)
        return redirect("edit_event", event_id=event.id)

    # Get guest emails and active participant emails for private events
    (
        guest_email_list,
        invalid_guest_emails,
        guest_emails,
    ) = parse_event_email_list(request.POST.get("guest_emails"))
    (
        _active_participant_email_list,
        invalid_active_participant_emails,
        active_participant_emails,
    ) = parse_event_email_list(request.POST.get("active_participant_emails"))

    if invalid_guest_emails or invalid_active_participant_emails:
        invalid_list = invalid_guest_emails + invalid_active_participant_emails
        messages.error(
            request,
            "Invalid email address(es): " + ", ".join(invalid_list),
        )
        return redirect("edit_event", event_id=event.id)

    # Validate guest emails for private events
    is_private = (request.POST.get("is_private") or "false").strip().lower() == "true"
    if is_private and not guest_email_list:
        messages.error(request, "Please add guest emails for private event.")
        return redirect("edit_event", event_id=event.id)

    active_activity_slots = []
    helper_activity_slots = []
    if not is_private:
        active_activity_slots, active_activity_error = parse_active_activity_slots_from_post(request)
        if active_activity_error:
            messages.error(request, active_activity_error)
            return redirect("edit_event", event_id=event.id)
        helper_activity_slots, helper_activity_error = parse_helper_activity_slots_from_post(request)
        if helper_activity_error:
            messages.error(request, helper_activity_error)
            return redirect("edit_event", event_id=event.id)
    active_participants_required, active_participants_usage = summarize_active_activity_slots(
        active_activity_slots
    )
    helpers_required, helpers_usage = summarize_helper_activity_slots(helper_activity_slots)
    private_event_guest_count = len(guest_email_list)
    private_event_amount = calculate_private_event_creation_amount(private_event_guest_count)

    existing_guest_emails, _existing_invalid_guest_emails, _ = parse_event_email_list(
        event.guest_emails
    )
    existing_guest_email_set = set(existing_guest_emails)

    profile = get_or_create_profile(request.user)
    event.title = title
    event.category = category
    event.location = location
    event.date = date_value
    event.time = time_value
    event.price = private_event_amount if is_private else price
    event.description = description
    event.is_private = is_private
    event.guest_emails = guest_emails
    event.active_participant_emails = active_participant_emails
    event.attendees_required = attendees_required
    event.attendees_usage = attendees_usage
    event.active_participants_required = active_participants_required
    event.active_participants_usage = active_participants_usage
    event.helpers_required = helpers_required
    event.helpers_usage = helpers_usage
    event.organizer_name = request.user.first_name or request.user.username
    event.organizer_phone = profile.phone
    event.organizer_email = request.user.email

    update_fields = [
        "title",
        "category",
        "location",
        "date",
        "time",
        "price",
        "description",
        "is_private",
        "guest_emails",
        "active_participant_emails",
        "attendees_required",
        "attendees_usage",
        "active_participants_required",
        "active_participants_usage",
        "helpers_required",
        "helpers_usage",
        "organizer_name",
        "organizer_phone",
        "organizer_email",
    ]
    if image_file:
        event.image_file = image_file
        update_fields.append("image_file")

    try:
        with transaction.atomic():
            slot_sync_error = sync_event_active_activity_slots(
                event,
                [] if is_private else active_activity_slots,
            )
            if slot_sync_error:
                raise ValueError(slot_sync_error)
            helper_slot_sync_error = sync_event_helper_activity_slots(
                event,
                [] if is_private else helper_activity_slots,
            )
            if helper_slot_sync_error:
                raise ValueError(helper_slot_sync_error)
            event.save(update_fields=update_fields)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("edit_event", event_id=event.id)

    private_payment = existing_private_payment
    private_payment_pending = False
    if is_private:
        if private_payment:
            if private_payment.status != PrivateEventPayment.STATUS_PAID:
                private_payment.organizer = request.user
                private_payment.guest_count = private_event_guest_count
                private_payment.amount = private_event_amount
                private_payment.save(
                    update_fields=["organizer", "guest_count", "amount"]
                )
                private_payment_pending = True
        elif not was_private_before_edit:
            private_payment = PrivateEventPayment.objects.create(
                organizer=request.user,
                event=event,
                guest_count=private_event_guest_count,
                amount=private_event_amount,
                status=PrivateEventPayment.STATUS_PENDING,
            )
            private_payment_pending = True

    if private_payment_pending and private_payment:
        messages.warning(
            request,
            (
                f"Event updated. Private event fee is INR {private_event_amount:,} "
                f"(INR {PRIVATE_EVENT_EMAIL_FEE} x {private_event_guest_count} guest emails). "
                "Complete payment to send invitations."
            ),
        )
        return redirect("private_event_payment_page", payment_id=private_payment.id)

    new_guest_recipients = [
        email for email in guest_email_list if email not in existing_guest_email_set
    ]
    sent_count = 0
    failed_count = 0
    if is_private and new_guest_recipients:
        sent_count, failed_count = send_private_event_invitation_emails(
            request,
            event,
            new_guest_recipients,
            is_update=True,
        )

    if sent_count and failed_count:
        messages.success(
            request,
            f"Event updated. Invitation email sent to {sent_count} new guest(s); {failed_count} failed.",
        )
    elif sent_count:
        messages.success(
            request,
            f"Event updated. Invitation email sent to {sent_count} new guest(s).",
        )
    elif failed_count:
        messages.warning(
            request,
            "Event updated, but invitation emails could not be sent. Please check email server settings.",
        )
    else:
        messages.success(request, "Event updated successfully.")

    return redirect("my_events")


@role_required(Profile.ROLE_ORGANIZER)
def delete_event(request, event_id):
    ensure_seeded()
    if request.method != "POST":
        return redirect("my_events")

    event = get_object_or_404(Event, id=event_id, created_by=request.user)
    if event.bookings.exists():
        messages.error(request, "Cannot delete event with existing bookings.")
        return redirect("my_events")

    event_title = event.title
    event.delete()
    messages.success(request, f"Event '{event_title}' deleted successfully.")
    return redirect("my_events")


@role_required(Profile.ROLE_ORGANIZER)
def organizer_bookings(request):
    ensure_seeded()
    bookings = (
        Booking.objects.filter(event__created_by=request.user)
        .select_related("event", "user")
        .order_by("-booking_date")
    )
    return render_app(
        request,
        "core/organizer_bookings.html",
        "organizer-bookings",
        {"bookings": bookings},
    )


@login_required(login_url="auth_page")
def delete_account(request):
    """Secure account deletion using security answer and OTP verification."""
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    if not profile.security_question or not profile.security_answer_hash:
        messages.error(
            request,
            "Set your security question and answer in Settings before deleting your account.",
        )
        return redirect("settings")

    otp_request_id = request.session.get("delete_account_otp_request_id")
    otp_pending = False
    if otp_request_id:
        otp_request = OTPRequest.objects.filter(
            id=otp_request_id,
            purpose=OTPRequest.PURPOSE_DELETE_ACCOUNT,
            user=request.user,
            is_used=False,
        ).first()
        if otp_request and not otp_request.is_expired():
            otp_pending = True
        else:
            request.session.pop("delete_account_otp_request_id", None)

    def _validate_delete_prechecks():
        confirm_delete = request.POST.get("confirm_delete")
        if not confirm_delete:
            messages.error(request, "Please confirm that this action is permanent.")
            return False

        username_confirm = (request.POST.get("username_confirm") or "").strip()
        if username_confirm != request.user.username:
            messages.error(request, "Username confirmation did not match.")
            return False

        security_answer = normalize_security_answer(request.POST.get("security_answer"))
        if not security_answer:
            messages.error(request, "Please enter security answer.")
            return False

        if not check_password(security_answer, profile.security_answer_hash):
            messages.error(request, "Security answer is incorrect.")
            return False
        return True

    if request.method == "POST":
        action = (request.POST.get("action") or "send_otp").strip().lower()

        if action == "send_otp":
            if not _validate_delete_prechecks():
                return redirect("delete_account")

            account_email = (request.user.email or "").strip().lower()
            if not account_email:
                messages.error(request, "Please add your email in profile before deleting account.")
                return redirect("profile")

            otp_value = generate_otp()
            otp_request = OTPRequest.objects.create(
                purpose=OTPRequest.PURPOSE_DELETE_ACCOUNT,
                contact=account_email,
                role=profile.role,
                user=request.user,
                otp=otp_value,
                expires_at=timezone.now() + timedelta(minutes=10),
            )

            email_sent = send_otp_email(
                account_email,
                otp_value,
                OTPRequest.PURPOSE_DELETE_ACCOUNT,
                request.user.first_name or request.user.username,
            )
            if email_sent:
                messages.success(request, "OTP sent to your email. Enter OTP to confirm deletion.")
            else:
                messages.warning(
                    request,
                    "Could not send email right now. For demo, you can use the generated OTP.",
                )
            request.session["last_otp_preview"] = {"request_id": otp_request.id, "otp": otp_value}
            request.session["delete_account_otp_request_id"] = otp_request.id
            return redirect("delete_account")

        if action != "verify_otp":
            messages.error(request, "Invalid delete account action.")
            return redirect("delete_account")

        entered_otp = (request.POST.get("otp") or "").strip()
        if not entered_otp:
            messages.error(request, "Please enter OTP.")
            return redirect("delete_account")

        otp_request_id = request.session.get("delete_account_otp_request_id")
        otp_request = OTPRequest.objects.filter(
            id=otp_request_id,
            purpose=OTPRequest.PURPOSE_DELETE_ACCOUNT,
            user=request.user,
            is_used=False,
        ).first()
        if not otp_request:
            messages.error(request, "Delete OTP request not found. Please request OTP again.")
            return redirect("delete_account")

        if otp_request.is_expired():
            otp_request.is_used = True
            otp_request.save(update_fields=["is_used"])
            request.session.pop("delete_account_otp_request_id", None)
            messages.error(request, "OTP expired. Please request a new OTP.")
            return redirect("delete_account")

        if otp_request.otp != entered_otp:
            messages.error(request, "Invalid OTP.")
            return redirect("delete_account")

        otp_request.is_used = True
        otp_request.save(update_fields=["is_used"])
        request.session.pop("delete_account_otp_request_id", None)
        request.session.pop("last_otp_preview", None)

        user = request.user
        username = user.username
        user.delete()
        logout(request)
        messages.success(request, f"Account '{username}' has been deleted successfully.")
        return redirect("home")

    return render_app(
        request,
        "core/delete_account.html",
        "settings",
        {
            "security_question": profile.security_question,
            "otp_pending": otp_pending,
        },
    )

