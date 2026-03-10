"""
Views - Website ke sabhi pages ke functions yahan hote hain.
Har view ek specific page ke liye hai jaise home, dashboard, event detail, etc.
Views data le kar template ko render karte hain jo HTML mein dikhega user ko.
"""

from datetime import datetime, timedelta
import hashlib
from html import escape
from io import BytesIO
import mimetypes
from pathlib import Path
import re
import secrets
import socket

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.password_validation import validate_password
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
from django.utils.html import strip_tags
from django.utils.text import slugify
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils import timezone
from django.utils.dateparse import parse_date
from PIL import Image as PILImage, ImageDraw, ImageFont, ImageOps

from .decorators import role_required, admin_required
from .integrations import (
    IntegrationError,
    build_github_auth_url,
    build_google_auth_url,
    create_razorpay_order,
    exchange_github_code,
    exchange_google_code,
    fetch_github_emails,
    fetch_github_profile,
    fetch_google_profile,
    generate_oauth_state,
    get_github_oauth_config,
    get_google_oauth_config,
    oauth_provider_ready,
    razorpay_ready,
    verify_razorpay_signature,
)
from .models import (
    Booking,
    Event,
    EventActivitySlot,
    EventCategory,
    EventHelperSlot,
    EventGallery,
    EventSchedule,
    Notification,
    OTPRequest,
    Payment,
    PrivateEventPayment,
    Profile,
    PromoCode,
    SecurityAuditLog,
    SupportTicket,
    TicketType,
)
from .services import (
    create_notification,
    generate_invoice_no,
    generate_otp,
    get_trending_events,
    menu_by_role,
    normalize_language,
    seed_demo_data,
    ui_labels,
)
from .security import (
    build_qr_code_data_uri,
    build_totp_uri,
    generate_backup_codes,
    generate_totp_secret,
    verify_totp_code,
)
from .security_controls import (
    clear_failed_logins,
    format_lockout_message,
    get_login_lockout,
    initialize_secure_session,
    record_audit_log,
    record_failed_login,
    sanitize_text_input,
    validate_user_password,
)

# Global variables for demo data seeding
_seed_checked = False
PRIVATE_EVENT_EMAIL_FEE = 10  # Private event ke liye per guest fee
NEWSLETTER_CONTACT_RECIPIENTS = (  # Newsletter subscribe hone par email yahan jayega
    "vishwakarmaayush3884@gmail.com",
    "2023bca136@axiscolleges.in",
    "asing27748@gmail.com",
)


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


def clear_pending_2fa_session(request):
    request.session.pop("2fa_user_id", None)
    request.session.pop("2fa_expected_role", None)
    request.session.pop("2fa_auth_source", None)


def begin_second_factor_challenge(request, user, profile, auth_source="password"):
    request.session["2fa_user_id"] = user.id
    request.session["2fa_expected_role"] = profile.role
    request.session["2fa_auth_source"] = (auth_source or "password").strip()


def complete_login_after_primary_auth(request, user, profile, info_message=None, auth_source="password"):
    if profile.two_factor_enabled:
        begin_second_factor_challenge(request, user, profile, auth_source=auth_source)
        messages.info(
            request,
            "Two-factor code required. Enter your authenticator app code or a backup code to continue.",
        )
        return redirect("verify_2fa")

    clear_pending_2fa_session(request)
    login(request, user)
    initialize_secure_session(request)
    record_audit_log(
        action="login_success",
        summary=f"Successful {auth_source} login.",
        category="auth",
        status="success",
        request=request,
        user=user,
        metadata={"auth_source": auth_source, "role": profile.role},
    )
    if info_message:
        messages.info(request, info_message)
    elif user.email and not profile.email_verified:
        messages.warning(request, "Login successful. Please verify your email from Settings.")
    messages.success(request, "Login successful.")
    return redirect("dashboard")


def show_password_validation_error(request, password, *, user=None, redirect_name):
    try:
        validate_user_password(password, user=user)
    except ValidationError as exc:
        messages.error(request, " ".join(exc.messages))
        return redirect(redirect_name)
    return None


def ensure_totp_setup_material(profile):
    update_fields = []
    if not profile.two_factor_secret:
        profile.two_factor_secret = generate_totp_secret()
        update_fields.append("two_factor_secret")
    if not profile.two_factor_backup_codes:
        profile.two_factor_backup_codes = generate_backup_codes()
        update_fields.append("two_factor_backup_codes")
    if update_fields:
        profile.save(update_fields=update_fields)
    return profile


def build_2fa_setup_context(request, profile):
    ensure_totp_setup_material(profile)
    account_name = (request.user.email or request.user.username or "user").strip()
    otpauth_uri = build_totp_uri(profile.two_factor_secret, account_name)
    return {
        "secret": profile.two_factor_secret,
        "backup_codes": list(profile.two_factor_backup_codes or []),
        "otpauth_uri": otpauth_uri,
        "qr_code_data_uri": build_qr_code_data_uri(otpauth_uri),
    }


def _oauth_state_key(provider_slug):
    return f"oauth_{provider_slug}_state"


def _oauth_redirect_uri(request, url_name, setting_name):
    configured_uri = (getattr(settings, setting_name, "") or "").strip()
    if configured_uri:
        return configured_uri
    return request.build_absolute_uri(reverse(url_name))


def _render_social_login_setup_page(request, provider_name, setup_required=True, error_message=""):
    return render(
        request,
        "core/social_login.html",
        {
            "provider": provider_name,
            "setup_required": setup_required,
            "error_message": error_message,
        },
    )


def sync_social_user(provider_slug, provider_user_id, email, first_name="", last_name=""):
    normalized_provider_id = str(provider_user_id or "").strip()
    normalized_email = (email or "").strip().lower()
    if not normalized_provider_id:
        raise ValidationError("Provider user id is missing.")
    if not normalized_email or "@" not in normalized_email:
        raise ValidationError("A verified email address is required for social login.")

    provider_field = "google_id" if provider_slug == "google" else "github_id"
    profile = (
        Profile.objects.select_related("user")
        .filter(**{provider_field: normalized_provider_id})
        .first()
    )
    created = False

    if profile:
        user = profile.user
    else:
        user = User.objects.filter(email__iexact=normalized_email).order_by("id").first()
        if not user:
            username = build_unique_auth_username(normalized_email, Profile.ROLE_USER)
            user = User.objects.create_user(
                username=username,
                email=normalized_email,
                password=secrets.token_urlsafe(24),
                first_name=(first_name or normalized_email.split("@")[0])[:150],
                last_name=(last_name or "")[:150],
            )
            created = True
        profile = get_or_create_profile(user)

    user_updates = []
    if normalized_email and user.email != normalized_email:
        user.email = normalized_email
        user_updates.append("email")
    if first_name and user.first_name != first_name[:150]:
        user.first_name = first_name[:150]
        user_updates.append("first_name")
    if last_name and user.last_name != last_name[:150]:
        user.last_name = last_name[:150]
        user_updates.append("last_name")
    if user_updates:
        user.save(update_fields=user_updates)

    profile_updates = []
    if getattr(profile, provider_field) != normalized_provider_id:
        setattr(profile, provider_field, normalized_provider_id)
        profile_updates.append(provider_field)
    if created or not profile.contact or profile.contact == user.username:
        profile.contact = normalized_email
        profile_updates.append("contact")
    if not profile.email_verified:
        profile.email_verified = True
        profile_updates.append("email_verified")
    if profile_updates:
        profile.save(update_fields=profile_updates)

    if created:
        create_notification(
            user,
            "Welcome to Eventify",
            f"Your account has been created via {provider_slug.title()} login.",
            "system",
        )

    return user, profile, created


def validate_image_upload(uploaded_image, *, label, max_size_bytes):
    if not uploaded_image:
        return None

    ext = Path(uploaded_image.name).suffix.lower()
    allowed_exts = {".jpg", ".jpeg", ".png", ".webp"}
    if ext not in allowed_exts:
        return f"Only JPG, JPEG, PNG, or WEBP {label.lower()} files are allowed."

    content_type = (uploaded_image.content_type or "").lower()
    allowed_content_types = {"image/jpeg", "image/png", "image/webp"}
    if content_type and content_type not in allowed_content_types:
        return f"{label} content type is invalid."

    if uploaded_image.size > max_size_bytes:
        return f"{label} size must be less than {max_size_bytes // (1024 * 1024)}MB."

    try:
        uploaded_image.seek(0)
        with PILImage.open(uploaded_image) as image:
            image.verify()
        uploaded_image.seek(0)
    except Exception:
        try:
            uploaded_image.seek(0)
        except Exception:
            pass
        return f"{label} file is corrupted or unsupported."

    return None


def validate_event_image(uploaded_image):
    return validate_image_upload(
        uploaded_image,
        label="Event image",
        max_size_bytes=5 * 1024 * 1024,
    )


def parse_required_count(raw_value):
    try:
        count = int(raw_value or 0)
    except (TypeError, ValueError):
        return None
    if count < 0:
        return None
    return count


def parse_positive_int(raw_value, minimum=0):
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return None
    if parsed < minimum:
        return None
    return parsed


def parse_ticket_sales_datetime(raw_value):
    value = (raw_value or "").strip()
    if not value:
        return None, ""
    try:
        naive_value = datetime.strptime(value, "%Y-%m-%dT%H:%M")
    except ValueError:
        return None, "Invalid ticket sale date/time format."
    return timezone.make_aware(naive_value, timezone.get_current_timezone()), ""


def default_ticket_type_payloads(base_price):
    base = max(0, int(base_price or 0))
    vip_price = max(base + max(200, base // 2), base)
    early_bird_price = max(0, base - max(100, base // 5))
    return [
        {
            "id": None,
            "name": "VIP",
            "price": vip_price,
            "total_quantity": 50,
            "max_per_booking": 4,
            "sales_start": None,
            "sales_end": None,
            "display_order": 0,
        },
        {
            "id": None,
            "name": "Regular",
            "price": base,
            "total_quantity": 200,
            "max_per_booking": 8,
            "sales_start": None,
            "sales_end": None,
            "display_order": 1,
        },
        {
            "id": None,
            "name": "Early Bird",
            "price": early_bird_price,
            "total_quantity": 100,
            "max_per_booking": 6,
            "sales_start": None,
            "sales_end": None,
            "display_order": 2,
        },
    ]


def default_single_ticket_type_payload(base_price):
    base = max(0, int(base_price or 0))
    return [
        {
            "id": None,
            "name": "Regular",
            "price": base,
            "total_quantity": 200,
            "max_per_booking": 8,
            "sales_start": None,
            "sales_end": None,
            "display_order": 0,
            "is_active": True,
        }
    ]


def build_ticket_type_form_rows(event=None, fallback_price=0):
    if event:
        existing_rows = list(
            event.ticket_types.order_by("display_order", "price", "id").values(
                "id",
                "name",
                "price",
                "total_quantity",
                "available_quantity",
                "max_per_booking",
                "sales_start",
                "sales_end",
                "is_active",
            )
        )
        if existing_rows:
            return existing_rows
    return default_ticket_type_payloads(fallback_price)


def parse_ticket_types_from_post(request):
    ticket_ids = request.POST.getlist("ticketTypeId[]") or request.POST.getlist("ticketTypeId")
    names = request.POST.getlist("ticketTypeName[]") or request.POST.getlist("ticketTypeName")
    prices = request.POST.getlist("ticketTypePrice[]") or request.POST.getlist("ticketTypePrice")
    quantities = request.POST.getlist("ticketTypeQuantity[]") or request.POST.getlist("ticketTypeQuantity")
    max_per_booking_values = (
        request.POST.getlist("ticketTypeMaxPerBooking[]")
        or request.POST.getlist("ticketTypeMaxPerBooking")
    )
    sales_starts = request.POST.getlist("ticketTypeSalesStart[]") or request.POST.getlist("ticketTypeSalesStart")
    sales_ends = request.POST.getlist("ticketTypeSalesEnd[]") or request.POST.getlist("ticketTypeSalesEnd")

    if not any([ticket_ids, names, prices, quantities, max_per_booking_values, sales_starts, sales_ends]):
        return [], ""

    max_rows = max(
        len(ticket_ids),
        len(names),
        len(prices),
        len(quantities),
        len(max_per_booking_values),
        len(sales_starts),
        len(sales_ends),
    )

    parsed_rows = []
    for index in range(max_rows):
        raw_id = (ticket_ids[index] if index < len(ticket_ids) else "").strip()
        name = (names[index] if index < len(names) else "").strip()
        raw_price = (prices[index] if index < len(prices) else "").strip()
        raw_quantity = (quantities[index] if index < len(quantities) else "").strip()
        raw_max_per_booking = (
            max_per_booking_values[index] if index < len(max_per_booking_values) else ""
        ).strip()
        raw_sales_start = (sales_starts[index] if index < len(sales_starts) else "").strip()
        raw_sales_end = (sales_ends[index] if index < len(sales_ends) else "").strip()

        if not any([raw_id, name, raw_price, raw_quantity, raw_max_per_booking, raw_sales_start, raw_sales_end]):
            continue

        if not name:
            return None, "Ticket type name is required."

        price = parse_positive_int(raw_price, minimum=0)
        if price is None:
            return None, "Ticket type price must be a valid non-negative number."

        total_quantity = parse_positive_int(raw_quantity, minimum=1)
        if total_quantity is None:
            return None, "Ticket quantity must be at least 1."

        max_per_booking = parse_positive_int(raw_max_per_booking or "1", minimum=1)
        if max_per_booking is None:
            return None, "Max tickets per booking must be at least 1."
        max_per_booking = min(max_per_booking, total_quantity)

        sales_start, sales_start_error = parse_ticket_sales_datetime(raw_sales_start)
        if sales_start_error:
            return None, sales_start_error
        sales_end, sales_end_error = parse_ticket_sales_datetime(raw_sales_end)
        if sales_end_error:
            return None, sales_end_error
        if sales_start and sales_end and sales_end <= sales_start:
            return None, "Ticket sale end time must be after sale start time."

        ticket_type_id = None
        if raw_id:
            ticket_type_id = parse_positive_int(raw_id, minimum=1)
            if ticket_type_id is None:
                return None, "Invalid ticket type row received."

        parsed_rows.append(
            {
                "id": ticket_type_id,
                "name": name[:80],
                "price": price,
                "total_quantity": total_quantity,
                "max_per_booking": max_per_booking,
                "sales_start": sales_start,
                "sales_end": sales_end,
                "display_order": index,
                "is_active": True,
            }
        )

    if not parsed_rows:
        return None, "Please add at least one ticket type."
    return parsed_rows, ""


def sync_event_ticket_types(event, ticket_rows):
    existing_ticket_types = {item.id: item for item in event.ticket_types.all()}
    retained_ids = set()

    for payload in ticket_rows:
        row_id = payload.get("id")
        if row_id and row_id in existing_ticket_types:
            ticket_type = existing_ticket_types[row_id]
            sold_count = max(0, int(ticket_type.total_quantity or 0) - int(ticket_type.available_quantity or 0))
            if payload["total_quantity"] < sold_count:
                return (
                    f"Ticket type '{ticket_type.name}' total quantity cannot be less than already sold count "
                    f"({sold_count})."
                )

            ticket_type.name = payload["name"]
            ticket_type.price = payload["price"]
            ticket_type.total_quantity = payload["total_quantity"]
            ticket_type.available_quantity = max(0, payload["total_quantity"] - sold_count)
            ticket_type.max_per_booking = payload["max_per_booking"]
            ticket_type.sales_start = payload["sales_start"]
            ticket_type.sales_end = payload["sales_end"]
            ticket_type.display_order = payload["display_order"]
            ticket_type.is_active = payload["is_active"]
            ticket_type.save(
                update_fields=[
                    "name",
                    "price",
                    "total_quantity",
                    "available_quantity",
                    "max_per_booking",
                    "sales_start",
                    "sales_end",
                    "display_order",
                    "is_active",
                ]
            )
            retained_ids.add(ticket_type.id)
            continue

        created_ticket_type = TicketType.objects.create(
            event=event,
            name=payload["name"],
            price=payload["price"],
            total_quantity=payload["total_quantity"],
            available_quantity=payload["total_quantity"],
            max_per_booking=payload["max_per_booking"],
            sales_start=payload["sales_start"],
            sales_end=payload["sales_end"],
            display_order=payload["display_order"],
            is_active=payload["is_active"],
        )
        retained_ids.add(created_ticket_type.id)

    for existing_id, existing_ticket_type in existing_ticket_types.items():
        if existing_id in retained_ids:
            continue
        has_active_bookings = existing_ticket_type.bookings.exclude(status=Booking.STATUS_CANCELLED).exists()
        if has_active_bookings:
            existing_ticket_type.is_active = False
            existing_ticket_type.save(update_fields=["is_active"])
        else:
            existing_ticket_type.delete()
    return ""


def get_bookable_ticket_types(event):
    now = timezone.now()
    available_types = []
    for ticket_type in event.ticket_types.filter(is_active=True).order_by("display_order", "price", "id"):
        if int(ticket_type.available_quantity or 0) <= 0:
            continue
        if ticket_type.sales_start and now < ticket_type.sales_start:
            continue
        if ticket_type.sales_end and now > ticket_type.sales_end:
            continue
        available_types.append(ticket_type)
    return available_types


def generate_payment_reference(prefix="PAY"):
    stamp = timezone.localtime().strftime("%Y%m%d%H%M%S")
    micro_suffix = timezone.localtime().microsecond % 100000
    return f"{prefix}-{stamp}-{micro_suffix:05d}"


PAYMENT_METHODS = ("UPI", "Card", "Net Banking", "Wallet")
RAZORPAY_METHOD = "Razorpay"
PAYMENT_CONTEXT_MAX_AGE = 15 * 60
UPI_ID_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$")
CARD_NUMBER_PATTERN = re.compile(r"^\d{12,19}$")
CARD_CVV_PATTERN = re.compile(r"^\d{3,4}$")
CARD_EXPIRY_PATTERN = re.compile(r"^(0[1-9]|1[0-2])\s*/\s*(\d{2}|\d{4})$")
ACCOUNT_NUMBER_PATTERN = re.compile(r"^\d{8,18}$")
MOBILE_NUMBER_PATTERN = re.compile(r"^\d{10,12}$")


def get_gateway_payment_id(method):
    method_code = slugify(method or "pay").replace("-", "").upper() or "PAY"
    return generate_payment_reference(method_code)


def sign_gateway_context(payload, salt):
    return signing.dumps(payload, salt=salt)


def load_gateway_context(token, salt, max_age=PAYMENT_CONTEXT_MAX_AGE):
    return signing.loads(token, salt=salt, max_age=max_age)


def is_valid_upi_id(value):
    return bool(UPI_ID_PATTERN.match((value or "").strip()))


def digits_only(value):
    return re.sub(r"\D", "", (value or "").strip())


def is_valid_card_number(value):
    card_number = digits_only(value)
    if not CARD_NUMBER_PATTERN.match(card_number):
        return False

    total = 0
    reverse_digits = card_number[::-1]
    for index, digit in enumerate(reverse_digits):
        number = int(digit)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def normalize_card_expiry(value):
    raw = (value or "").strip()
    match = CARD_EXPIRY_PATTERN.match(raw)
    if not match:
        return ""

    month = int(match.group(1))
    year = int(match.group(2))
    if year < 100:
        year += 2000
    today = timezone.localdate()
    if (year, month) < (today.year, today.month):
        return ""
    return f"{month:02d}/{str(year)[-2:]}"


def mask_last4(value):
    digits = digits_only(value)
    if not digits:
        return ""
    return digits[-4:]


def extract_payment_details(request, method):
    if method == "UPI":
        upi_id = (request.POST.get("upiId") or "").strip().lower()
        if not upi_id:
            return None, "Please enter your UPI ID."
        if not is_valid_upi_id(upi_id):
            return None, "Please enter a valid UPI ID (example: user@bank)."
        return {
            "upi_id": upi_id,
            "payment_meta": {"upi_id": upi_id},
        }, ""

    if method == "Card":
        card_holder_name = (request.POST.get("cardHolderName") or "").strip()
        card_number = digits_only(request.POST.get("cardNumber"))
        card_expiry = normalize_card_expiry(request.POST.get("cardExpiry"))
        card_cvv = digits_only(request.POST.get("cardCvv"))
        if not all([card_holder_name, card_number, card_expiry, card_cvv]):
            return None, "Please fill all card details."
        if not is_valid_card_number(card_number):
            return None, "Please enter a valid card number."
        if not CARD_CVV_PATTERN.match(card_cvv):
            return None, "Please enter a valid CVV."
        return {
            "upi_id": "",
            "payment_meta": {
                "card_holder_name": card_holder_name,
                "card_last4": card_number[-4:],
                "card_expiry": card_expiry,
            },
        }, ""

    if method == "Net Banking":
        bank_name = (request.POST.get("bankName") or "").strip()
        account_holder_name = (request.POST.get("accountHolderName") or "").strip()
        account_number = digits_only(request.POST.get("accountNumber"))
        if not all([bank_name, account_holder_name, account_number]):
            return None, "Please fill all net banking details."
        if not ACCOUNT_NUMBER_PATTERN.match(account_number):
            return None, "Please enter a valid account number."
        return {
            "upi_id": "",
            "payment_meta": {
                "bank_name": bank_name,
                "account_holder_name": account_holder_name,
                "account_last4": account_number[-4:],
            },
        }, ""

    if method == "Wallet":
        wallet_provider = (request.POST.get("walletProvider") or "").strip()
        wallet_mobile = digits_only(request.POST.get("walletMobile"))
        if not all([wallet_provider, wallet_mobile]):
            return None, "Please fill all wallet details."
        if not MOBILE_NUMBER_PATTERN.match(wallet_mobile):
            return None, "Please enter a valid wallet mobile number."
        return {
            "upi_id": "",
            "payment_meta": {
                "wallet_provider": wallet_provider,
                "wallet_mobile_last4": wallet_mobile[-4:],
            },
        }, ""

    return None, "Please select a valid payment method."


def find_active_promo(code):
    normalized_code = (code or "").strip().upper()
    if not normalized_code:
        return None
    return PromoCode.objects.filter(code__iexact=normalized_code, active=True).first()


def validate_promo_for_amount(code, amount):
    normalized_code = (code or "").strip().upper()
    if not normalized_code:
        return None, 0, ""

    promo = PromoCode.objects.filter(code__iexact=normalized_code).first()
    if not promo:
        return None, 0, "Promo code not found."
    if not promo.can_use():
        if promo.is_expired:
            return None, 0, "Promo code has expired."
        if promo.max_uses and promo.used_count >= promo.max_uses:
            return None, 0, "Promo code usage limit reached."
        return None, 0, "Promo code is inactive."

    discount_amount = promo.calculate_discount(amount)
    if discount_amount <= 0:
        return None, 0, "Promo code is not valid for this amount."
    return promo, discount_amount, ""


def build_ticket_holder_name(user):
    return (user.first_name or user.get_full_name().strip() or user.username or "Guest").strip()


def build_placeholder_profile_image(holder_name):
    avatar_size = 700
    image = PILImage.new("RGB", (avatar_size, avatar_size), "#dbe6ff")
    draw = ImageDraw.Draw(image)
    initials = "".join(part[:1].upper() for part in holder_name.split()[:2] if part) or "EV"
    radius = int(avatar_size * 0.44)
    center = avatar_size // 2
    draw.ellipse(
        (center - radius, center - radius, center + radius, center + radius),
        fill="#4a73d3",
    )
    font = _load_font(210, bold=True)
    text_width = draw.textlength(initials, font=font)
    text_height = 210
    text_x = int((avatar_size - text_width) / 2)
    text_y = int((avatar_size - text_height) / 2) - 12
    draw.text((text_x, text_y), initials, fill="#ffffff", font=font)
    return image


def load_ticket_holder_photo(user):
    profile = get_or_create_profile(user)
    if profile.profile_image:
        try:
            with profile.profile_image.open("rb") as image_file:
                user_photo = PILImage.open(image_file).convert("RGB")
                user_photo.load()
                return user_photo
        except Exception:
            pass
    return build_placeholder_profile_image(build_ticket_holder_name(user))


def send_booking_ticket_email(request, booking, payment):
    recipient = (booking.user.email or "").strip()
    if not recipient:
        return False

    holder_name = build_ticket_holder_name(booking.user)
    user_photo = load_ticket_holder_photo(booking.user)
    ticket_token = generate_ticket_token(booking)
    scan_path = reverse("ticket_qr_scan", args=[ticket_token])
    qr_url = f"{build_qr_base_url(request)}{scan_path}"
    ticket_pdf = build_ticket_pdf(booking, holder_name, user_photo, qr_url)
    payment_time = timezone.localtime(payment.paid_at).strftime("%d %b %Y, %I:%M %p") if payment.paid_at else "-"
    body = "\n".join(
        [
            "Your payment was successful.",
            "",
            f"Event: {booking.event.title}",
            f"Ticket ID: {booking.ticket_reference}",
            f"Invoice No: {booking.invoice_no or '-'}",
            f"Transaction ID: {payment.transaction_ref or '-'}",
            f"Amount Paid: INR {int(payment.amount or 0):,}",
            f"Payment Time: {payment_time}",
            "",
            "Your ticket PDF is attached with this email.",
        ]
    )
    from_email = (
        (getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip()
        or (getattr(settings, "EMAIL_HOST_USER", "") or "").strip()
        or "webmaster@localhost"
    )
    try:
        email = EmailMessage(
            subject=f"Eventify Payment Confirmation | {booking.event.title}",
            body=body,
            from_email=from_email,
            to=[recipient],
        )
        email.attach(f"{booking.ticket_reference}.pdf", ticket_pdf, "application/pdf")
        email.send(fail_silently=False)
        return True
    except Exception:
        return False


def log_failed_payment(
    booking,
    method,
    reason,
    coupon_code="",
    gateway_provider="Eventify Local Gateway",
    gateway_payment_id="",
    verification_signature="",
    payment_meta=None,
):
    Payment.objects.create(
        booking=booking,
        amount=max(0, int(booking.total_amount or 0)),
        method=(method or "Unknown")[:80],
        status=Payment.STATUS_FAILED,
        transaction_ref=generate_payment_reference("FAIL"),
        gateway_provider=(gateway_provider or "Eventify Local Gateway")[:80],
        gateway_payment_id=(gateway_payment_id or get_gateway_payment_id(method))[:120],
        verification_signature=(verification_signature or "")[:180],
        verification_status="invalid",
        failure_reason=reason,
        coupon_code=(coupon_code or "").strip().upper(),
        payment_meta=payment_meta or {},
    )
    record_audit_log(
        action="payment_failed",
        summary=f"Payment failed for booking {booking.ticket_reference}.",
        category="payment",
        status="failure",
        user=booking.user,
        actor_contact=getattr(getattr(booking.user, "profile", None), "contact", booking.user.username),
        metadata={
            "booking_id": booking.id,
            "event_id": booking.event_id,
            "reason": reason,
            "method": method,
            "gateway_provider": gateway_provider,
        },
    )


def calculate_refund_amount(booking):
    latest_paid_payment = booking.payments.filter(status=Payment.STATUS_PAID).order_by("-paid_at", "-id").first()
    if not latest_paid_payment:
        return 0
    amount_paid = int(latest_paid_payment.amount or 0)
    days_left = (booking.event.date - timezone.localdate()).days if booking.event and booking.event.date else 0
    if days_left >= 2:
        return amount_paid
    return max(0, amount_paid // 2)


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
    question = sanitize_text_input(request.POST.get("securityQuestion"), max_length=255)
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
    record_audit_log(
        action="security_question_updated",
        summary="Security question updated from settings.",
        category="account",
        status="success",
        request=request,
        user=request.user,
    )
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
        ("Ticket Type", booking.ticket_type.name if booking.ticket_type_id else "Standard"),
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


def build_invoice_pdf(booking, payment_records):
    page_width, page_height = 1240, 1754
    page = PILImage.new("RGB", (page_width, page_height), "#f4f7ff")
    draw = ImageDraw.Draw(page)

    title_font = _load_font(50, bold=True)
    section_font = _load_font(32, bold=True)
    body_font = _load_font(27)
    small_font = _load_font(23)

    draw.rounded_rectangle((60, 70, page_width - 60, page_height - 70), radius=36, fill="#ffffff", outline="#d6e0f8", width=3)
    draw.rounded_rectangle((60, 70, page_width - 60, 240), radius=36, fill="#1d4eb8")
    draw.text((96, 118), "EVENTIFY INVOICE", fill="#ffffff", font=title_font)

    latest_paid_payment = next((item for item in payment_records if item.status == Payment.STATUS_PAID), None)
    latest_refund_payment = next((item for item in payment_records if item.status == Payment.STATUS_REFUNDED), None)
    details = [
        ("Invoice No", booking.invoice_no or "-"),
        ("Booking ID", f"#{booking.id}"),
        ("Ticket ID", booking.ticket_reference),
        ("Customer", build_ticket_holder_name(booking.user)),
        ("Event", booking.event.title),
        ("Event Date", booking.event.date.strftime("%d %b %Y")),
        ("Location", booking.event.location),
        ("Ticket Type", booking.ticket_type.name if booking.ticket_type_id else "Standard"),
        ("Tickets", str(booking.tickets)),
        ("Payment Status", booking.payment_status.title()),
        ("Amount Paid", f"INR {int((latest_paid_payment.amount if latest_paid_payment else booking.total_amount) or 0):,}"),
        (
            "Discount",
            f"INR {int((latest_paid_payment.discount_amount if latest_paid_payment else 0) or 0):,}",
        ),
        (
            "Promo Code",
            (latest_paid_payment.coupon_code if latest_paid_payment else "") or "-",
        ),
        (
            "Refund Amount",
            f"INR {int((latest_refund_payment.amount if latest_refund_payment else 0) or 0):,}",
        ),
        ("Issued On", timezone.localtime().strftime("%d %b %Y, %I:%M %p")),
    ]

    draw.text((96, 300), "Payment Receipt", fill="#244b9d", font=section_font)
    row_y = 360
    label_width = 220
    value_width = page_width - 190 - label_width
    for label, value in details:
        draw.text((96, row_y), f"{label}:", fill="#2d4988", font=body_font)
        wrapped = _wrap_text(draw, str(value or "-"), body_font, value_width)
        for idx, line in enumerate(wrapped):
            draw.text((96 + label_width, row_y + (idx * 36)), line, fill="#1f2a44", font=body_font)
        row_height = max(50, 36 * len(wrapped))
        row_y += row_height
        draw.line((96, row_y, page_width - 96, row_y), fill="#e2e8f8", width=2)
        row_y += 16

    payment_section_top = min(page_height - 440, row_y + 16)
    draw.text((96, payment_section_top), "Transactions", fill="#244b9d", font=section_font)
    payment_row_y = payment_section_top + 58
    if payment_records:
        for payment in payment_records[:8]:
            reference_time = payment.refunded_at if payment.status == Payment.STATUS_REFUNDED and payment.refunded_at else payment.paid_at
            formatted_time = timezone.localtime(reference_time).strftime("%d %b %Y, %I:%M %p") if reference_time else "-"
            pieces = [
                formatted_time,
                payment.status.upper(),
                payment.method or "-",
                f"INR {int(payment.amount or 0):,}",
                f"Txn {payment.transaction_ref or '-'}",
            ]
            if payment.gateway_payment_id:
                pieces.append(f"Gateway {payment.gateway_payment_id}")
            if payment.coupon_code:
                pieces.append(f"Promo {payment.coupon_code}")
            if payment.failure_reason:
                pieces.append(f"Reason {payment.failure_reason}")
            line_text = " | ".join(pieces)
            wrapped_line = _wrap_text(draw, line_text, small_font, page_width - 192)
            for idx, line in enumerate(wrapped_line):
                draw.text((96, payment_row_y + (idx * 30)), line, fill="#2f4371", font=small_font)
            line_height = max(38, 30 * len(wrapped_line))
            payment_row_y += line_height
            draw.line((96, payment_row_y, page_width - 96, payment_row_y), fill="#ebeff9", width=2)
            payment_row_y += 12
            if payment_row_y > page_height - 170:
                break
    else:
        draw.text((96, payment_row_y), "No payment transactions available.", fill="#5f7099", font=small_font)

    draw.text(
        (96, page_height - 128),
        "This is a system-generated Eventify invoice and receipt.",
        fill="#61739e",
        font=small_font,
    )

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
    trending_events_raw = get_trending_events(limit=12)
    trending_events = []
    normalized_query = query.lower()
    for trending_event in trending_events_raw:
        if selected_category and selected_category.lower() not in (trending_event.category or "").lower():
            continue
        if query:
            haystack = " ".join(
                [
                    trending_event.title or "",
                    trending_event.location or "",
                    trending_event.category or "",
                    trending_event.time or "",
                ]
            ).lower()
            if normalized_query not in haystack:
                if not parsed_date or trending_event.date != parsed_date:
                    continue
        trending_events.append(trending_event)
        if len(trending_events) >= 6:
            break
    
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

    categories = list(
        EventCategory.objects.filter(is_active=True)
        .values_list("name", flat=True)
        .order_by("display_order", "name")
    )
    if not categories:
        categories = list(
            Event.objects.filter(is_private=False)
            .exclude(category__exact="")
            .values_list("category", flat=True)
            .distinct()
            .order_by("category")
        )
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
            "home_contact_email": request.user.email if request.user.is_authenticated else "",
            "home_profile_role": home_profile_role,
            "query": query,
            "selected_category": selected_category,
            "categories": categories,
            "featured_events": featured_events,
            "trending_events": trending_events,
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

    question = sanitize_text_input(request.POST.get("question"), max_length=1000)
    if not question:
        messages.error(request, "Please enter your question.")
        return redirect("home")

    subject = f"New Subscription and Question from {email}"
    message = f"User Email: {email}\n\nQuestion: {question}"

    try:
        from django.core.mail import send_mail
        from_email = (
            (getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip()
            or (getattr(settings, "EMAIL_HOST_USER", "") or "").strip()
            or "noreply@eventify.com"
        )

        send_mail(
            subject,
            message,
            from_email,
            list(NEWSLETTER_CONTACT_RECIPIENTS),
            fail_silently=False,
        )

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

    locked_state, remaining_seconds = get_login_lockout(role, contact)
    if locked_state:
        record_audit_log(
            action="login_blocked",
            summary="Blocked login attempt due to temporary lockout.",
            category="auth",
            status="failure",
            request=request,
            actor_contact=contact,
            metadata={"role": role, "remaining_seconds": remaining_seconds},
        )
        messages.error(request, format_lockout_message(remaining_seconds))
        return redirect("/auth/?tab=login")

    profile = find_profile_by_contact_role(contact, role)
    if not profile:
        throttle = record_failed_login(role, contact)
        remaining = 0
        if throttle and throttle.locked_until and throttle.locked_until > timezone.now():
            remaining = int((throttle.locked_until - timezone.now()).total_seconds())
        record_audit_log(
            action="login_failed",
            summary="Failed login attempt for unknown account or role.",
            category="auth",
            status="failure",
            request=request,
            actor_contact=contact,
            metadata={"role": role, "locked": bool(remaining)},
        )
        if remaining:
            messages.error(request, format_lockout_message(remaining))
            return redirect("/auth/?tab=login")
        messages.error(request, "Invalid credentials for selected role.")
        return redirect("/auth/?tab=login")

    user = authenticate(request, username=profile.user.username, password=password)
    if not user:
        throttle = record_failed_login(role, contact)
        remaining = 0
        if throttle and throttle.locked_until and throttle.locked_until > timezone.now():
            remaining = int((throttle.locked_until - timezone.now()).total_seconds())
        record_audit_log(
            action="login_failed",
            summary="Failed login attempt due to invalid password.",
            category="auth",
            status="failure",
            request=request,
            user=profile.user,
            actor_contact=contact,
            metadata={"role": role, "locked": bool(remaining)},
        )
        if remaining:
            messages.error(request, format_lockout_message(remaining))
            return redirect("/auth/?tab=login")
        messages.error(request, "Invalid credentials for selected role.")
        return redirect("/auth/?tab=login")

    clear_failed_logins(role, contact)
    return complete_login_after_primary_auth(request, user, profile, auth_source="password")


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
    name = sanitize_text_input(request.POST.get("name"), max_length=120)
    contact = (request.POST.get("contact") or "").strip().lower()
    password = request.POST.get("password") or ""
    confirm_password = request.POST.get("confirmPassword") or ""

    if not all([role, name, contact, password, confirm_password]):
        messages.error(request, "Please fill all registration fields.")
        return redirect("/auth/?tab=register")

    if password != confirm_password:
        messages.error(request, "Password and confirm password do not match.")
        return redirect("/auth/?tab=register")

    password_error_redirect = show_password_validation_error(
        request,
        password,
        redirect_name="/auth/?tab=register",
    )
    if password_error_redirect:
        return password_error_redirect

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
    record_audit_log(
        action="registration_otp_requested",
        summary="Registration OTP requested.",
        category="account",
        status="info",
        request=request,
        actor_contact=contact,
        metadata={"role": role},
    )
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
        initialize_secure_session(request)
        record_audit_log(
            action="account_registered",
            summary="Account created after OTP verification.",
            category="account",
            status="success",
            request=request,
            user=user,
            metadata={"role": otp_request.role},
        )
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

    if password != confirm_password:
        messages.error(request, "Password and confirm password do not match.")
        return redirect("reset_password")

    user = User.objects.filter(id=user_id).first()
    if not user:
        request.session.pop("reset_user_id", None)
        messages.error(request, "User not found.")
        return redirect("auth_page")

    password_error_redirect = show_password_validation_error(
        request,
        password,
        user=user,
        redirect_name="reset_password",
    )
    if password_error_redirect:
        return password_error_redirect

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
    initialize_secure_session(request)
    record_audit_log(
        action="password_reset",
        summary="Password reset completed via OTP flow.",
        category="account",
        status="success",
        request=request,
        user=user,
    )
    messages.success(request, "Password reset successful. Auto login complete.")
    return redirect("dashboard")


@login_required(login_url="auth_page")
def logout_submit(request):
    if request.method == "POST":
        record_audit_log(
            action="logout",
            summary="User logged out.",
            category="auth",
            status="info",
            request=request,
            user=request.user,
        )
        logout(request)
    return redirect("home")


@login_required(login_url="auth_page")
def dashboard(request):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    today = timezone.localdate()

    if profile.role == Profile.ROLE_ADMIN:
        return redirect("admin_dashboard")

    if profile.role == Profile.ROLE_ORGANIZER:
        events_qs = Event.objects.filter(created_by=request.user).prefetch_related(
            Prefetch(
                "bookings",
                queryset=Booking.objects.select_related("user").prefetch_related("payments").order_by("-booking_date"),
            )
        )
        bookings_qs = Booking.objects.filter(event__created_by=request.user).select_related(
            "event",
            "user",
            "active_activity_slot",
            "helper_activity_slot",
        ).prefetch_related("payments")
        paid_payments_qs = Payment.objects.filter(
            booking__event__created_by=request.user,
            status=Payment.STATUS_PAID,
        )
        refunded_payments_qs = Payment.objects.filter(
            booking__event__created_by=request.user,
            status=Payment.STATUS_REFUNDED,
        )
        gross_earnings = paid_payments_qs.aggregate(total=Sum("amount"))["total"] or 0
        refund_total = refunded_payments_qs.aggregate(total=Sum("amount"))["total"] or 0
        stats = {
            "total_events": events_qs.count(),
            "total_bookings": bookings_qs.count(),
            "total_revenue": max(0, gross_earnings - refund_total),
            "gross_earnings": gross_earnings,
            "refund_total": refund_total,
            "total_tickets_sold": bookings_qs.filter(payment_status=Booking.PAYMENT_PAID).aggregate(
                total=Sum("tickets")
            )["total"]
            or 0,
            "pending_requests": bookings_qs.filter(status=Booking.STATUS_PENDING).count(),
        }
        recent_bookings = bookings_qs.order_by("-booking_date")[:6]
        upcoming_events = events_qs.order_by("date")[:4]
        revenue_rows = []
        for event in events_qs.order_by("date"):
            event_bookings = list(event.bookings.all())
            tickets_sold = sum(
                int(booking.tickets or 0)
                for booking in event_bookings
                if booking.payment_status == Booking.PAYMENT_PAID
            )
            gross = sum(
                int(payment.amount or 0)
                for booking in event_bookings
                for payment in booking.payments.all()
                if payment.status == Payment.STATUS_PAID
            )
            refunds = sum(
                int(payment.amount or 0)
                for booking in event_bookings
                for payment in booking.payments.all()
                if payment.status == Payment.STATUS_REFUNDED
            )
            revenue_rows.append(
                {
                    "event": event,
                    "tickets_sold": tickets_sold,
                    "gross": gross,
                    "refunds": refunds,
                    "net": max(0, gross - refunds),
                }
            )
        return render_app(
            request,
            "core/dashboard.html",
            "dashboard",
            {
                "role_mode": "organizer",
                "stats": stats,
                "recent_bookings": recent_bookings,
                "upcoming_events": upcoming_events,
                "revenue_rows": revenue_rows,
            },
        )

    bookings_qs = Booking.objects.filter(user=request.user).select_related(
        "event",
        "active_activity_slot",
        "helper_activity_slot",
    ).prefetch_related("payments")
    paid_total = Payment.objects.filter(booking__user=request.user, status=Payment.STATUS_PAID).aggregate(
        total=Sum("amount")
    )["total"] or 0
    refund_total = Payment.objects.filter(booking__user=request.user, status=Payment.STATUS_REFUNDED).aggregate(
        total=Sum("amount")
    )["total"] or 0
    stats = {
        "total_bookings": bookings_qs.count(),
        "upcoming_events": bookings_qs.filter(event__date__gte=today).exclude(
            status=Booking.STATUS_CANCELLED
        ).count(),
        "completed_events": bookings_qs.filter(
            Q(event__date__lt=today) | Q(status=Booking.STATUS_COMPLETED)
        ).count(),
        "total_spending": max(0, paid_total - refund_total),
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
    event = get_object_or_404(
        Event.objects.prefetch_related("schedules", "gallery_images", "ticket_types"),
        id=event_id,
    )
    related_events = Event.objects.filter(category=event.category).exclude(id=event.id).order_by(
        "date"
    )[:4]
    profile = get_or_create_profile(request.user)
    is_event_owner = profile.role == Profile.ROLE_ORGANIZER and event.created_by_id == request.user.id
    is_admin = profile.role == Profile.ROLE_ADMIN
    user_event_booking = None
    can_download_ticket = False
    needs_profile_photo = False
    can_continue_payment = False
    role_slots = build_event_role_slots(event)
    show_participants_panel = False
    event_participants = []
    event_schedules = list(event.schedules.filter(is_active=True).order_by("display_order", "start_time", "id"))
    event_gallery_images = list(event.gallery_images.filter(is_active=True).order_by("display_order", "-uploaded_at"))
    bookable_ticket_types = get_bookable_ticket_types(event)
    can_manage_event_assets = is_event_owner or is_admin

    if profile.role == Profile.ROLE_USER:
        user_event_booking = (
            Booking.objects.filter(user=request.user, event=event)
            .select_related("ticket_type")
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
    elif is_event_owner or is_admin:
        show_participants_panel = True
        event_participants = list(
            Booking.objects.select_related(
                "user",
                "user__profile",
                "active_activity_slot",
                "helper_activity_slot",
                "ticket_type",
            )
            .filter(event=event)
            .exclude(status=Booking.STATUS_CANCELLED)
            .order_by("-booking_date", "-id")
        )
        if is_event_owner:
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
            "event_schedules": event_schedules,
            "event_gallery_images": event_gallery_images,
            "bookable_ticket_types": bookable_ticket_types,
            "can_manage_event_assets": can_manage_event_assets,
            "is_event_owner": is_event_owner,
        },
    )


@role_required(Profile.ROLE_USER)
def book_event(request, event_id):
    ensure_seeded()
    event = get_object_or_404(Event.objects.prefetch_related("ticket_types"), id=event_id)
    existing_booking = (
        Booking.objects.filter(user=request.user, event=event)
        .exclude(status=Booking.STATUS_CANCELLED)
        .order_by("-booking_date", "-id")
        .first()
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
    bookable_ticket_types = get_bookable_ticket_types(event)
    default_ticket_type = bookable_ticket_types[0] if bookable_ticket_types else None
    default_ticket_type_id = str(default_ticket_type.id) if default_ticket_type else ""
    default_ticket_quantity = 1

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
                "ticket_types": bookable_ticket_types,
                "selected_ticket_type_id": default_ticket_type_id,
                "selected_ticket_quantity": default_ticket_quantity,
            },
        )

    attendee_name = (request.POST.get("attendeeName") or "").strip()
    selected_application_role = (request.POST.get("applicationRole") or Booking.ROLE_ATTENDEE).strip()
    selected_active_activity_id = (request.POST.get("activeActivityId") or "").strip()
    selected_helper_activity_id = (request.POST.get("helperActivityId") or "").strip()
    selected_ticket_type_id = (request.POST.get("ticketTypeId") or "").strip()
    selected_ticket_quantity_raw = (request.POST.get("ticketQuantity") or "1").strip()
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

    selected_ticket_type = None
    tickets = 1
    if bookable_ticket_types:
        if not selected_ticket_type_id:
            messages.error(request, "Please select a ticket type.")
            return redirect("book_event", event_id=event.id)
        selected_ticket_type = next(
            (item for item in bookable_ticket_types if str(item.id) == selected_ticket_type_id),
            None,
        )
        if not selected_ticket_type:
            messages.error(request, "Selected ticket type is invalid or unavailable.")
            return redirect("book_event", event_id=event.id)

        tickets = parse_positive_int(selected_ticket_quantity_raw, minimum=1)
        if tickets is None:
            messages.error(request, "Ticket quantity must be at least 1.")
            return redirect("book_event", event_id=event.id)

        if selected_application_role != Booking.ROLE_ATTENDEE:
            tickets = 1

        max_allowed = min(
            int(selected_ticket_type.max_per_booking or tickets),
            int(selected_ticket_type.available_quantity or 0),
        )
        if max_allowed <= 0:
            messages.error(request, "Selected ticket type is sold out.")
            return redirect("book_event", event_id=event.id)
        if tickets > max_allowed:
            messages.error(request, f"You can book up to {max_allowed} ticket(s) for this ticket type.")
            return redirect("book_event", event_id=event.id)
        total_amount = int(selected_ticket_type.price or 0) * tickets
    else:
        total_amount = int(event.price or 0) * tickets

    booking = Booking.objects.create(
        user=request.user,
        event=event,
        ticket_type=selected_ticket_type,
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
    record_audit_log(
        action="booking_created",
        summary=f"Booking created for '{event.title}'.",
        category="booking",
        status="success",
        request=request,
        user=request.user,
        metadata={"booking_id": booking.id, "event_id": event.id, "tickets": tickets},
    )
    messages.success(request, "Booking created. Please complete payment.")
    return redirect("payment_page", booking_id=booking.id)


def render_razorpay_checkout_page(
    request,
    *,
    active_page,
    title,
    description,
    amount,
    order_id,
    verify_url,
    cancel_url,
    context_token,
    prefill_name="",
    prefill_email="",
    prefill_contact="",
):
    return render_app(
        request,
        "core/razorpay_checkout.html",
        active_page,
        {
            "checkout_title": title,
            "checkout_description": description,
            "checkout_amount": amount,
            "razorpay_key_id": settings.RAZORPAY_KEY_ID,
            "razorpay_order_id": order_id,
            "verify_url": verify_url,
            "cancel_url": cancel_url,
            "context_token": context_token,
            "prefill_name": prefill_name,
            "prefill_email": prefill_email,
            "prefill_contact": prefill_contact,
        },
    )


def finalize_booking_payment(
    booking,
    *,
    acting_user,
    method,
    final_amount,
    promo=None,
    coupon_code="",
    discount_amount=0,
    upi_id="",
    gateway_provider="Eventify Local Gateway",
    gateway_payment_id="",
    verification_signature="",
    payment_meta=None,
):
    capacity_error = ""
    payment = None
    already_paid = False

    with transaction.atomic():
        booking = (
            Booking.objects.select_related("event", "ticket_type")
            .select_for_update()
            .get(id=booking.id, user=acting_user)
        )
        if booking.payment_status == Booking.PAYMENT_PAID:
            already_paid = True
        else:
            locked_ticket_type = None
            if booking.ticket_type_id:
                locked_ticket_type = (
                    TicketType.objects.select_for_update()
                    .filter(id=booking.ticket_type_id, event_id=booking.event_id)
                    .first()
                )
                if not locked_ticket_type or not locked_ticket_type.is_active:
                    capacity_error = "Selected ticket type is no longer available."
                else:
                    now = timezone.now()
                    if locked_ticket_type.sales_start and now < locked_ticket_type.sales_start:
                        capacity_error = "Ticket sales for this ticket type have not started yet."
                    elif locked_ticket_type.sales_end and now > locked_ticket_type.sales_end:
                        capacity_error = "Ticket sales for this ticket type have ended."
                    elif int(booking.tickets or 0) > int(locked_ticket_type.available_quantity or 0):
                        capacity_error = (
                            f"Only {int(locked_ticket_type.available_quantity or 0)} ticket(s) left "
                            f"for {locked_ticket_type.name}."
                        )

            if not capacity_error:
                booking.payment_status = Booking.PAYMENT_PAID
                booking.status = Booking.STATUS_CONFIRMED
                booking.total_amount = max(0, int(final_amount or 0))
                if not booking.invoice_no:
                    booking.invoice_no = generate_invoice_no()
                booking.save(update_fields=["payment_status", "status", "total_amount", "invoice_no"])

                payment = Payment.objects.create(
                    booking=booking,
                    amount=max(0, int(final_amount or 0)),
                    method=(method or "Unknown")[:80],
                    status=Payment.STATUS_PAID,
                    transaction_ref=generate_payment_reference(),
                    upi_id=(upi_id or "")[:120],
                    gateway_provider=(gateway_provider or "Eventify Local Gateway")[:80],
                    gateway_payment_id=(gateway_payment_id or get_gateway_payment_id(method))[:120],
                    verification_signature=(verification_signature or "")[:180],
                    verification_status="verified",
                    coupon_code=(coupon_code or "").strip().upper(),
                    discount_amount=max(0, int(discount_amount or 0)),
                    payment_meta=payment_meta or {},
                )
                if promo:
                    promo.used_count += 1
                    promo.save(update_fields=["used_count"])

                if locked_ticket_type:
                    locked_ticket_type.available_quantity = max(
                        0,
                        int(locked_ticket_type.available_quantity or 0) - int(booking.tickets or 0),
                    )
                    locked_ticket_type.save(update_fields=["available_quantity"])

    return booking, payment, capacity_error, already_paid


def build_booking_razorpay_checkout(request, booking, final_amount, promo, discount_amount):
    order = create_razorpay_order(
        final_amount,
        receipt=booking.ticket_reference,
        notes={
            "booking_id": str(booking.id),
            "event_id": str(booking.event_id),
            "user_id": str(request.user.id),
        },
    )
    order_id = (order or {}).get("id", "").strip()
    if not order_id:
        raise IntegrationError("Razorpay did not return an order id.")

    context_token = sign_gateway_context(
        {
            "booking_id": booking.id,
            "user_id": request.user.id,
            "order_id": order_id,
            "amount": int(final_amount or 0),
            "promo_id": promo.id if promo else None,
            "coupon_code": promo.code if promo else "",
            "discount_amount": int(discount_amount or 0),
        },
        salt="razorpay-booking-payment",
    )
    profile = get_or_create_profile(request.user)
    return render_razorpay_checkout_page(
        request,
        active_page="my-bookings",
        title="Complete Secure Payment",
        description=f"{booking.event.title} booking checkout",
        amount=int(final_amount or 0),
        order_id=order_id,
        verify_url=reverse("payment_verify", args=[booking.id]),
        cancel_url=reverse("payment_page", args=[booking.id]),
        context_token=context_token,
        prefill_name=request.user.get_full_name() or request.user.first_name or booking.attendee_name,
        prefill_email=request.user.email,
        prefill_contact=(profile.phone or "").strip(),
    )


def build_private_event_razorpay_checkout(request, private_payment):
    order = create_razorpay_order(
        private_payment.amount,
        receipt=f"private-{private_payment.id}",
        notes={
            "private_payment_id": str(private_payment.id),
            "event_id": str(private_payment.event_id),
            "organizer_id": str(request.user.id),
        },
    )
    order_id = (order or {}).get("id", "").strip()
    if not order_id:
        raise IntegrationError("Razorpay did not return an order id.")

    private_payment.gateway_provider = "Razorpay"
    private_payment.gateway_order_id = order_id
    private_payment.verification_status = "pending"
    private_payment.payment_meta = {"razorpay_order": order}
    private_payment.save(
        update_fields=[
            "gateway_provider",
            "gateway_order_id",
            "verification_status",
            "payment_meta",
        ]
    )

    context_token = sign_gateway_context(
        {
            "private_payment_id": private_payment.id,
            "organizer_id": request.user.id,
            "order_id": order_id,
            "amount": int(private_payment.amount or 0),
        },
        salt="razorpay-private-event-payment",
    )
    profile = get_or_create_profile(request.user)
    return render_razorpay_checkout_page(
        request,
        active_page="my-events",
        title="Private Event Checkout",
        description=f"{private_payment.event.title} organizer payment",
        amount=int(private_payment.amount or 0),
        order_id=order_id,
        verify_url=reverse("private_event_payment_verify", args=[private_payment.id]),
        cancel_url=reverse("private_event_payment_page", args=[private_payment.id]),
        context_token=context_token,
        prefill_name=request.user.get_full_name() or request.user.first_name or request.user.username,
        prefill_email=request.user.email,
        prefill_contact=(profile.phone or "").strip(),
    )


@role_required(Profile.ROLE_USER)
def payment_page(request, booking_id):
    ensure_seeded()
    booking = get_object_or_404(
        Booking.objects.select_related("event", "ticket_type").prefetch_related("payments"),
        id=booking_id,
        user=request.user,
    )
    available_promos = [promo for promo in PromoCode.objects.filter(active=True).order_by("code") if promo.can_use()]
    return render_app(
        request,
        "core/payment.html",
        "my-bookings",
        {
            "booking": booking,
            "razorpay_enabled": razorpay_ready(),
            "payment_methods": PAYMENT_METHODS,
            "available_promos": available_promos,
            "recent_payments": booking.payments.all()[:5],
        },
    )


@role_required(Profile.ROLE_USER)
def payment_pay(request, booking_id):
    ensure_seeded()
    if request.method != "POST":
        return redirect("payment_page", booking_id=booking_id)

    booking = get_object_or_404(
        Booking.objects.select_related("event", "user", "ticket_type").prefetch_related("payments"),
        id=booking_id,
        user=request.user,
    )
    method = (request.POST.get("method") or "").strip()
    upi_id = (request.POST.get("upiId") or "").strip().lower()
    promo_code = (request.POST.get("promoCode") or "").strip().upper()

    if booking.payment_status == Booking.PAYMENT_PAID:
        return redirect("booking_success", booking_id=booking.id)

    base_amount = int(booking.total_amount or 0)
    promo, discount_amount, promo_error = validate_promo_for_amount(promo_code, base_amount)
    if promo_error:
        log_failed_payment(booking, method or RAZORPAY_METHOD, promo_error, promo_code)
        messages.error(request, promo_error)
        return redirect("payment_page", booking_id=booking.id)

    final_amount = max(0, base_amount - discount_amount)

    if razorpay_ready():
        try:
            return build_booking_razorpay_checkout(request, booking, final_amount, promo, discount_amount)
        except IntegrationError as exc:
            log_failed_payment(
                booking,
                RAZORPAY_METHOD,
                str(exc),
                promo_code,
                gateway_provider="Razorpay",
            )
            messages.error(request, f"Razorpay checkout could not be started: {exc}")
            return redirect("payment_page", booking_id=booking.id)

    if method not in PAYMENT_METHODS:
        log_failed_payment(booking, method, "Please select a valid payment method.", promo_code)
        messages.error(request, "Please select a valid payment method.")
        return redirect("payment_page", booking_id=booking.id)

    payment_details, payment_error = extract_payment_details(request, method)
    if payment_error:
        log_failed_payment(booking, method, payment_error, promo_code)
        messages.error(request, payment_error)
        return redirect("payment_page", booking_id=booking.id)
    upi_id = payment_details.get("upi_id", "")
    payment_meta = payment_details.get("payment_meta", {})
    gateway_payment_id = get_gateway_payment_id(method)
    verification_signature = hashlib.sha256(
        f"{booking.id}:{gateway_payment_id}:{final_amount}:{method}".encode("utf-8")
    ).hexdigest()[:48]

    booking, payment, capacity_error, already_paid = finalize_booking_payment(
        booking,
        acting_user=request.user,
        method=method,
        final_amount=final_amount,
        promo=promo,
        coupon_code=promo.code if promo else promo_code,
        discount_amount=discount_amount,
        upi_id=upi_id,
        gateway_provider="Eventify Local Gateway",
        gateway_payment_id=gateway_payment_id,
        verification_signature=verification_signature,
        payment_meta=payment_meta,
    )

    if already_paid:
        return redirect("booking_success", booking_id=booking.id)
    if capacity_error:
        log_failed_payment(booking, method, capacity_error, promo_code)
        messages.error(request, capacity_error)
        return redirect("payment_page", booking_id=booking.id)

    create_notification(
        request.user,
        "Booking Confirmed",
        f"Payment successful for '{booking.event.title}'. Booking is confirmed.",
        "payment",
    )
    record_audit_log(
        action="payment_success",
        summary=f"Razorpay payment completed for booking {booking.ticket_reference}.",
        category="payment",
        status="success",
        request=request,
        user=request.user,
        metadata={"booking_id": booking.id, "payment_id": payment.id if payment else None, "method": RAZORPAY_METHOD},
    )
    email_sent = send_booking_ticket_email(request, booking, payment)
    if email_sent:
        messages.success(request, "Payment successful. Booking confirmed and ticket emailed.")
    else:
        messages.success(request, "Payment successful. Booking confirmed.")
    return redirect("booking_success", booking_id=booking.id)


@role_required(Profile.ROLE_USER)
def payment_verify(request, booking_id):
    ensure_seeded()
    if request.method != "POST":
        return redirect("payment_page", booking_id=booking_id)

    booking = get_object_or_404(
        Booking.objects.select_related("event", "user", "ticket_type").prefetch_related("payments"),
        id=booking_id,
        user=request.user,
    )
    if booking.payment_status == Booking.PAYMENT_PAID:
        return redirect("booking_success", booking_id=booking.id)

    context_token = (request.POST.get("contextToken") or "").strip()
    order_id = (request.POST.get("razorpay_order_id") or "").strip()
    payment_id = (request.POST.get("razorpay_payment_id") or "").strip()
    signature = (request.POST.get("razorpay_signature") or "").strip()

    try:
        gateway_context = load_gateway_context(context_token, salt="razorpay-booking-payment")
    except (BadSignature, SignatureExpired):
        log_failed_payment(
            booking,
            RAZORPAY_METHOD,
            "Razorpay payment session expired or is invalid.",
            gateway_provider="Razorpay",
            gateway_payment_id=payment_id,
            verification_signature=signature,
        )
        messages.error(request, "Payment session expired. Please start Razorpay checkout again.")
        return redirect("payment_page", booking_id=booking.id)

    if (
        int(gateway_context.get("booking_id") or 0) != booking.id
        or int(gateway_context.get("user_id") or 0) != request.user.id
        or (gateway_context.get("order_id") or "").strip() != order_id
    ):
        log_failed_payment(
            booking,
            RAZORPAY_METHOD,
            "Razorpay checkout context mismatch.",
            gateway_provider="Razorpay",
            gateway_payment_id=payment_id,
            verification_signature=signature,
            payment_meta={"razorpay_order_id": order_id},
        )
        messages.error(request, "Invalid payment verification payload.")
        return redirect("payment_page", booking_id=booking.id)

    if not payment_id or not signature or not verify_razorpay_signature(order_id, payment_id, signature):
        log_failed_payment(
            booking,
            RAZORPAY_METHOD,
            "Razorpay signature verification failed.",
            coupon_code=gateway_context.get("coupon_code") or "",
            gateway_provider="Razorpay",
            gateway_payment_id=payment_id,
            verification_signature=signature,
            payment_meta={"razorpay_order_id": order_id},
        )
        messages.error(request, "Payment verification failed. No charge was recorded in Eventify.")
        return redirect("payment_page", booking_id=booking.id)

    promo = None
    promo_id = gateway_context.get("promo_id")
    if promo_id:
        promo = PromoCode.objects.filter(id=promo_id).first()

    booking, payment, capacity_error, already_paid = finalize_booking_payment(
        booking,
        acting_user=request.user,
        method=RAZORPAY_METHOD,
        final_amount=int(gateway_context.get("amount") or 0),
        promo=promo,
        coupon_code=gateway_context.get("coupon_code") or "",
        discount_amount=int(gateway_context.get("discount_amount") or 0),
        gateway_provider="Razorpay",
        gateway_payment_id=payment_id,
        verification_signature=signature,
        payment_meta={
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
        },
    )

    if already_paid:
        return redirect("booking_success", booking_id=booking.id)
    if capacity_error:
        log_failed_payment(
            booking,
            RAZORPAY_METHOD,
            capacity_error,
            coupon_code=gateway_context.get("coupon_code") or "",
            gateway_provider="Razorpay",
            gateway_payment_id=payment_id,
            verification_signature=signature,
            payment_meta={"razorpay_order_id": order_id},
        )
        messages.error(request, capacity_error)
        return redirect("payment_page", booking_id=booking.id)

    create_notification(
        request.user,
        "Booking Confirmed",
        f"Payment successful for '{booking.event.title}'. Booking is confirmed.",
        "payment",
    )
    record_audit_log(
        action="payment_success",
        summary=f"Payment completed for booking {booking.ticket_reference}.",
        category="payment",
        status="success",
        request=request,
        user=request.user,
        metadata={"booking_id": booking.id, "payment_id": payment.id if payment else None, "method": method},
    )
    email_sent = send_booking_ticket_email(request, booking, payment)
    if email_sent:
        messages.success(request, "Razorpay payment successful. Booking confirmed and ticket emailed.")
    else:
        messages.success(request, "Razorpay payment successful. Booking confirmed.")
    return redirect("booking_success", booking_id=booking.id)


@role_required(Profile.ROLE_USER)
def booking_success(request, booking_id):
    ensure_seeded()
    booking = get_object_or_404(
        Booking.objects.select_related("event", "ticket_type"),
        id=booking_id,
        user=request.user,
    )
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
        {
            "private_payment": private_payment,
            "razorpay_enabled": razorpay_ready(),
            "payment_methods": PAYMENT_METHODS,
        },
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

    if razorpay_ready():
        try:
            return build_private_event_razorpay_checkout(request, private_payment)
        except IntegrationError as exc:
            private_payment.status = PrivateEventPayment.STATUS_FAILED
            private_payment.failure_reason = str(exc)
            private_payment.verification_status = "invalid"
            private_payment.save(update_fields=["status", "failure_reason", "verification_status"])
            messages.error(request, f"Razorpay checkout could not be started: {exc}")
            return redirect("private_event_payment_page", payment_id=private_payment.id)

    method = (request.POST.get("method") or "").strip()
    if method not in PAYMENT_METHODS:
        messages.error(request, "Please select a valid payment method.")
        return redirect("private_event_payment_page", payment_id=private_payment.id)

    _payment_details, payment_error = extract_payment_details(request, method)
    if payment_error:
        messages.error(request, payment_error)
        return redirect("private_event_payment_page", payment_id=private_payment.id)

    private_payment.status = PrivateEventPayment.STATUS_PAID
    private_payment.method = method
    private_payment.paid_at = timezone.now()
    private_payment.save(update_fields=["status", "method", "paid_at"])
    record_audit_log(
        action="private_event_payment_success",
        summary=f"Private event payment completed for '{private_payment.event.title}'.",
        category="payment",
        status="success",
        request=request,
        user=request.user,
        metadata={"private_payment_id": private_payment.id, "method": method},
    )

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


@role_required(Profile.ROLE_ORGANIZER)
def private_event_payment_verify(request, payment_id):
    ensure_seeded()
    if request.method != "POST":
        return redirect("private_event_payment_page", payment_id=payment_id)

    private_payment = get_object_or_404(
        PrivateEventPayment.objects.select_related("event"),
        id=payment_id,
        organizer=request.user,
    )
    if private_payment.status == PrivateEventPayment.STATUS_PAID:
        return redirect("my_events")

    context_token = (request.POST.get("contextToken") or "").strip()
    order_id = (request.POST.get("razorpay_order_id") or "").strip()
    payment_id_value = (request.POST.get("razorpay_payment_id") or "").strip()
    signature = (request.POST.get("razorpay_signature") or "").strip()

    try:
        gateway_context = load_gateway_context(context_token, salt="razorpay-private-event-payment")
    except (BadSignature, SignatureExpired):
        private_payment.status = PrivateEventPayment.STATUS_FAILED
        private_payment.failure_reason = "Razorpay payment session expired or is invalid."
        private_payment.verification_status = "invalid"
        private_payment.save(update_fields=["status", "failure_reason", "verification_status"])
        messages.error(request, "Payment session expired. Please restart the private event checkout.")
        return redirect("private_event_payment_page", payment_id=private_payment.id)

    if (
        int(gateway_context.get("private_payment_id") or 0) != private_payment.id
        or int(gateway_context.get("organizer_id") or 0) != request.user.id
        or (gateway_context.get("order_id") or "").strip() != order_id
    ):
        private_payment.status = PrivateEventPayment.STATUS_FAILED
        private_payment.failure_reason = "Razorpay checkout context mismatch."
        private_payment.gateway_payment_id = payment_id_value
        private_payment.verification_signature = signature
        private_payment.verification_status = "invalid"
        private_payment.payment_meta = {"razorpay_order_id": order_id}
        private_payment.save(
            update_fields=[
                "status",
                "failure_reason",
                "gateway_payment_id",
                "verification_signature",
                "verification_status",
                "payment_meta",
            ]
        )
        messages.error(request, "Invalid payment verification payload.")
        return redirect("private_event_payment_page", payment_id=private_payment.id)

    if not payment_id_value or not signature or not verify_razorpay_signature(order_id, payment_id_value, signature):
        private_payment.status = PrivateEventPayment.STATUS_FAILED
        private_payment.failure_reason = "Razorpay signature verification failed."
        private_payment.gateway_payment_id = payment_id_value
        private_payment.verification_signature = signature
        private_payment.verification_status = "invalid"
        private_payment.payment_meta = {"razorpay_order_id": order_id}
        private_payment.save(
            update_fields=[
                "status",
                "failure_reason",
                "gateway_payment_id",
                "verification_signature",
                "verification_status",
                "payment_meta",
            ]
        )
        messages.error(request, "Payment verification failed. Please try again.")
        return redirect("private_event_payment_page", payment_id=private_payment.id)

    private_payment.status = PrivateEventPayment.STATUS_PAID
    private_payment.method = RAZORPAY_METHOD
    private_payment.paid_at = timezone.now()
    private_payment.gateway_provider = "Razorpay"
    private_payment.gateway_order_id = order_id
    private_payment.gateway_payment_id = payment_id_value
    private_payment.verification_signature = signature
    private_payment.verification_status = "verified"
    private_payment.failure_reason = ""
    private_payment.payment_meta = {
        "razorpay_order_id": order_id,
        "razorpay_payment_id": payment_id_value,
    }
    private_payment.save(
        update_fields=[
            "status",
            "method",
            "paid_at",
            "gateway_provider",
            "gateway_order_id",
            "gateway_payment_id",
            "verification_signature",
            "verification_status",
            "failure_reason",
            "payment_meta",
        ]
    )
    record_audit_log(
        action="private_event_payment_success",
        summary=f"Razorpay private event payment completed for '{private_payment.event.title}'.",
        category="payment",
        status="success",
        request=request,
        user=request.user,
        metadata={"private_payment_id": private_payment.id, "method": RAZORPAY_METHOD},
    )

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
        .select_related("event", "ticket_type")
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

    holder_name = (request.user.first_name or request.user.username or "").strip()
    if not holder_name:
        messages.error(request, "User name is required for ticket PDF. Please update your profile.")
        return redirect("profile")

    user_photo = load_ticket_holder_photo(request.user)

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

    refund_amount = 0
    refund_mode = ""
    with transaction.atomic():
        booking = Booking.objects.select_for_update().get(id=booking.id, user=request.user)
        if booking.status == Booking.STATUS_CANCELLED:
            messages.error(request, "Booking is already cancelled.")
            return redirect("my_bookings")

        payment_was_paid = booking.payment_status == Booking.PAYMENT_PAID
        booking.status = Booking.STATUS_CANCELLED
        update_fields = ["status"]

        if payment_was_paid:
            booking.payment_status = Booking.PAYMENT_REFUNDED
            update_fields.append("payment_status")
        booking.save(update_fields=update_fields)

        if payment_was_paid:
            latest_paid_payment = booking.payments.filter(status=Payment.STATUS_PAID).order_by("-paid_at", "-id").first()
            refund_amount = calculate_refund_amount(booking)
            refund_mode = "full" if refund_amount >= int((latest_paid_payment.amount if latest_paid_payment else 0) or 0) else "partial"
            Payment.objects.create(
                booking=booking,
                amount=refund_amount,
                method=(latest_paid_payment.method if latest_paid_payment else "Refund"),
                status=Payment.STATUS_REFUNDED,
                transaction_ref=generate_payment_reference("RFD"),
                gateway_provider=(latest_paid_payment.gateway_provider if latest_paid_payment else "Eventify Local Gateway"),
                gateway_payment_id=get_gateway_payment_id("refund"),
                verification_status="verified",
                failure_reason=(
                    "Automatic full refund processed after booking cancellation."
                    if refund_mode == "full"
                    else "Automatic partial refund processed after booking cancellation."
                ),
                coupon_code=(latest_paid_payment.coupon_code if latest_paid_payment else ""),
                discount_amount=(latest_paid_payment.discount_amount if latest_paid_payment else 0),
                refunded_at=timezone.now(),
            )

            if booking.ticket_type_id:
                locked_ticket_type = (
                    TicketType.objects.select_for_update()
                    .filter(id=booking.ticket_type_id, event_id=booking.event_id)
                    .first()
                )
                if locked_ticket_type:
                    restored_quantity = int(locked_ticket_type.available_quantity or 0) + int(booking.tickets or 0)
                    locked_ticket_type.available_quantity = min(
                        int(locked_ticket_type.total_quantity or restored_quantity),
                        restored_quantity,
                    )
                    locked_ticket_type.save(update_fields=["available_quantity"])

    create_notification(
        request.user,
        "Booking Cancelled",
        (
            f"Your booking for '{booking.event.title}' has been cancelled and a full refund was initiated."
            if refund_mode == "full"
            else (
                f"Your booking for '{booking.event.title}' has been cancelled and a partial refund was initiated."
                if refund_mode == "partial"
                else f"Your booking for '{booking.event.title}' has been cancelled."
            )
        ),
        "booking",
    )
    if refund_mode == "full":
        messages.success(request, f"Booking cancelled. Full refund of INR {refund_amount:,} initiated.")
    elif refund_mode == "partial":
        messages.success(request, f"Booking cancelled. Partial refund of INR {refund_amount:,} initiated.")
    else:
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
def payment_history(request):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    if profile.role == Profile.ROLE_ORGANIZER:
        records = (
            Payment.objects.select_related("booking", "booking__event", "booking__user", "booking__ticket_type")
            .filter(booking__event__created_by=request.user)
            .order_by("-paid_at", "-id")
        )
    else:
        records = (
            Payment.objects.select_related("booking", "booking__event", "booking__ticket_type")
            .filter(booking__user=request.user)
            .order_by("-paid_at", "-id")
        )
    return render_app(
        request,
        "core/payment_history.html",
        "payment-history",
        {"records": records, "mode": profile.role},
    )


@login_required(login_url="auth_page")
def invoices(request):
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    invoice_statuses = [Booking.PAYMENT_PAID, Booking.PAYMENT_REFUNDED]
    if profile.role == Profile.ROLE_ORGANIZER:
        records = (
            Booking.objects.select_related(
                "event",
                "user",
                "active_activity_slot",
                "helper_activity_slot",
                "ticket_type",
            )
            .filter(event__created_by=request.user, payment_status__in=invoice_statuses)
            .order_by("-booking_date")
        )
    else:
        records = (
            Booking.objects.select_related("event", "active_activity_slot", "helper_activity_slot", "ticket_type")
            .filter(user=request.user, payment_status__in=invoice_statuses)
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
    invoice_statuses = [Booking.PAYMENT_PAID, Booking.PAYMENT_REFUNDED]
    if profile.role == Profile.ROLE_ORGANIZER:
        booking = get_object_or_404(
            Booking.objects.select_related("event", "user", "ticket_type"),
            id=booking_id,
            event__created_by=request.user,
            payment_status__in=invoice_statuses,
        )
    else:
        booking = get_object_or_404(
            Booking.objects.select_related("event", "user", "ticket_type"),
            id=booking_id,
            user=request.user,
            payment_status__in=invoice_statuses,
        )
    payment_records = list(booking.payments.order_by("-paid_at", "-id"))
    response = HttpResponse(build_invoice_pdf(booking, payment_records), content_type="application/pdf")
    file_name = booking.invoice_no or f"invoice-{booking.id}"
    response["Content-Disposition"] = f'attachment; filename="{file_name}.pdf"'
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
            upload_error = validate_image_upload(
                uploaded,
                label="Profile image",
                max_size_bytes=2 * 1024 * 1024,
            )
            if upload_error:
                messages.error(request, upload_error)
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
        record_audit_log(
            action="profile_updated",
            summary="Profile updated from account page.",
            category="account",
            status="success",
            request=request,
            user=request.user,
        )
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

    if new_password != confirm_password:
        messages.error(request, "New password and confirm password do not match.")
        return redirect("settings")

    if not check_password(old_password, request.user.password):
        record_audit_log(
            action="password_change_failed",
            summary="Password change rejected because old password was incorrect.",
            category="account",
            status="failure",
            request=request,
            user=request.user,
        )
        messages.error(request, "Old password is incorrect.")
        return redirect("settings")

    password_error_redirect = show_password_validation_error(
        request,
        new_password,
        user=request.user,
        redirect_name="settings",
    )
    if password_error_redirect:
        return password_error_redirect

    request.user.set_password(new_password)
    request.user.save(update_fields=["password"])
    create_notification(
        request.user,
        "Password Changed",
        "Your account password was changed from Settings.",
        "security",
    )
    login(request, request.user)
    initialize_secure_session(request)
    record_audit_log(
        action="password_changed",
        summary="Password changed from settings.",
        category="account",
        status="success",
        request=request,
        user=request.user,
    )
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

        subject = sanitize_text_input(request.POST.get("subject"), max_length=120)
        message_text = sanitize_text_input(request.POST.get("message"), max_length=1000)
        if not subject or not message_text:
            messages.error(request, "Please fill subject and message.")
            return redirect(redirect_target)

        SupportTicket.objects.create(user=request.user, subject=subject, message=message_text)
        record_audit_log(
            action="support_ticket_created",
            summary="Support ticket submitted.",
            category="account",
            status="success",
            request=request,
            user=request.user,
            metadata={"subject": subject},
        )
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
            Booking.objects.select_related(
                "user",
                "active_activity_slot",
                "helper_activity_slot",
                "ticket_type",
            )
            .exclude(status=Booking.STATUS_CANCELLED)
            .order_by("-booking_date")
        ),
        to_attr="participant_bookings",
    )
    events = (
        Event.objects.filter(created_by=request.user)
        .select_related("private_event_payment")
        .annotate(
            ticket_types_count=Count("ticket_types", distinct=True),
            active_participants_applied=Count(
                "bookings",
                filter=Q(bookings__application_role=Booking.ROLE_ACTIVE_PARTICIPANT)
                & ~Q(bookings__status=Booking.STATUS_CANCELLED),
                distinct=True,
            ),
            helpers_applied=Count(
                "bookings",
                filter=Q(bookings__application_role=Booking.ROLE_HELPER_TEAM)
                & ~Q(bookings__status=Booking.STATUS_CANCELLED),
                distinct=True,
            ),
        )
        .prefetch_related(participant_prefetch, "ticket_types")
        .order_by("-date")
    )
    events = list(events)
    for event in events:
        try:
            event.private_payment = event.private_event_payment
        except PrivateEventPayment.DoesNotExist:
            event.private_payment = None
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
            "ticket_type",
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
        if inline_section == "attendance":
            inline_section = "participants"
        show_participants_table = inline_section in {"all", "participants"}
        show_attendance_table = False
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
        show_ticket_types = event_type != "private"
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
                "show_ticket_types": show_ticket_types,
                "ticket_type_rows": build_ticket_type_form_rows(fallback_price=0),
            },
        )

    title = sanitize_text_input(request.POST.get("title"), max_length=180)
    category = sanitize_text_input(request.POST.get("category"), max_length=80)
    location = sanitize_text_input(request.POST.get("location"), max_length=180)
    date_value = request.POST.get("date")
    time_value = build_event_time_from_post(request)
    description = sanitize_text_input(request.POST.get("description"))
    attendees_usage = sanitize_text_input(request.POST.get("attendeesUsage"), max_length=220)
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
    ticket_type_rows = []
    if not is_private:
        active_activity_slots, active_activity_error = parse_active_activity_slots_from_post(request)
        if active_activity_error:
            messages.error(request, active_activity_error)
            return redirect("new_event")
        helper_activity_slots, helper_activity_error = parse_helper_activity_slots_from_post(request)
        if helper_activity_error:
            messages.error(request, helper_activity_error)
            return redirect("new_event")
        ticket_type_rows, ticket_type_error = parse_ticket_types_from_post(request)
        if ticket_type_error:
            messages.error(request, ticket_type_error)
            return redirect("new_event")
        if not ticket_type_rows:
            ticket_type_rows = default_single_ticket_type_payload(price)
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

    public_base_price = price
    if ticket_type_rows:
        public_base_price = min(item["price"] for item in ticket_type_rows)

    profile = get_or_create_profile(request.user)
    event_data = {
        "title": title,
        "category": category,
        "location": location,
        "date": date_value,
        "time": time_value,
        "price": private_event_amount if is_private else public_base_price,
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
                ticket_type_sync_error = sync_event_ticket_types(event, ticket_type_rows)
                if ticket_type_sync_error:
                    raise ValueError(ticket_type_sync_error)
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
        record_audit_log(
            action="event_created",
            summary=f"Private event '{event.title}' created.",
            category="event",
            status="success",
            request=request,
            user=request.user,
            metadata={"event_id": event.id, "is_private": True},
        )
        return redirect("private_event_payment_page", payment_id=payment.id)

    record_audit_log(
        action="event_created",
        summary=f"Event '{event.title}' created.",
        category="event",
        status="success",
        request=request,
        user=request.user,
        metadata={"event_id": event.id, "is_private": False},
    )
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
        show_ticket_types = not event.is_private
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
                "show_ticket_types": show_ticket_types,
                "ticket_type_rows": build_ticket_type_form_rows(event=event, fallback_price=event.price),
            },
        )

    title = sanitize_text_input(request.POST.get("title"), max_length=180)
    category = sanitize_text_input(request.POST.get("category"), max_length=80)
    location = sanitize_text_input(request.POST.get("location"), max_length=180)
    date_value = request.POST.get("date")
    time_value = build_event_time_from_post(request)
    description = sanitize_text_input(request.POST.get("description"))
    attendees_usage = sanitize_text_input(request.POST.get("attendeesUsage"), max_length=220)
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
    ticket_type_rows = []
    if not is_private:
        active_activity_slots, active_activity_error = parse_active_activity_slots_from_post(request)
        if active_activity_error:
            messages.error(request, active_activity_error)
            return redirect("edit_event", event_id=event.id)
        helper_activity_slots, helper_activity_error = parse_helper_activity_slots_from_post(request)
        if helper_activity_error:
            messages.error(request, helper_activity_error)
            return redirect("edit_event", event_id=event.id)
        ticket_type_rows, ticket_type_error = parse_ticket_types_from_post(request)
        if ticket_type_error:
            messages.error(request, ticket_type_error)
            return redirect("edit_event", event_id=event.id)
        if not ticket_type_rows:
            ticket_type_rows = default_single_ticket_type_payload(price)
    active_participants_required, active_participants_usage = summarize_active_activity_slots(
        active_activity_slots
    )
    helpers_required, helpers_usage = summarize_helper_activity_slots(helper_activity_slots)
    private_event_guest_count = len(guest_email_list)
    private_event_amount = calculate_private_event_creation_amount(private_event_guest_count)
    public_base_price = price
    if ticket_type_rows:
        public_base_price = min(item["price"] for item in ticket_type_rows)

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
    event.price = private_event_amount if is_private else public_base_price
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
            ticket_type_sync_error = sync_event_ticket_types(
                event,
                [] if is_private else ticket_type_rows,
            )
            if ticket_type_sync_error:
                raise ValueError(ticket_type_sync_error)
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

    record_audit_log(
        action="event_updated",
        summary=f"Event '{event.title}' updated.",
        category="event",
        status="success",
        request=request,
        user=request.user,
        metadata={"event_id": event.id, "is_private": event.is_private},
    )
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
    event_id_value = event.id
    event.delete()
    record_audit_log(
        action="event_deleted",
        summary=f"Event '{event_title}' deleted.",
        category="event",
        status="success",
        request=request,
        user=request.user,
        metadata={"event_id": event_id_value},
    )
    messages.success(request, f"Event '{event_title}' deleted successfully.")
    return redirect("my_events")


@role_required(Profile.ROLE_ORGANIZER)
def organizer_bookings(request):
    ensure_seeded()
    bookings = (
        Booking.objects.filter(event__created_by=request.user)
        .select_related("event", "user", "ticket_type")
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
        record_audit_log(
            action="account_deleted",
            summary=f"Account '{username}' deleted.",
            category="account",
            status="success",
            request=request,
            user=user,
        )
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


# ============================================================
# NEW FEATURES: Admin Dashboard, Social Login, 2FA, Email Verification, Trending Events
# ============================================================


@admin_required
def admin_dashboard(request):
    """Admin dashboard showing all platform statistics."""
    ensure_seeded()
    
    # Get overall statistics
    total_users = User.objects.count()
    total_events = Event.objects.count()
    total_bookings = Booking.objects.count()
    total_payments = Payment.objects.filter(status=Payment.STATUS_PAID).aggregate(
        total=Sum("amount")
    )["total"] or 0
    
    # Recent bookings
    recent_bookings = Booking.objects.select_related(
        "user", "event"
    ).order_by("-booking_date")[:10]
    
    # Recent users
    recent_users = Profile.objects.select_related("user").order_by("-created_at")[:10]
    
    # Support tickets
    open_tickets = SupportTicket.objects.filter(
        status=SupportTicket.STATUS_OPEN
    ).count()
    recent_security_events = SecurityAuditLog.objects.select_related("user").order_by("-created_at")[:10]
    
    stats = {
        "total_users": total_users,
        "total_events": total_events,
        "total_bookings": total_bookings,
        "total_payments": total_payments,
        "open_tickets": open_tickets,
    }
    
    return render_app(
        request,
        "core/admin_dashboard.html",
        "dashboard",
        {
            "stats": stats,
            "recent_bookings": recent_bookings,
            "recent_users": recent_users,
            "recent_security_events": recent_security_events,
        },
    )


@admin_required
def admin_events(request):
    """Admin page to view all events."""
    ensure_seeded()
    events = Event.objects.select_related("created_by").order_by("-created_at")
    return render_app(
        request,
        "core/admin_events.html",
        "admin-events",
        {"events": events},
    )


@admin_required
def admin_users(request):
    """Admin page to view all users."""
    ensure_seeded()
    profiles = Profile.objects.select_related("user").order_by("-created_at")
    return render_app(
        request,
        "core/admin_users.html",
        "admin-users",
        {"profiles": profiles},
    )


@admin_required
def admin_bookings(request):
    """Admin page to view all bookings."""
    ensure_seeded()
    bookings = Booking.objects.select_related(
        "user", "event"
    ).order_by("-booking_date")
    return render_app(
        request,
        "core/admin_bookings.html",
        "admin-tickets",
        {"bookings": bookings},
    )


@admin_required
def admin_payments(request):
    """Admin page to view all payments."""
    ensure_seeded()
    payments = Payment.objects.select_related(
        "booking", "booking__user", "booking__event"
    ).order_by("-paid_at")
    return render_app(
        request,
        "core/admin_payments.html",
        "admin-payments",
        {"payments": payments},
    )


@admin_required
def admin_support(request):
    """Admin page to view all support tickets."""
    ensure_seeded()
    tickets = SupportTicket.objects.select_related("user").order_by("-created_at")
    return render_app(
        request,
        "core/admin_support.html",
        "admin-support",
        {"tickets": tickets},
    )


@admin_required
def admin_resolve_ticket(request, ticket_id):
    """Admin action to resolve a support ticket."""
    ensure_seeded()
    if request.method == "POST":
        ticket = get_object_or_404(SupportTicket, id=ticket_id)
        ticket.status = SupportTicket.STATUS_RESOLVED
        ticket.save(update_fields=["status"])
        record_audit_log(
            action="support_ticket_resolved",
            summary=f"Support ticket #{ticket_id} resolved by admin.",
            category="admin",
            status="success",
            request=request,
            user=request.user,
            metadata={"ticket_id": ticket_id},
        )
        messages.success(request, f"Ticket #{ticket_id} resolved.")
    return redirect("admin_support")


def social_login_google(request):
    ensure_seeded()
    provider = get_google_oauth_config()
    if not oauth_provider_ready(provider):
        return _render_social_login_setup_page(request, "Google")

    redirect_uri = _oauth_redirect_uri(request, "social_login_google", "GOOGLE_OAUTH_REDIRECT_URI")
    error = (request.GET.get("error") or "").strip()
    if error:
        messages.error(request, f"Google login was cancelled or failed: {error}.")
        return redirect("auth_page")

    code = (request.GET.get("code") or "").strip()
    if not code:
        state = generate_oauth_state()
        request.session[_oauth_state_key("google")] = state
        return redirect(build_google_auth_url(redirect_uri, state))

    returned_state = (request.GET.get("state") or "").strip()
    expected_state = request.session.pop(_oauth_state_key("google"), "")
    if not expected_state or not secrets.compare_digest(expected_state, returned_state):
        messages.error(request, "Google login state validation failed. Please try again.")
        return redirect("auth_page")

    try:
        token_payload = exchange_google_code(code, redirect_uri)
        access_token = (token_payload or {}).get("access_token", "").strip()
        if not access_token:
            raise IntegrationError("Google access token was not returned.")
        google_profile = fetch_google_profile(access_token)
        user, profile, created = sync_social_user(
            "google",
            google_profile.get("sub"),
            google_profile.get("email"),
            first_name=(google_profile.get("given_name") or google_profile.get("name") or "").strip(),
            last_name=(google_profile.get("family_name") or "").strip(),
        )
    except (IntegrationError, ValidationError) as exc:
        messages.error(request, f"Google login failed: {exc}")
        return redirect("auth_page")

    info_message = None
    if created:
        info_message = "Your Eventify account was created with Google."
    return complete_login_after_primary_auth(
        request,
        user,
        profile,
        info_message=info_message,
        auth_source="google",
    )


def social_login_github(request):
    ensure_seeded()
    provider = get_github_oauth_config()
    if not oauth_provider_ready(provider):
        return _render_social_login_setup_page(request, "GitHub")

    redirect_uri = _oauth_redirect_uri(request, "social_login_github", "GITHUB_OAUTH_REDIRECT_URI")
    error = (request.GET.get("error") or "").strip()
    if error:
        messages.error(request, f"GitHub login was cancelled or failed: {error}.")
        return redirect("auth_page")

    code = (request.GET.get("code") or "").strip()
    if not code:
        state = generate_oauth_state()
        request.session[_oauth_state_key("github")] = state
        return redirect(build_github_auth_url(redirect_uri, state))

    returned_state = (request.GET.get("state") or "").strip()
    expected_state = request.session.pop(_oauth_state_key("github"), "")
    if not expected_state or not secrets.compare_digest(expected_state, returned_state):
        messages.error(request, "GitHub login state validation failed. Please try again.")
        return redirect("auth_page")

    try:
        token_payload = exchange_github_code(code, redirect_uri)
        access_token = (token_payload or {}).get("access_token", "").strip()
        if not access_token:
            raise IntegrationError("GitHub access token was not returned.")
        github_profile = fetch_github_profile(access_token)
        github_emails = fetch_github_emails(access_token)
        primary_email = next(
            (
                item.get("email")
                for item in github_emails
                if item.get("email") and item.get("verified") and item.get("primary")
            ),
            None,
        )
        if not primary_email:
            primary_email = next(
                (
                    item.get("email")
                    for item in github_emails
                    if item.get("email") and item.get("verified")
                ),
                github_profile.get("email"),
            )
        display_name = (github_profile.get("name") or github_profile.get("login") or "").strip()
        first_name = display_name.split()[0] if display_name else ""
        last_name = " ".join(display_name.split()[1:]) if len(display_name.split()) > 1 else ""
        user, profile, created = sync_social_user(
            "github",
            github_profile.get("id"),
            primary_email,
            first_name=first_name,
            last_name=last_name,
        )
    except (IntegrationError, ValidationError) as exc:
        messages.error(request, f"GitHub login failed: {exc}")
        return redirect("auth_page")

    info_message = None
    if created:
        info_message = "Your Eventify account was created with GitHub."
    return complete_login_after_primary_auth(
        request,
        user,
        profile,
        info_message=info_message,
        auth_source="github",
    )


@login_required(login_url="auth_page")
def verify_email(request):
    """Send email verification link."""
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    
    if request.method == "POST":
        if profile.email_verified:
            messages.info(request, "Your email is already verified.")
            return redirect("dashboard")
        
        # Generate verification token
        import secrets
        token = secrets.token_urlsafe(32)
        profile.verification_token = token
        profile.save(update_fields=["verification_token"])
        
        verification_link = request.build_absolute_uri(
            f"/verify-email-confirm/?token={token}"
        )

        recipient = (request.user.email or "").strip()
        if not recipient:
            messages.error(request, "Add your email in profile before requesting verification.")
            return redirect("profile")

        from_email = (
            (getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip()
            or (getattr(settings, "EMAIL_HOST_USER", "") or "").strip()
            or "webmaster@localhost"
        )
        email_subject = "Eventify Email Verification"
        email_body = "\n".join(
            [
                f"Hi {request.user.first_name or request.user.username},",
                "",
                "Verify your Eventify email by opening this link:",
                verification_link,
                "",
                "If you did not request this, you can ignore this email.",
            ]
        )
        try:
            EmailMessage(
                subject=email_subject,
                body=email_body,
                from_email=from_email,
                to=[recipient],
            ).send(fail_silently=False)
            record_audit_log(
                action="email_verification_requested",
                summary="Email verification link sent.",
                category="account",
                status="success",
                request=request,
                user=request.user,
            )
            messages.success(request, "Verification email sent successfully.")
        except Exception:
            messages.warning(
                request,
                f"Verification email could not be sent. Demo link: {verification_link}",
            )
        return redirect("settings")
    
    return render_app(
        request,
        "core/verify_email.html",
        "settings",
        {
            "is_email_verified": profile.email_verified,
            "account_email": request.user.email,
        },
    )


def verify_email_confirm(request):
    """Confirm email verification with token."""
    ensure_seeded()
    token = request.GET.get("token", "").strip()
    
    if not token:
        messages.error(request, "Invalid verification token.")
        return redirect("home")
    
    profile = Profile.objects.filter(verification_token=token).first()
    
    if not profile:
        messages.error(request, "Invalid or expired verification token.")
        return redirect("home")
    
    profile.email_verified = True
    profile.verification_token = ""
    profile.save(update_fields=["email_verified", "verification_token"])
    record_audit_log(
        action="email_verified",
        summary="Email verification completed.",
        category="account",
        status="success",
        request=request,
        user=profile.user,
    )
    
    messages.success(request, "Email verified successfully!")
    
    if request.user.is_authenticated:
        return redirect("dashboard")
    return redirect("auth_page")


@login_required(login_url="auth_page")
def setup_2fa(request):
    """Setup Two-Factor Authentication."""
    ensure_seeded()
    profile = get_or_create_profile(request.user)

    if profile.two_factor_enabled:
        messages.info(request, "2FA is already enabled.")
        return redirect("settings")

    return render_app(
        request,
        "core/setup_2fa.html",
        "settings",
        build_2fa_setup_context(request, profile),
    )


@login_required(login_url="auth_page")
def enable_2fa(request):
    """Enable 2FA after verification."""
    ensure_seeded()
    profile = get_or_create_profile(request.user)

    if request.method != "POST":
        return redirect("setup_2fa")

    ensure_totp_setup_material(profile)
    code = "".join((request.POST.get("code") or "").split())
    if not verify_totp_code(profile.two_factor_secret, code):
        messages.error(request, "Invalid authenticator code. Please try again.")
        return redirect("setup_2fa")

    profile.two_factor_enabled = True
    profile.save(update_fields=["two_factor_enabled"])
    record_audit_log(
        action="two_factor_enabled",
        summary="Two-factor authentication enabled.",
        category="account",
        status="success",
        request=request,
        user=request.user,
    )
    messages.success(request, "Two-Factor Authentication enabled.")
    return redirect("settings")


@login_required(login_url="auth_page")
def disable_2fa(request):
    """Disable Two-Factor Authentication."""
    ensure_seeded()
    profile = get_or_create_profile(request.user)
    
    if not profile.two_factor_enabled:
        messages.info(request, "2FA is not enabled.")
        return redirect("settings")
    
    if request.method == "POST":
        # Require password to disable
        password = request.POST.get("password", "")
        if not check_password(password, request.user.password):
            messages.error(request, "Incorrect password.")
            return redirect("disable_2fa")
        
        profile.two_factor_enabled = False
        profile.two_factor_secret = ""
        profile.two_factor_backup_codes = []
        profile.save(update_fields=[
            "two_factor_enabled", 
            "two_factor_secret", 
            "two_factor_backup_codes"
        ])
        record_audit_log(
            action="two_factor_disabled",
            summary="Two-factor authentication disabled.",
            category="account",
            status="success",
            request=request,
            user=request.user,
        )
        messages.success(request, "Two-Factor Authentication disabled.")
        return redirect("settings")
    
    return render_app(request, "core/disable_2fa.html", "settings")


def verify_2fa(request):
    """Verify 2FA code during login."""
    ensure_seeded()
    user_id = request.session.get("2fa_user_id")
    expected_role = request.session.get("2fa_expected_role")
    if not user_id:
        messages.error(request, "2FA session has expired. Please login again.")
        return redirect("auth_page")

    user = User.objects.filter(id=user_id).first()
    if not user:
        request.session.pop("2fa_user_id", None)
        request.session.pop("2fa_expected_role", None)
        messages.error(request, "2FA user not found. Please login again.")
        return redirect("auth_page")

    profile = get_or_create_profile(user)
    if expected_role and profile.role != expected_role:
        request.session.pop("2fa_user_id", None)
        request.session.pop("2fa_expected_role", None)
        messages.error(request, "Role mismatch detected. Please login again.")
        return redirect("auth_page")

    if request.method == "GET":
        return render(
            request,
            "core/verify_2fa.html",
            {
                "backup_code_count": len(profile.two_factor_backup_codes or []),
            },
        )

    code = "".join((request.POST.get("code") or "").split())
    if not code:
        messages.error(request, "Enter a 2FA code or backup code.")
        return redirect("verify_2fa")

    verified = False
    if profile.two_factor_secret and verify_totp_code(profile.two_factor_secret, code):
        verified = True
    else:
        backup_code = code.upper()
        active_backup_codes = list(profile.two_factor_backup_codes or [])
        if backup_code in active_backup_codes:
            active_backup_codes.remove(backup_code)
            profile.two_factor_backup_codes = active_backup_codes
            profile.save(update_fields=["two_factor_backup_codes"])
            verified = True

    if not verified:
        record_audit_log(
            action="two_factor_failed",
            summary="Invalid two-factor verification code.",
            category="auth",
            status="failure",
            request=request,
            user=user,
        )
        messages.error(request, "Invalid verification code.")
        return redirect("verify_2fa")

    login(request, user)
    initialize_secure_session(request)
    auth_source = request.session.get("2fa_auth_source", "password")
    clear_pending_2fa_session(request)
    record_audit_log(
        action="login_success",
        summary=f"Successful {auth_source} login after 2FA verification.",
        category="auth",
        status="success",
        request=request,
        user=user,
        metadata={"auth_source": auth_source, "role": profile.role, "two_factor": True},
    )
    messages.success(request, "Login successful.")
    return redirect("dashboard")


# ============================================================
# Event Schedule Management Views
# ============================================================


@role_required(Profile.ROLE_ORGANIZER)
def event_schedule_add(request, event_id):
    """Add a schedule item to an event."""
    ensure_seeded()
    event = get_object_or_404(Event, id=event_id, created_by=request.user)
    
    if request.method == "POST":
        title = sanitize_text_input(request.POST.get("title"), max_length=180)
        description = sanitize_text_input(request.POST.get("description"))
        start_time = request.POST.get("start_time", "").strip()
        end_time = request.POST.get("end_time", "").strip()
        speaker_name = sanitize_text_input(request.POST.get("speaker_name"), max_length=120)
        location = sanitize_text_input(request.POST.get("location"), max_length=180)
        
        if not title or not start_time or not end_time:
            messages.error(request, "Please fill required fields.")
            return redirect("event_schedule_add", event_id=event.id)
        
        EventSchedule.objects.create(
            event=event,
            title=title,
            description=description,
            start_time=start_time,
            end_time=end_time,
            speaker_name=speaker_name,
            location=location,
        )
        record_audit_log(
            action="event_schedule_added",
            summary=f"Schedule item added to '{event.title}'.",
            category="event",
            status="success",
            request=request,
            user=request.user,
            metadata={"event_id": event.id},
        )
        
        messages.success(request, "Schedule item added.")
        return redirect("event_detail", event_id=event.id)
    
    return render_app(
        request,
        "core/event_schedule_form.html",
        "my-events",
        {"event": event, "action": "add"},
    )


@role_required(Profile.ROLE_ORGANIZER)
def event_schedule_edit(request, schedule_id):
    """Edit a schedule item."""
    ensure_seeded()
    schedule = get_object_or_404(
        EventSchedule, 
        id=schedule_id, 
        event__created_by=request.user
    )
    
    if request.method == "POST":
        schedule.title = sanitize_text_input(request.POST.get("title"), max_length=180)
        schedule.description = sanitize_text_input(request.POST.get("description"))
        schedule.start_time = request.POST.get("start_time", "").strip()
        schedule.end_time = request.POST.get("end_time", "").strip()
        schedule.speaker_name = sanitize_text_input(request.POST.get("speaker_name"), max_length=120)
        schedule.location = sanitize_text_input(request.POST.get("location"), max_length=180)
        schedule.save()
        record_audit_log(
            action="event_schedule_updated",
            summary=f"Schedule item updated for '{schedule.event.title}'.",
            category="event",
            status="success",
            request=request,
            user=request.user,
            metadata={"event_id": schedule.event.id, "schedule_id": schedule.id},
        )
        
        messages.success(request, "Schedule updated.")
        return redirect("event_detail", event_id=schedule.event.id)
    
    return render_app(
        request,
        "core/event_schedule_form.html",
        "my-events",
        {"schedule": schedule, "event": schedule.event, "action": "edit"},
    )


@role_required(Profile.ROLE_ORGANIZER)
def event_schedule_delete(request, schedule_id):
    """Delete a schedule item."""
    ensure_seeded()
    schedule = get_object_or_404(
        EventSchedule,
        id=schedule_id,
        event__created_by=request.user
    )
    event_id = schedule.event.id
    if request.method != "POST":
        return redirect("event_detail", event_id=event_id)
    record_audit_log(
        action="event_schedule_deleted",
        summary=f"Schedule item deleted from '{schedule.event.title}'.",
        category="event",
        status="success",
        request=request,
        user=request.user,
        metadata={"event_id": event_id, "schedule_id": schedule.id},
    )
    schedule.delete()
    messages.success(request, "Schedule item deleted.")
    return redirect("event_detail", event_id=event_id)


# ============================================================
# Event Gallery Management Views
# ============================================================


@role_required(Profile.ROLE_ORGANIZER)
def event_gallery_add(request, event_id):
    """Add gallery images to an event."""
    ensure_seeded()
    event = get_object_or_404(Event, id=event_id, created_by=request.user)
    
    if request.method == "POST":
        images = request.FILES.getlist("images")
        caption = sanitize_text_input(request.POST.get("caption"), max_length=255)
        
        if not images:
            messages.error(request, "Please select at least one image.")
            return redirect("event_gallery_add", event_id=event.id)
        
        for image in images:
            upload_error = validate_image_upload(
                image,
                label="Gallery image",
                max_size_bytes=5 * 1024 * 1024,
            )
            if upload_error:
                messages.error(request, upload_error)
                return redirect("event_gallery_add", event_id=event.id)
            EventGallery.objects.create(
                event=event,
                image=image,
                caption=caption,
            )
        record_audit_log(
            action="event_gallery_uploaded",
            summary=f"Gallery images uploaded for '{event.title}'.",
            category="event",
            status="success",
            request=request,
            user=request.user,
            metadata={"event_id": event.id, "image_count": len(images)},
        )
        
        messages.success(request, f"{len(images)} image(s) added to gallery.")
        return redirect("event_detail", event_id=event.id)
    
    return render_app(
        request,
        "core/event_gallery_form.html",
        "my-events",
        {"event": event},
    )


@role_required(Profile.ROLE_ORGANIZER)
def event_gallery_delete(request, gallery_id):
    """Delete a gallery image."""
    ensure_seeded()
    gallery = get_object_or_404(
        EventGallery,
        id=gallery_id,
        event__created_by=request.user
    )
    event_id = gallery.event.id
    if request.method != "POST":
        return redirect("event_detail", event_id=event_id)
    record_audit_log(
        action="event_gallery_deleted",
        summary=f"Gallery image deleted from '{gallery.event.title}'.",
        category="event",
        status="success",
        request=request,
        user=request.user,
        metadata={"event_id": event_id, "gallery_id": gallery.id},
    )
    gallery.delete()
    messages.success(request, "Gallery image deleted.")
    return redirect("event_detail", event_id=event_id)

