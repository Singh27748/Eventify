"""
Eventify Models - Sabhi database tables yahan define hote hain.
Yeh models events, bookings, payments ke liye use hoti hain.
"""

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class Profile(models.Model):
    """
    Profile model - Har user ki extra information store karta hai.
    Jaise role (user/organizer/admin), contact, phone, address, etc.
    """
    ROLE_USER = "user"
    ROLE_ORGANIZER = "organizer"
    ROLE_ADMIN = "admin"
    ROLE_CHOICES = (
        (ROLE_USER, "User"),
        (ROLE_ORGANIZER, "Organizer"),
        (ROLE_ADMIN, "Admin"),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_USER)
    contact = models.CharField(max_length=150)
    phone = models.CharField(max_length=40, blank=True)
    address = models.CharField(max_length=255, blank=True)
    profile_image = models.ImageField(upload_to="profile_images/", blank=True, null=True)
    notification_booking = models.BooleanField(default=True)
    notification_payment = models.BooleanField(default=True)
    notification_updates = models.BooleanField(default=True)
    security_question = models.CharField(max_length=255, blank=True)
    security_answer_hash = models.CharField(max_length=255, blank=True)
    language = models.CharField(max_length=30, default="English")
    dark_mode = models.BooleanField(default=False)
    
    # Email verification
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255, blank=True)
    
    # Social login
    google_id = models.CharField(max_length=255, blank=True)
    github_id = models.CharField(max_length=255, blank=True)
    
    # Two-factor authentication (2FA)
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=255, blank=True)
    two_factor_backup_codes = models.JSONField(default=list, blank=True)

    # Profile completion tracking
    profile_completed = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["contact", "role"], name="uniq_profile_contact_role"),
        ]

    def __str__(self):
        return f"{self.user.username} ({self.role})"


class OTPRequest(models.Model):
    """
    OTP Request model - Login/registration ke liye OTP (One Time Password) store karta hai.
    Registration, password reset, ya account delete ke time use hota hai.
    """
    PURPOSE_REGISTER = "register"
    PURPOSE_RESET = "reset"
    PURPOSE_DELETE_ACCOUNT = "delete_account"
    PURPOSE_SECURITY_EMAIL = "security_email"
    PURPOSE_PASSWORD_EMAIL = "password_email"
    PURPOSE_CHOICES = (
        (PURPOSE_REGISTER, "Register"),
        (PURPOSE_RESET, "Reset"),
        (PURPOSE_DELETE_ACCOUNT, "Delete Account"),
        (PURPOSE_SECURITY_EMAIL, "Security Question Email"),
        (PURPOSE_PASSWORD_EMAIL, "Password Change Email"),
    )

    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES)
    contact = models.CharField(max_length=150)
    role = models.CharField(max_length=20, choices=Profile.ROLE_CHOICES, blank=True)
    name = models.CharField(max_length=120, blank=True)
    password_hash = models.CharField(max_length=255, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    otp = models.CharField(max_length=6)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.expires_at


class LoginThrottle(models.Model):
    """Tracks failed login attempts and temporary lockouts."""

    key = models.CharField(max_length=64, unique=True)
    role = models.CharField(max_length=20, choices=Profile.ROLE_CHOICES)
    contact = models.CharField(max_length=150)
    failed_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(blank=True, null=True)
    last_attempt_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-last_attempt_at"]

    def __str__(self):
        return f"{self.contact} ({self.role})"


class SecurityAuditLog(models.Model):
    """Persistent audit trail for important security and business events."""

    CATEGORY_AUTH = "auth"
    CATEGORY_ACCOUNT = "account"
    CATEGORY_EVENT = "event"
    CATEGORY_BOOKING = "booking"
    CATEGORY_PAYMENT = "payment"
    CATEGORY_ADMIN = "admin"
    CATEGORY_CHOICES = (
        (CATEGORY_AUTH, "Auth"),
        (CATEGORY_ACCOUNT, "Account"),
        (CATEGORY_EVENT, "Event"),
        (CATEGORY_BOOKING, "Booking"),
        (CATEGORY_PAYMENT, "Payment"),
        (CATEGORY_ADMIN, "Admin"),
    )

    STATUS_INFO = "info"
    STATUS_SUCCESS = "success"
    STATUS_FAILURE = "failure"
    STATUS_CHOICES = (
        (STATUS_INFO, "Info"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILURE, "Failure"),
    )

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="security_audit_logs",
    )
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES, default=CATEGORY_AUTH)
    action = models.CharField(max_length=60)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_INFO)
    actor_contact = models.CharField(max_length=150, blank=True)
    summary = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.CharField(max_length=255, blank=True)
    path = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.category}:{self.action}:{self.status}"


class Event(models.Model):
    """
    Event model - Har event ki details store karta hai.
    Jaise title, category, location, date, time, price, description, etc.
    Organizers apni events create karte hain, aur users book karte hain.
    """
    title = models.CharField(max_length=180)
    category = models.CharField(max_length=80)
    location = models.CharField(max_length=180)
    date = models.DateField()
    time = models.CharField(max_length=80)
    price = models.PositiveIntegerField(default=0)
    description = models.TextField()
    is_private = models.BooleanField(default=False, help_text="If private, event is only accessible via direct link")
    guest_emails = models.TextField(blank=True, help_text="Comma-separated list of guest emails for private events")
    active_participant_emails = models.TextField(blank=True, help_text="Comma-separated list of active participant emails")
    attendees_required = models.PositiveIntegerField(default=0)
    attendees_usage = models.CharField(max_length=220, blank=True)
    active_participants_required = models.PositiveIntegerField(default=0)
    active_participants_usage = models.CharField(max_length=220, blank=True)
    helpers_required = models.PositiveIntegerField(default=0)
    helpers_usage = models.CharField(max_length=220, blank=True)
    image_url = models.URLField(blank=True, null=True)
    image_file = models.ImageField(upload_to="event_images/", blank=True, null=True)
    organizer_name = models.CharField(max_length=120)
    organizer_phone = models.CharField(max_length=40, blank=True)
    organizer_email = models.EmailField(blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="created_events"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

    @property
    def image_source(self):
        if self.image_file:
            try:
                return self.image_file.url
            except ValueError:
                pass
        return (self.image_url or "").strip()


class EventActivitySlot(models.Model):
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="active_activity_slots",
    )
    name = models.CharField(max_length=220)
    required_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return f"{self.event.title} :: {self.name} ({self.required_count})"


class EventHelperSlot(models.Model):
    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
        related_name="helper_activity_slots",
    )
    name = models.CharField(max_length=220)
    required_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return f"{self.event.title} :: Helper {self.name} ({self.required_count})"


class Booking(models.Model):
    """
    Booking model - User ki event booking store karta hai.
    Ek user ek event ke liye booking kar sakta hai.
    Isme tickets, status, payment status, aur role (attendee/active participant/helper) hota hai.
    """
    STATUS_PENDING = "pending"
    STATUS_CONFIRMED = "confirmed"
    STATUS_COMPLETED = "completed"
    STATUS_CANCELLED = "cancelled"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_CONFIRMED, "Confirmed"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_CANCELLED, "Cancelled"),
    )

    PAYMENT_UNPAID = "unpaid"
    PAYMENT_PAID = "paid"
    PAYMENT_REFUNDED = "refunded"
    PAYMENT_CHOICES = (
        (PAYMENT_UNPAID, "Unpaid"),
        (PAYMENT_PAID, "Paid"),
        (PAYMENT_REFUNDED, "Refunded"),
    )

    ROLE_ATTENDEE = "attendee"
    ROLE_ACTIVE_PARTICIPANT = "active_participant"
    ROLE_HELPER_TEAM = "helper_team"
    APPLICATION_ROLE_CHOICES = (
        (ROLE_ATTENDEE, "Audience Ticket"),
        (ROLE_ACTIVE_PARTICIPANT, "Active Participant"),
        (ROLE_HELPER_TEAM, "Helper Team"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="bookings")
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="bookings")
    ticket_type = models.ForeignKey(
        "TicketType",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="bookings",
    )
    tickets = models.PositiveIntegerField(default=1)
    attendee_name = models.CharField(max_length=120)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    payment_status = models.CharField(
        max_length=20, choices=PAYMENT_CHOICES, default=PAYMENT_UNPAID
    )
    application_role = models.CharField(
        max_length=30,
        choices=APPLICATION_ROLE_CHOICES,
        default=ROLE_ATTENDEE,
    )
    active_activity_slot = models.ForeignKey(
        EventActivitySlot,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="bookings",
    )
    helper_activity_slot = models.ForeignKey(
        EventHelperSlot,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="bookings",
    )
    total_amount = models.PositiveIntegerField(default=0)
    invoice_no = models.CharField(max_length=80, blank=True)
    booking_date = models.DateTimeField(auto_now_add=True)
    attendance_marked_at = models.DateTimeField(blank=True, null=True)

    @property
    def ticket_reference(self):
        booking_id = int(self.pk or 0)
        event_id = int(self.event_id or 0)

        def _to_base36(value):
            digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            number = int(value or 0)
            if number <= 0:
                return "0"

            encoded = []
            while number:
                number, remainder = divmod(number, 36)
                encoded.append(digits[remainder])
            return "".join(reversed(encoded))

        event_code = _to_base36(event_id).zfill(4)
        booking_code = _to_base36(booking_id).zfill(6)
        return f"TKT-E{event_code}-B{booking_code}"

    @property
    def applied_role_label(self):
        label = self.get_application_role_display()
        if self.application_role == self.ROLE_ACTIVE_PARTICIPANT and self.active_activity_slot_id:
            slot_name = (self.active_activity_slot.name or "").strip()
            if slot_name:
                return f"{label} - {slot_name}"
        if self.application_role == self.ROLE_HELPER_TEAM and self.helper_activity_slot_id:
            slot_name = (self.helper_activity_slot.name or "").strip()
            if slot_name:
                return f"{label} - {slot_name}"
        return label

    def __str__(self):
        return f"Booking #{self.pk} - {self.event.title}"


class Payment(models.Model):
    """
    Payment model - Booking ke payment ki details store karta hai.
    Isme amount, method (UPI/Card/Net Banking/Wallet), status, transaction ref hota hai.
    Har booking ke liye ek ya zyada payments ho sakte hain.
    """
    STATUS_PAID = "paid"
    STATUS_REFUNDED = "refunded"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_PAID, "Paid"),
        (STATUS_REFUNDED, "Refunded"),
        (STATUS_FAILED, "Failed"),
    )

    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name="payments")
    amount = models.PositiveIntegerField()
    method = models.CharField(max_length=80)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PAID)
    transaction_ref = models.CharField(max_length=80, blank=True, default="")
    upi_id = models.CharField(max_length=120, blank=True, default="")
    gateway_provider = models.CharField(max_length=80, blank=True, default="")
    gateway_payment_id = models.CharField(max_length=120, blank=True, default="")
    verification_signature = models.CharField(max_length=180, blank=True, default="")
    verification_status = models.CharField(max_length=20, default="verified")
    failure_reason = models.TextField(blank=True, default="")
    coupon_code = models.CharField(max_length=40, blank=True, default="")
    discount_amount = models.PositiveIntegerField(default=0)
    payment_meta = models.JSONField(default=dict, blank=True)
    refunded_at = models.DateTimeField(blank=True, null=True)
    paid_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-paid_at", "-id"]

    def __str__(self):
        return f"{self.booking.ticket_reference} | {self.status} | {self.amount}"

    @property
    def method_detail_summary(self):
        meta = self.payment_meta or {}
        if self.status == self.STATUS_REFUNDED:
            refund_destination = (meta.get("refund_destination_summary") or "").strip()
            original_transaction_ref = (meta.get("original_transaction_ref") or "").strip()
            refund_mode = (meta.get("refund_mode") or "").strip()
            parts = []
            if refund_destination:
                parts.append(f"Refunded to {refund_destination}")
            elif self.method:
                parts.append(f"Refunded to {self.method}")
            if original_transaction_ref:
                parts.append(f"Original Txn {original_transaction_ref}")
            if refund_mode:
                parts.append(f"{refund_mode.title()} refund")
            if parts:
                return " | ".join(parts)
        if self.method == "UPI":
            return meta.get("upi_id") or self.upi_id or "-"
        if self.method == "Card":
            holder = meta.get("card_holder_name") or "Card"
            last4 = meta.get("card_last4") or "----"
            expiry = meta.get("card_expiry") or "-"
            return f"{holder} | **** {last4} | {expiry}"
        if self.method == "Net Banking":
            bank_name = meta.get("bank_name") or "Bank"
            account_holder = meta.get("account_holder_name") or "Account"
            account_last4 = meta.get("account_last4") or "----"
            return f"{bank_name} | {account_holder} | **** {account_last4}"
        if self.method == "Wallet":
            provider = meta.get("wallet_provider") or "Wallet"
            mobile_last4 = meta.get("wallet_mobile_last4") or "----"
            return f"{provider} | **** {mobile_last4}"
        return "-"


class PromoCode(models.Model):
    """
    PromoCode model - Discount coupons ke liye use hota hai.
    Organizers promo codes create karte hain jisme percentage ya fixed discount milta hai.
    Users booking ke time promo code apply kar sakte hain.
    """
    DISCOUNT_PERCENTAGE = "percentage"
    DISCOUNT_FIXED = "fixed"
    DISCOUNT_CHOICES = (
        (DISCOUNT_PERCENTAGE, "Percentage"),
        (DISCOUNT_FIXED, "Fixed"),
    )

    code = models.CharField(max_length=40, unique=True)
    description = models.CharField(max_length=160, blank=True)
    discount_type = models.CharField(max_length=20, choices=DISCOUNT_CHOICES, default=DISCOUNT_PERCENTAGE)
    discount_value = models.PositiveIntegerField(default=0)
    active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    max_uses = models.PositiveIntegerField(default=0)
    used_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["code"]

    def __str__(self):
        return self.code

    @property
    def is_expired(self):
        if not self.expires_at:
            return False
        return self.expires_at <= timezone.now()

    def can_use(self):
        if not self.active or self.is_expired:
            return False
        if self.max_uses and self.used_count >= self.max_uses:
            return False
        return True

    def calculate_discount(self, amount):
        amount_value = max(0, int(amount or 0))
        discount_value = max(0, int(self.discount_value or 0))
        if self.discount_type == self.DISCOUNT_FIXED:
            return min(amount_value, discount_value)
        percentage_discount = (amount_value * discount_value) // 100
        return min(amount_value, percentage_discount)


class HomepageHeroPromo(models.Model):
    eyebrow = models.CharField(max_length=80)
    headline = models.CharField(max_length=180)
    description = models.TextField()
    chip_one = models.CharField(max_length=40, blank=True)
    chip_two = models.CharField(max_length=40, blank=True)
    chip_three = models.CharField(max_length=40, blank=True)
    image_url = models.URLField(blank=True, null=True)
    image_file = models.ImageField(upload_to="homepage_hero/", blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return self.headline

    @property
    def image_source(self):
        if self.image_file:
            try:
                return self.image_file.url
            except ValueError:
                pass
        return (self.image_url or "").strip()


class EventAdvertisement(models.Model):
    """
    EventAdvertisement model - Public event advertisement approval workflow.
    Organizers can request advertisement; admins approve/reject.
    """

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    )

    event = models.OneToOneField(
        Event,
        on_delete=models.CASCADE,
        related_name="advertisement",
    )
    requested_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="event_ad_requests",
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    requested_at = models.DateTimeField(auto_now_add=True)
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="event_ad_reviews",
    )
    reviewed_at = models.DateTimeField(blank=True, null=True)
    admin_note = models.CharField(max_length=255, blank=True)
    notified_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ["-requested_at", "-id"]

    def __str__(self):
        return f"Ad Request: {self.event.title} ({self.status})"


class AdvertisementSettings(models.Model):
    """
    Global advertisement rotation settings for homepage slots.
    """

    rotation_seconds = models.PositiveSmallIntegerField(default=8)
    slot_count = models.PositiveSmallIntegerField(default=2)
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="advertisement_settings_updates",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-id"]

    def __str__(self):
        return f"Advertisement Settings ({self.rotation_seconds}s)"


class AdvertisementSlot(models.Model):
    """
    Slot configuration for homepage advertisement cards.
    """

    SIZE_COMPACT = "compact"
    SIZE_STANDARD = "standard"
    SIZE_LARGE = "large"
    SIZE_WIDE = "wide"
    SIZE_CHOICES = (
        (SIZE_COMPACT, "Compact"),
        (SIZE_STANDARD, "Standard"),
        (SIZE_LARGE, "Large"),
        (SIZE_WIDE, "Wide"),
    )

    DESIGN_CLASSIC = "classic"
    DESIGN_GLASS = "glass"
    DESIGN_BOLD = "bold"
    DESIGN_SOFT = "soft"
    DESIGN_CHOICES = (
        (DESIGN_CLASSIC, "Classic"),
        (DESIGN_GLASS, "Glass"),
        (DESIGN_BOLD, "Bold"),
        (DESIGN_SOFT, "Soft"),
    )

    slot_index = models.PositiveSmallIntegerField(default=0, unique=True)
    rotation_seconds = models.PositiveSmallIntegerField(default=8)
    size = models.CharField(max_length=12, choices=SIZE_CHOICES, default=SIZE_STANDARD)
    design = models.CharField(max_length=12, choices=DESIGN_CHOICES, default=DESIGN_CLASSIC)
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="advertisement_slot_updates",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["slot_index"]

    def __str__(self):
        return f"Advertisement Slot {self.slot_index}"


class AdvertisementSlotItem(models.Model):
    """
    Assign approved advertisements to slots with ordering.
    """

    slot = models.ForeignKey(
        AdvertisementSlot,
        on_delete=models.CASCADE,
        related_name="items",
    )
    advertisement = models.ForeignKey(
        EventAdvertisement,
        on_delete=models.CASCADE,
        related_name="slot_items",
    )
    position = models.PositiveSmallIntegerField(default=1)

    class Meta:
        ordering = ["slot", "position", "id"]
        unique_together = (("slot", "advertisement"),)

    def __str__(self):
        return f"Slot {self.slot.slot_index} -> {self.advertisement.event.title}"


class PrivateEventPayment(models.Model):
    """
    PrivateEventPayment model - Private events ke liye payment track karta hai.
    Jab koi organizer private event create karta hai, toh guest emails ke hisab se fee lagta hai.
    Yeh model us payment ko track karta hai.
    """
    STATUS_PENDING = "pending"
    STATUS_PAID = "paid"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending"),
        (STATUS_PAID, "Paid"),
        (STATUS_FAILED, "Failed"),
    )

    organizer = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="private_event_payments",
    )
    event = models.OneToOneField(
        Event,
        on_delete=models.CASCADE,
        related_name="private_event_payment",
    )
    guest_count = models.PositiveIntegerField(default=0)
    amount = models.PositiveIntegerField(default=0)
    method = models.CharField(max_length=80, blank=True)
    gateway_provider = models.CharField(max_length=80, blank=True, default="")
    gateway_order_id = models.CharField(max_length=120, blank=True, default="")
    gateway_payment_id = models.CharField(max_length=120, blank=True, default="")
    verification_signature = models.CharField(max_length=180, blank=True, default="")
    verification_status = models.CharField(max_length=20, default="pending")
    failure_reason = models.TextField(blank=True, default="")
    payment_meta = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
    )
    paid_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Private Event Payment #{self.pk} - {self.event.title}"


class Notification(models.Model):
    """
    Notification model - Users ko notifications bhejne ke liye use hota hai.
    Jaise booking confirmation, payment update, event reminders, etc.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notifications")
    title = models.CharField(max_length=160)
    message = models.TextField()
    type = models.CharField(max_length=30, default="system")
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class SupportConversation(models.Model):
    """Persistent AI support conversation for a logged-in user."""

    STATUS_ACTIVE = "active"
    STATUS_HANDED_OFF = "handed_off"
    STATUS_CLOSED = "closed"
    STATUS_CHOICES = (
        (STATUS_ACTIVE, "Active"),
        (STATUS_HANDED_OFF, "Handed Off"),
        (STATUS_CLOSED, "Closed"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="support_conversations")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    title = models.CharField(max_length=180, blank=True, default="")
    model_provider = models.CharField(max_length=40, blank=True, default="")
    model_name = models.CharField(max_length=120, blank=True, default="")
    last_summary = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-id"]

    def __str__(self):
        return f"Support conversation #{self.pk} for {self.user.username}"


class SupportMessage(models.Model):
    """Individual support chat messages exchanged with AI or admins."""

    SENDER_USER = "user"
    SENDER_ASSISTANT = "assistant"
    SENDER_ADMIN = "admin"
    SENDER_SYSTEM = "system"
    SENDER_CHOICES = (
        (SENDER_USER, "User"),
        (SENDER_ASSISTANT, "Assistant"),
        (SENDER_ADMIN, "Admin"),
        (SENDER_SYSTEM, "System"),
    )

    conversation = models.ForeignKey(
        SupportConversation,
        on_delete=models.CASCADE,
        related_name="messages",
    )
    sender_type = models.CharField(max_length=20, choices=SENDER_CHOICES)
    content = models.TextField()
    meta = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return f"{self.sender_type} message #{self.pk} for conversation #{self.conversation_id}"


class SupportTicket(models.Model):
    """
    SupportTicket model - Users ki support tickets ke liye use hota hai.
    Jab user ko koi problem aata hai, toh ticket create kar sakta hai.
    Admin team tickets resolve karti hai.
    """
    STATUS_OPEN = "open"
    STATUS_IN_PROGRESS = "in_progress"
    STATUS_RESOLVED = "resolved"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_RESOLVED, "Resolved"),
    )
    SOURCE_MANUAL = "manual"
    SOURCE_AI_HANDOFF = "ai_handoff"
    SOURCE_CHOICES = (
        (SOURCE_MANUAL, "Manual"),
        (SOURCE_AI_HANDOFF, "AI Handoff"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="support_tickets")
    conversation = models.ForeignKey(
        SupportConversation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="tickets",
    )
    subject = models.CharField(max_length=180)
    message = models.TextField()
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default=SOURCE_MANUAL)
    ai_summary = models.TextField(blank=True, default="")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"Support ticket #{self.pk} - {self.subject}"


class SupportReply(models.Model):
    """Admin-authored or AI-drafted replies for support tickets."""

    STATUS_DRAFT = "draft"
    STATUS_SENT = "sent"
    STATUS_CHOICES = (
        (STATUS_DRAFT, "Draft"),
        (STATUS_SENT, "Sent"),
    )

    ticket = models.ForeignKey(SupportTicket, on_delete=models.CASCADE, related_name="replies")
    admin = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="support_replies_sent",
    )
    subject = models.CharField(max_length=180)
    body = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_DRAFT)
    ai_generated = models.BooleanField(default=True)
    sent_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-id"]

    def __str__(self):
        return f"Support reply #{self.pk} for ticket #{self.ticket_id}"


class EventReview(models.Model):
    """
    EventReview model - Events ke liye reviews aur ratings store karta hai.
    Users event book karne ke baad review aur rating de sakte hain.
    Rating 1 se 5 stars mein hoti hai.
    """
    RATING_CHOICES = [
        (1, "1 Star - Poor"),
        (2, "2 Stars - Fair"),
        (3, "3 Stars - Good"),
        (4, "4 Stars - Very Good"),
        (5, "5 Stars - Excellent"),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="reviews")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="event_reviews")
    rating = models.PositiveIntegerField(choices=RATING_CHOICES)
    review_text = models.TextField(blank=True, help_text="User ka feedback comment")
    is_verified_booking = models.BooleanField(default=False, help_text="Kya user ne event book kiya tha")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["event", "user"], name="unique_event_review_per_user"),
        ]

    def __str__(self):
        return f"Review for {self.event.title} by {self.user.username} - {self.rating} stars"

    @property
    def rating_stars(self):
        """Rating ko stars mein convert karta hai (e.g., 5 -> '★★★★★')"""
        return "★" * self.rating + "☆" * (5 - self.rating)


class EventCategory(models.Model):
    """
    EventCategory model - Event categories ke liye use hota hai.
    Organizers apni events ko categories mein divide karte hain.
    Example: Music, Wedding, Tech, Sports, Festival, etc.
    """
    name = models.CharField(max_length=80, unique=True)
    slug = models.SlugField(max_length=80, unique=True)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True, help_text="Category icon class name")
    is_active = models.BooleanField(default=True)
    display_order = models.PositiveIntegerField(default=0, help_text="Order in which to display categories")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["display_order", "name"]
        verbose_name_plural = "Event Categories"

    def __str__(self):
        return self.name


class Waitlist(models.Model):
    """
    Waitlist model - Full events ke liye waitlist maintain karta hai.
    Jab event full ho jata hai, toh interested users waitlist mein join kar sakte hain.
    """
    STATUS_PENDING = "pending"
    STATUS_OFFERED = "offered"
    STATUS_CONFIRMED = "confirmed"
    STATUS_EXPIRED = "expired"
    STATUS_CANCELLED = "cancelled"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_OFFERED, "Offered"),
        (STATUS_CONFIRMED, "Confirmed"),
        (STATUS_EXPIRED, "Expired"),
        (STATUS_CANCELLED, "Cancelled"),
    ]

    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="waitlist")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="event_waitlist")
    tickets_requested = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    offer_expires_at = models.DateTimeField(blank=True, null=True)
    position = models.PositiveIntegerField(help_text="Waitlist mein position")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["position", "created_at"]
        constraints = [
            models.UniqueConstraint(fields=["event", "user"], name="unique_waitlist_per_user"),
        ]

    def __str__(self):
        return f"Waitlist: {self.event.title} - {self.user.username} (#{self.position})"

    def is_offer_expired(self):
        """Check karta hai ki offer expire ho gaya hai ya nahi"""
        if self.status != self.STATUS_OFFERED:
            return False
        if not self.offer_expires_at:
            return False
        return timezone.now() > self.offer_expires_at


class TicketType(models.Model):
    """
    TicketType model - Events ke liye different ticket types define karta hai.
    Example: VIP, Regular, Early Bird, Student, etc.
    Har ticket type ki alag price aur availability hoti hai.
    """
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="ticket_types")
    name = models.CharField(max_length=80, help_text="Ticket type ka naam (VIP, Regular, etc.)")
    description = models.TextField(blank=True)
    price = models.PositiveIntegerField(default=0)
    total_quantity = models.PositiveIntegerField(default=0, help_text="Total tickets available")
    available_quantity = models.PositiveIntegerField(default=0, help_text="Abhi available tickets")
    max_per_booking = models.PositiveIntegerField(default=10, help_text="Ek booking mein maximum tickets")
    sales_start = models.DateTimeField(blank=True, null=True, help_text="Kab ticket sale shuru hogi")
    sales_end = models.DateTimeField(blank=True, null=True, help_text="Kab ticket sale khatam hogi")
    is_active = models.BooleanField(default=True)
    display_order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["display_order", "price"]
        unique_together = ["event", "name"]

    def __str__(self):
        return f"{self.event.title} - {self.name} (₹{self.price})"

    @property
    def is_available(self):
        """Check karta hai ki ticket available hai ya nahi"""
        if not self.is_active:
            return False
        if self.available_quantity <= 0:
            return False
        now = timezone.now()
        if self.sales_start and now < self.sales_start:
            return False
        if self.sales_end and now > self.sales_end:
            return False
        return True

    @property
    def is_sold_out(self):
        """Check karta hai ki tickets sold out hain ya nahi"""
        return self.available_quantity <= 0


class EventSchedule(models.Model):
    """
    EventSchedule model - Event schedule/agenda management.
    Allows organizers to create detailed schedules for their events.
    """
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="schedules")
    title = models.CharField(max_length=180, help_text="Session/activity title")
    description = models.TextField(blank=True)
    start_time = models.TimeField(help_text="Start time of the session")
    end_time = models.TimeField(help_text="End time of the session")
    speaker_name = models.CharField(max_length=120, blank=True, help_text="Speaker/host name")
    speaker_bio = models.TextField(blank=True)
    location = models.CharField(max_length=180, blank=True, help_text="Room/venue within the event")
    display_order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["display_order", "start_time", "id"]
        verbose_name_plural = "Event Schedules"

    def __str__(self):
        return f"{self.event.title} - {self.title} ({self.start_time} - {self.end_time})"

    @property
    def duration_minutes(self):
        """Calculate duration in minutes"""
        if self.start_time and self.end_time:
            from datetime import datetime, timedelta
            start = datetime.combine(datetime.today(), self.start_time)
            end = datetime.combine(datetime.today(), self.end_time)
            if end < start:
                end += timedelta(days=1)
            return int((end - start).total_seconds() / 60)
        return 0


class EventGallery(models.Model):
    """
    EventGallery model - Event photo gallery management.
    Allows organizers to upload multiple images for their events.
    """
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="gallery_images")
    image = models.ImageField(upload_to="event_gallery/", help_text="Gallery image")
    caption = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    display_order = models.PositiveIntegerField(default=0)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["display_order", "-uploaded_at"]
        verbose_name_plural = "Event Galleries"

    def __str__(self):
        return f"Gallery - {self.event.title}"

    @property
    def image_url(self):
        try:
            return self.image.url
        except ValueError:
            return ""
