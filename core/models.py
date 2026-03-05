from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class Profile(models.Model):
    ROLE_USER = "user"
    ROLE_ORGANIZER = "organizer"
    ROLE_CHOICES = (
        (ROLE_USER, "User"),
        (ROLE_ORGANIZER, "Organizer"),
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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["contact", "role"], name="uniq_profile_contact_role"),
        ]

    def __str__(self):
        return f"{self.user.username} ({self.role})"


class OTPRequest(models.Model):
    PURPOSE_REGISTER = "register"
    PURPOSE_RESET = "reset"
    PURPOSE_DELETE_ACCOUNT = "delete_account"
    PURPOSE_CHOICES = (
        (PURPOSE_REGISTER, "Register"),
        (PURPOSE_RESET, "Reset"),
        (PURPOSE_DELETE_ACCOUNT, "Delete Account"),
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


class Event(models.Model):
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
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name="payments")
    amount = models.PositiveIntegerField()
    method = models.CharField(max_length=80)
    status = models.CharField(max_length=20, default="paid")
    paid_at = models.DateTimeField(auto_now_add=True)


class PrivateEventPayment(models.Model):
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
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notifications")
    title = models.CharField(max_length=160)
    message = models.TextField()
    type = models.CharField(max_length=30, default="system")
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class SupportTicket(models.Model):
    STATUS_OPEN = "open"
    STATUS_IN_PROGRESS = "in_progress"
    STATUS_RESOLVED = "resolved"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_RESOLVED, "Resolved"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="support_tickets")
    subject = models.CharField(max_length=180)
    message = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    created_at = models.DateTimeField(auto_now_add=True)
