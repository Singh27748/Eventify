"""
Eventify Services - Helper functions aur business logic yahan define hote hain.
Isme notifications create karna, menu items, labels, OTP generate karna, etc. shamil hai.
"""

import random

from django.conf import settings
from datetime import timedelta

from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone

from .models import Booking, Event, Notification, OTPRequest, Payment, Profile, PromoCode


# Supported languages - Eventify Hindi, Urdu aur English support karta hai
SUPPORTED_LANGUAGES = ("English", "Hindi", "Urdu")


def normalize_language(value):
    selected = (value or "English").strip().title()
    if selected in SUPPORTED_LANGUAGES:
        return selected
    return "English"


def ui_labels(language):
    selected = normalize_language(language)
    if selected == "Hindi":
        return {
            "browse_events": "इवेंट ब्राउज़ करें",
            "dashboard": "डैशबोर्ड",
            "my_events": "मेरे इवेंट",
            "bookings": "बुकिंग्स",
            "my_bookings": "मेरी बुकिंग्स",
            "event_history": "इवेंट हिस्ट्री",
            "invoice": "इनवॉइस",
            "my_profile": "माय प्रोफाइल",
            "settings": "सेटिंग्स",
            "logout": "लॉगआउट",
            "notifications_aria": "नोटिफिकेशन्स",
            "browse_events_aria": "इवेंट ब्राउज़ करें",
        }
    if selected == "Urdu":
        return {
            "browse_events": "ایونٹس براؤز کریں",
            "dashboard": "ڈیش بورڈ",
            "my_events": "میرے ایونٹس",
            "bookings": "بکنگز",
            "my_bookings": "میری بکنگز",
            "event_history": "ایونٹ ہسٹری",
            "invoice": "انوائس",
            "my_profile": "میرا پروفائل",
            "settings": "سیٹنگز",
            "logout": "لاگ آؤٹ",
            "notifications_aria": "نوٹیفکیشنز",
            "browse_events_aria": "ایونٹس براؤز کریں",
        }
    return {
        "browse_events": "Browse Events",
        "dashboard": "Dashboard",
        "my_events": "My Events",
        "bookings": "Bookings",
        "my_bookings": "My Bookings",
        "event_history": "Event History",
        "payment_history": "Payment History",
        "invoice": "Invoice",
        "my_profile": "My Profile",
        "settings": "Settings",
        "logout": "Logout",
        "notifications_aria": "Notifications",
        "browse_events_aria": "Browse Events",
    }


def format_money(amount):
    try:
        value = int(amount or 0)
    except (TypeError, ValueError):
        value = 0
    return f"INR {value:,}"


def status_class(status):
    value = (status or "").lower()
    if value in ("confirmed", "paid", "completed", "resolved"):
        return "badge-green"
    if value in ("pending", "unpaid", "open", "in_progress"):
        return "badge-orange"
    if value in ("cancelled", "refunded", "failed"):
        return "badge-red"
    return "badge-blue"


def generate_otp():
    return str(random.randint(100000, 999999))


def generate_invoice_no():
    suffix = random.randint(10, 99)
    return f"INV-{int(timezone.now().timestamp())}{suffix}"


def create_notification(user, title, message, ntype="system"):
    return Notification.objects.create(
        user=user,
        title=title,
        message=message,
        type=ntype,
    )


def menu_by_role(role, language="English"):
    labels = ui_labels(language)
    labels.setdefault("payment_history", "Payment History")
    if role == Profile.ROLE_ADMIN:
        return [
            {"key": "dashboard", "label": labels["dashboard"], "href": "/dashboard/"},
            {"key": "admin-events", "label": "All Events", "href": "/platform-admin/events/"},
            {"key": "admin-ads", "label": "Advertisements", "href": "/platform-admin/advertisements/"},
            {"key": "admin-users", "label": "All Users", "href": "/platform-admin/users/"},
            {"key": "admin-tickets", "label": "All Bookings", "href": "/platform-admin/bookings/"},
            {"key": "admin-payments", "label": "All Payments", "href": "/platform-admin/payments/"},
            {"key": "admin-support", "label": "Support Tickets", "href": "/platform-admin/support/"},
            {"key": "profile", "label": labels["my_profile"], "href": "/profile/"},
        ]
    if role == Profile.ROLE_ORGANIZER:
        return [
            {"key": "dashboard", "label": labels["dashboard"], "href": "/dashboard/"},
            {"key": "my-events", "label": labels["my_events"], "href": "/my-events/"},
            {"key": "organizer-bookings", "label": labels["bookings"], "href": "/organizer-bookings/"},
            {"key": "ticket-recheck", "label": "Ticket Rechecking", "href": "/ticket-recheck/"},
            {"key": "payment-history", "label": labels["payment_history"], "href": "/payment-history/"},
            {"key": "invoices", "label": labels["invoice"], "href": "/invoices/"},
            {"key": "profile", "label": labels["my_profile"], "href": "/profile/"},
        ]
    return [
        {"key": "dashboard", "label": labels["dashboard"], "href": "/dashboard/"},
        {"key": "my-bookings", "label": labels["my_bookings"], "href": "/my-bookings/"},
        {"key": "event-history", "label": labels["event_history"], "href": "/event-history/"},
        {"key": "payment-history", "label": labels["payment_history"], "href": "/payment-history/"},
        {"key": "invoices", "label": labels["invoice"], "href": "/invoices/"},
        {"key": "profile", "label": labels["my_profile"], "href": "/profile/"},
    ]


@transaction.atomic
def seed_demo_data():
    user = User.objects.filter(username="john@example.com").first()
    if not user:
        user = User.objects.create_user(
            username="john@example.com",
            password="password123",
            first_name="john@example.com",
            last_name="",
            email="john@example.com",
        )
        Profile.objects.update_or_create(
            user=user,
            defaults={
                "role": Profile.ROLE_USER,
                "contact": "john@example.com",
                "phone": "+91 9876543210",
                "address": "123 Main Street, New Delhi, India",
            },
        )
    else:
        Profile.objects.get_or_create(
            user=user,
            defaults={
                "role": Profile.ROLE_USER,
                "contact": user.username,
                "phone": "+91 9876543210",
                "address": "123 Main Street, New Delhi, India",
            },
        )

    organizer = User.objects.filter(username="organizer@example.com").first()
    if not organizer:
        organizer = User.objects.create_user(
            username="organizer@example.com",
            password="organizer123",
            first_name="organizer@example.com",
            last_name="",
            email="organizer@example.com",
        )
        Profile.objects.update_or_create(
            user=organizer,
            defaults={
                "role": Profile.ROLE_ORGANIZER,
                "contact": "organizer@example.com",
                "phone": "+92 300 1224567",
                "address": "Karachi, Pakistan",
            },
        )
    else:
        Profile.objects.get_or_create(
            user=organizer,
            defaults={
                "role": Profile.ROLE_ORGANIZER,
                "contact": organizer.username,
                "phone": "+92 300 1224567",
                "address": "Karachi, Pakistan",
            },
        )

    admin_email = (getattr(settings, "DEFAULT_ADMIN_EMAIL", "") or "asing27748@gmail.com").strip().lower()
    admin_user = User.objects.filter(username=admin_email).first()
    if not admin_user:
        admin_user = User.objects.create_user(
            username=admin_email,
            password="admin123",
            first_name="Platform Admin",
            last_name="",
            email=admin_email,
        )
        admin_user.is_staff = True
        admin_user.save(update_fields=["is_staff"])
        Profile.objects.update_or_create(
            user=admin_user,
            defaults={
                "role": Profile.ROLE_ADMIN,
                "contact": admin_email,
                "phone": "+91 9000000000",
                "address": "Platform Operations",
                "email_verified": True,
            },
        )
    else:
        if not admin_user.is_staff:
            admin_user.is_staff = True
            admin_user.save(update_fields=["is_staff"])
        Profile.objects.update_or_create(
            user=admin_user,
            defaults={
                "role": Profile.ROLE_ADMIN,
                "contact": admin_user.username,
                "email_verified": True,
            },
        )

    if Event.objects.count() == 0:
        today = timezone.localdate()
        events = [
            {
                "title": "Electro Beats: Live Music Concert",
                "category": "Music",
                "location": "Karachi, Pakistan",
                "date": today + timedelta(days=25),
                "time": "7:00 PM - 10:00 PM",
                "price": 2500,
                "description": "Live music event with top DJs and immersive stage lighting.",
                "image_url": "https://images.unsplash.com/photo-1492684223066-81342ee5ff30?auto=format&fit=crop&w=1200&q=80",
            },
            {
                "title": "Startup & Tech Conference 2026",
                "category": "Business",
                "location": "Karachi, Pakistan",
                "date": today + timedelta(days=35),
                "time": "9:00 AM - 5:00 PM",
                "price": 0,
                "description": "Conference on AI, product design, and startup growth.",
                "image_url": "https://images.unsplash.com/photo-1515169067868-5387ec356754?auto=format&fit=crop&w=1200&q=80",
            },
            {
                "title": "Photography Workshop for Beginners",
                "category": "Workshop",
                "location": "Karachi, Pakistan",
                "date": today + timedelta(days=18),
                "time": "1:00 PM - 5:00 PM",
                "price": 1200,
                "description": "Hands-on workshop on camera basics, framing, and lighting.",
                "image_url": "https://images.unsplash.com/photo-1516035069371-29a1b244cc32?auto=format&fit=crop&w=1200&q=80",
            },
            {
                "title": "Culinary Masterclass with Chef Asad",
                "category": "Workshop",
                "location": "Karachi, Pakistan",
                "date": today + timedelta(days=30),
                "time": "12:00 PM - 5:00 PM",
                "price": 2000,
                "description": "Interactive culinary event with plated tasting session.",
                "image_url": "https://images.unsplash.com/photo-1556911220-bff31c812dba?auto=format&fit=crop&w=1200&q=80",
            },
            {
                "title": "Wedding Event 2026",
                "category": "Wedding",
                "location": "Serena Hotel, Karachi, Pakistan",
                "date": today + timedelta(days=45),
                "time": "10:00 AM - 4:00 PM",
                "price": 5000,
                "description": "Luxury wedding planning showcase for couples and families.",
                "image_url": "https://images.unsplash.com/photo-1519741497674-611481863552?auto=format&fit=crop&w=1400&q=80",
            },
            {
                "title": "Business Leadership Summit",
                "category": "Business",
                "location": "Convention Center, Bangalore",
                "date": today - timedelta(days=22),
                "time": "10:00 AM - 6:00 PM",
                "price": 5000,
                "description": "Leadership talks and networking for business professionals.",
                "image_url": "https://images.unsplash.com/photo-1475721027785-f74eccf877e2?auto=format&fit=crop&w=1200&q=80",
            },
            {
                "title": "Art & Design Expo",
                "category": "Art",
                "location": "Gallery Hall, Mumbai",
                "date": today - timedelta(days=40),
                "time": "11:00 AM - 8:00 PM",
                "price": 3000,
                "description": "Curated exhibition of modern art and design installations.",
                "image_url": "https://images.unsplash.com/photo-1460661419201-fd4cecdf8a8b?auto=format&fit=crop&w=1200&q=80",
            },
            {
                "title": "Food Festival Night",
                "category": "Food & Drinks",
                "location": "Carnival Ground, Kolkata",
                "date": today + timedelta(days=55),
                "time": "6:00 PM - 11:00 PM",
                "price": 2000,
                "description": "Street food festival with live music and tasting counters.",
                "image_url": "https://images.unsplash.com/photo-1504674900247-0877df9cc836?auto=format&fit=crop&w=1200&q=80",
            },
        ]

        for payload in events:
            Event.objects.create(
                organizer_name="Sarah Weddings",
                organizer_phone="+92 300 1224567",
                organizer_email="contact@sarahweddings.com",
                created_by=organizer,
                **payload,
            )

    if Booking.objects.count() == 0:
        e1 = Event.objects.filter(title="Electro Beats: Live Music Concert").first()
        e2 = Event.objects.filter(title="Startup & Tech Conference 2026").first()
        e3 = Event.objects.filter(title="Business Leadership Summit").first()
        e4 = Event.objects.filter(title="Art & Design Expo").first()
        if all([e1, e2, e3, e4]):
            b1 = Booking.objects.create(
                user=user,
                event=e1,
                tickets=1,
                attendee_name="John Doe",
                status=Booking.STATUS_CONFIRMED,
                payment_status=Booking.PAYMENT_PAID,
                total_amount=e1.price,
                invoice_no="INV-2026001",
            )
            Payment.objects.create(booking=b1, amount=e1.price, method="UPI", status="paid")

            Booking.objects.create(
                user=user,
                event=e2,
                tickets=2,
                attendee_name="John Doe",
                status=Booking.STATUS_PENDING,
                payment_status=Booking.PAYMENT_UNPAID,
                total_amount=e2.price * 2,
            )

            b3 = Booking.objects.create(
                user=user,
                event=e3,
                tickets=1,
                attendee_name="John Doe",
                status=Booking.STATUS_COMPLETED,
                payment_status=Booking.PAYMENT_PAID,
                total_amount=e3.price,
                invoice_no="INV-2025012",
            )
            Payment.objects.create(booking=b3, amount=e3.price, method="Card", status="paid")

            Booking.objects.create(
                user=user,
                event=e4,
                tickets=1,
                attendee_name="John Doe",
                status=Booking.STATUS_CANCELLED,
                payment_status=Booking.PAYMENT_REFUNDED,
                total_amount=e4.price,
            )

    promo_defaults = [
        {
            "code": "WELCOME10",
            "description": "10% off on your first booking",
            "discount_type": PromoCode.DISCOUNT_PERCENTAGE,
            "discount_value": 10,
            "active": True,
            "expires_at": timezone.now() + timedelta(days=120),
        },
        {
            "code": "FLAT200",
            "description": "Flat INR 200 off",
            "discount_type": PromoCode.DISCOUNT_FIXED,
            "discount_value": 200,
            "active": True,
            "expires_at": timezone.now() + timedelta(days=45),
        },
    ]
    for promo in promo_defaults:
        PromoCode.objects.update_or_create(code=promo["code"], defaults=promo)

    if Notification.objects.filter(user=user).count() == 0:
        create_notification(
            user,
            "Booking Confirmed",
            "Your booking for 'Electro Beats: Live Music Concert' has been confirmed.",
            "booking",
        )
        create_notification(
            user,
            "Payment Updated",
            "Payment of INR 2,500 completed successfully.",
            "payment",
        )
        create_notification(
            user,
            "Event Reminder",
            "Reminder: Photography Workshop starts soon.",
            "reminder",
        )

    return {
        "total_users": User.objects.count(),
        "total_events": Event.objects.count(),
        "paid_revenue": Booking.objects.filter(payment_status=Booking.PAYMENT_PAID).aggregate(
            total=Sum("total_amount")
        )["total"]
        or 0,
    }


def get_trending_events(limit=6):
    """
    Get trending events based on booking count and recent activity.
    Events with most bookings in the last 30 days are considered trending,
    but only events scheduled in the next 30 days are returned.
    """
    from django.db.models import Count

    today = timezone.localdate()
    thirty_days_from_now = today + timedelta(days=30)
    thirty_days_ago = timezone.now() - timedelta(days=30)

    # Get events with most bookings in last 30 days, limited to the next 30 days.
    trending = (
        Event.objects.filter(
            is_private=False,
            date__gte=today,
            date__lte=thirty_days_from_now,
            bookings__booking_date__gte=thirty_days_ago,
            bookings__payment_status=Booking.PAYMENT_PAID,
        )
        .annotate(booking_count=Count("bookings"))
        .filter(booking_count__gt=0)
        .order_by("-booking_count", "date")[:limit]
    )

    # If not enough trending events, fill with other upcoming events from the same 30-day window.
    if trending.count() < limit:
        existing_ids = [e.id for e in trending]
        upcoming = Event.objects.filter(
            is_private=False,
            date__gte=today,
            date__lte=thirty_days_from_now,
        ).exclude(id__in=existing_ids).order_by("date")[: limit - trending.count()]
        trending = list(trending) + list(upcoming)

    return trending
