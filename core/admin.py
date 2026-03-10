"""
Django Admin Configuration - Admin panel ke liye models register karne ka kaam.
Yahan hum define karte hain ki admin panel mein kaisa data dikhega.
"""

from django.contrib import admin

from .models import (
    Booking,
    Event,
    EventActivitySlot,
    EventHelperSlot,
    LoginThrottle,
    Notification,
    OTPRequest,
    Payment,
    Profile,
    PromoCode,
    SecurityAuditLog,
    SupportTicket,
)


# Basic models - Seed data dekhne ke liye
admin.site.register(Profile)
admin.site.register(OTPRequest)
admin.site.register(Event)
admin.site.register(EventActivitySlot)
admin.site.register(EventHelperSlot)
admin.site.register(Booking)
admin.site.register(LoginThrottle)


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "booking",
        "amount",
        "method",
        "status",
        "transaction_ref",
        "gateway_provider",
        "coupon_code",
        "paid_at",
    )
    list_filter = ("status", "method", "gateway_provider", "verification_status")
    search_fields = ("transaction_ref", "gateway_payment_id", "booking__invoice_no", "booking__event__title")


@admin.register(PromoCode)
class PromoCodeAdmin(admin.ModelAdmin):
    list_display = ("code", "discount_type", "discount_value", "active", "expires_at", "used_count", "max_uses")
    list_filter = ("discount_type", "active")
    search_fields = ("code", "description")


admin.site.register(Notification)
admin.site.register(SupportTicket)


@admin.register(SecurityAuditLog)
class SecurityAuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "category", "action", "status", "actor_contact", "ip_address")
    list_filter = ("category", "status", "created_at")
    search_fields = ("action", "summary", "actor_contact", "ip_address", "user__username", "user__email")

# Register your models here.
