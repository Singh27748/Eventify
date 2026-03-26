"""
Django Admin Configuration - Admin panel ke liye models register karne ka kaam.
Yahan hum define karte hain ki admin panel mein kaisa data dikhega.
"""

from django.contrib import admin

from .models import (
    Booking,
    Event,
    EventAdvertisement,
    EventActivitySlot,
    EventHelperSlot,
    HomepageHeroPromo,
    LoginThrottle,
    Notification,
    OTPRequest,
    Payment,
    Profile,
    PromoCode,
    SecurityAuditLog,
    SupportConversation,
    SupportMessage,
    SupportReply,
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
admin.site.register(EventAdvertisement)


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


@admin.register(HomepageHeroPromo)
class HomepageHeroPromoAdmin(admin.ModelAdmin):
    list_display = ("headline", "eyebrow", "is_active", "updated_at")
    list_filter = ("is_active", "updated_at")
    search_fields = ("headline", "eyebrow", "description")


admin.site.register(Notification)
admin.site.register(SupportConversation)
admin.site.register(SupportMessage)


@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "subject", "source", "status", "created_at")
    list_filter = ("status", "source", "created_at")
    search_fields = ("subject", "message", "ai_summary", "user__username", "user__email")


@admin.register(SupportReply)
class SupportReplyAdmin(admin.ModelAdmin):
    list_display = ("id", "ticket", "admin", "status", "ai_generated", "sent_at", "updated_at")
    list_filter = ("status", "ai_generated", "updated_at")
    search_fields = ("subject", "body", "ticket__subject", "ticket__user__email")


@admin.register(SecurityAuditLog)
class SecurityAuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "category", "action", "status", "actor_contact", "ip_address")
    list_filter = ("category", "status", "created_at")
    search_fields = ("action", "summary", "actor_contact", "ip_address", "user__username", "user__email")

# Register your models here.
