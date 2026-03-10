"""
Template Tags - Custom template filters jo hum HTML templates mein use karte hain.
In filters se hum data ko format karte hain display ke liye.
Example: {{ booking.total_amount|money }} se "INR 1,500" milega.
"""

from django import template
from django.utils import timezone

from core.services import format_money, status_class

register = template.Library()


@register.filter
def money(value):
    """
    Money filter - Amount ko INR format mein convert karta hai.
    Example: 1500 -> "INR 1,500"
    """
    return format_money(value)


@register.filter
def badge_class(value):
    """
    Badge class filter - Status ke hisab se CSS class return karta hai.
    Example: "confirmed" -> "badge-green"
    """
    return status_class(value)


@register.filter
def date_human(value):
    """
    Date human filter - Date ko readable format mein dikhata hai.
    Example: 2026-02-27 -> "27 Feb 2026"
    """
    if not value:
        return ""
    if hasattr(value, "date"):
        value = value.date()
    return value.strftime("%d %b %Y")


@register.filter
def datetime_human(value):
    """
    Datetime human filter - Date aur time ko readable format mein dikhata hai.
    Example: 2026-02-27 14:30:00 -> "27 Feb 2026, 02:30 PM"
    """
    if not value:
        return ""
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    return value.strftime("%d %b %Y, %I:%M %p")


@register.filter
def initials(value):
    """
    Initials filter - Name se initials extract karta hai.
    Example: "John Doe" -> "JD", "John" -> "J"
    """
    value = (value or "").strip()
    if not value:
        return "U"
    parts = [p for p in value.split() if p]
    if len(parts) == 1:
        return parts[0][:1].upper()
    return (parts[0][:1] + parts[1][:1]).upper()

