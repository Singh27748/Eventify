from django import template
from django.utils import timezone

from core.services import format_money, status_class

register = template.Library()


@register.filter
def money(value):
    return format_money(value)


@register.filter
def badge_class(value):
    return status_class(value)


@register.filter
def date_human(value):
    if not value:
        return ""
    if hasattr(value, "date"):
        value = value.date()
    return value.strftime("%d %b %Y")


@register.filter
def datetime_human(value):
    if not value:
        return ""
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    return value.strftime("%d %b %Y, %I:%M %p")


@register.filter
def initials(value):
    value = (value or "").strip()
    if not value:
        return "U"
    parts = [p for p in value.split() if p]
    if len(parts) == 1:
        return parts[0][:1].upper()
    return (parts[0][:1] + parts[1][:1]).upper()

