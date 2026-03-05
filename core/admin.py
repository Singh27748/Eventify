from django.contrib import admin

from .models import (
    Booking,
    Event,
    EventActivitySlot,
    EventHelperSlot,
    Notification,
    OTPRequest,
    Payment,
    Profile,
    SupportTicket,
)


admin.site.register(Profile)
admin.site.register(OTPRequest)
admin.site.register(Event)
admin.site.register(EventActivitySlot)
admin.site.register(EventHelperSlot)
admin.site.register(Booking)
admin.site.register(Payment)
admin.site.register(Notification)
admin.site.register(SupportTicket)

# Register your models here.
