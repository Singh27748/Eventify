from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import Booking, Notification
from core.services import create_notification


class Command(BaseCommand):
    help = "Send event reminder notifications and emails for upcoming paid bookings."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=1,
            help="Send reminders for events happening after N day(s). Default is 1 (tomorrow).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview reminders without sending notifications or emails.",
        )

    def handle(self, *args, **options):
        days = max(0, int(options["days"] or 0))
        dry_run = bool(options["dry_run"])
        target_date = timezone.localdate() + timedelta(days=days)

        bookings = (
            Booking.objects.select_related("user", "event")
            .filter(
                event__date=target_date,
                payment_status=Booking.PAYMENT_PAID,
            )
            .exclude(status=Booking.STATUS_CANCELLED)
            .order_by("event__time", "id")
        )

        notification_sent = 0
        email_sent = 0
        skipped = 0
        failed_emails = 0

        from_email = (
            (getattr(settings, "DEFAULT_FROM_EMAIL", "") or "").strip()
            or (getattr(settings, "EMAIL_HOST_USER", "") or "").strip()
            or "webmaster@localhost"
        )

        for booking in bookings:
            reminder_key = f"event-reminder-{booking.id}-{target_date.isoformat()}"
            already_notified = Notification.objects.filter(
                user=booking.user,
                type="reminder",
                message__icontains=reminder_key,
            ).exists()
            if already_notified:
                skipped += 1
                continue

            reminder_message = (
                f"Reminder: '{booking.event.title}' is on "
                f"{booking.event.date.strftime('%d %b %Y')} at {booking.event.time}. "
                f"Ticket ID: {booking.ticket_reference}. ({reminder_key})"
            )

            if not dry_run:
                create_notification(
                    booking.user,
                    "Event Reminder",
                    reminder_message,
                    "reminder",
                )
            notification_sent += 1

            recipient = (booking.user.email or "").strip()
            if not recipient:
                continue

            if dry_run:
                email_sent += 1
                continue

            try:
                send_mail(
                    subject=f"Eventify Reminder | {booking.event.title}",
                    message=reminder_message,
                    from_email=from_email,
                    recipient_list=[recipient],
                    fail_silently=False,
                )
                email_sent += 1
            except Exception:
                failed_emails += 1

        self.stdout.write(
            self.style.SUCCESS(
                "Event reminders processed "
                f"(target_date={target_date.isoformat()}, days={days}, dry_run={dry_run})."
            )
        )
        self.stdout.write(
            f"Notifications: {notification_sent} | Emails sent: {email_sent} | "
            f"Skipped existing: {skipped} | Email failures: {failed_emails}"
        )
