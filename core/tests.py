import json
import secrets

from django.contrib.messages import get_messages
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import JsonResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .middleware import PanelTransportEncryptionMiddleware
from .models import (
    Booking,
    Event,
    EventActivitySlot,
    EventHelperSlot,
    OTPRequest,
    Payment,
    PrivateEventPayment,
    Profile,
)
from .api_views import _build_auth_username, _build_unique_auth_username
from .transport_crypto import (
    PanelPayloadError,
    _base64url_encode,
    _derive_key,
    decrypt_panel_payload,
    encrypt_panel_payload,
)
from .views import (
    build_auth_username,
    build_unique_auth_username,
    generate_ticket_token,
    parse_ticket_reference,
)


class TransportCryptoTests(TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        csrf_token = "csrf-demo-token-123"
        original = {
            "contact": "john@example.com",
            "role": "user",
            "tags": ["alpha", "beta"],
        }

        encrypted = encrypt_panel_payload(original, csrf_token)
        decrypted = decrypt_panel_payload(encrypted, csrf_token)

        self.assertEqual(decrypted, original)

    def test_decrypt_rejects_invalid_payload(self):
        with self.assertRaises(PanelPayloadError):
            decrypt_panel_payload("not-valid-payload", "csrf-demo-token-123")

    def test_decrypt_accepts_legacy_payload_without_aad(self):
        csrf_token = "csrf-legacy-token-123"
        payload = {"contact": "john@example.com", "role": "user"}
        iv = secrets.token_bytes(12)
        cipher = AESGCM(_derive_key(csrf_token))
        ciphertext = cipher.encrypt(
            iv,
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            b"",
        )
        encrypted = _base64url_encode(iv + ciphertext)

        decrypted = decrypt_panel_payload(encrypted, csrf_token)

        self.assertEqual(decrypted, payload)


class TransportMiddlewareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_request_payload_is_decrypted_before_view(self):
        csrf_token = "csrf-login-token"
        encrypted = encrypt_panel_payload(
            {
                "role": "user",
                "contact": "john@example.com",
                "password": "password123",
            },
            csrf_token,
        )

        request = self.factory.post(
            "/login/",
            {"csrfmiddlewaretoken": csrf_token, "__enc_payload": encrypted},
        )

        middleware = PanelTransportEncryptionMiddleware(
            lambda req: JsonResponse(
                {
                    "role": req.POST.get("role"),
                    "contact": req.POST.get("contact"),
                    "password": req.POST.get("password"),
                    "has_enc_field": "__enc_payload" in req.POST,
                }
            )
        )

        response = middleware(request)
        payload = json.loads(response.content.decode("utf-8"))

        self.assertEqual(payload["role"], "user")
        self.assertEqual(payload["contact"], "john@example.com")
        self.assertEqual(payload["password"], "password123")
        self.assertFalse(payload["has_enc_field"])

    def test_invalid_request_payload_returns_400(self):
        request = self.factory.post(
            "/login/",
            {
                "csrfmiddlewaretoken": "csrf-login-token",
                "__enc_payload": "invalid-token",
            },
        )

        middleware = PanelTransportEncryptionMiddleware(
            lambda req: JsonResponse({"ok": True})
        )

        response = middleware(request)

        self.assertEqual(response.status_code, 400)

    def test_json_response_can_be_encrypted(self):
        csrf_token = "csrf-response-token"
        request = self.factory.get(
            "/api/echo/",
            HTTP_X_PANEL_ENCRYPTION="1",
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        middleware = PanelTransportEncryptionMiddleware(
            lambda req: JsonResponse({"message": "hello"})
        )

        response = middleware(request)
        envelope = json.loads(response.content.decode("utf-8"))
        decrypted = decrypt_panel_payload(envelope["payload"], csrf_token)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-Panel-Encrypted"], "1")
        self.assertEqual(decrypted, {"message": "hello"})


class ApiEndpointsTests(TestCase):
    @staticmethod
    def _json(response):
        return json.loads(response.content.decode("utf-8"))

    def test_api_login_success(self):
        user = User.objects.create_user(
            username="api-login-user::user",
            password="secret123",
            first_name="API User",
            email="api-login@example.com",
        )
        profile = user.profile
        profile.role = Profile.ROLE_USER
        profile.contact = "api-login@example.com"
        profile.save(update_fields=["role", "contact"])

        response = self.client.post(
            "/api/login/",
            data=json.dumps(
                {
                    "role": Profile.ROLE_USER,
                    "contact": "api-login@example.com",
                    "password": "secret123",
                }
            ),
            content_type="application/json",
        )

        body = self._json(response)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["user"]["contact"], "api-login@example.com")
        self.assertIn("_auth_user_id", self.client.session)

    @override_settings(DEBUG=True)
    def test_api_register_send_and_verify_otp(self):
        send_response = self.client.post(
            "/api/register/send-otp/",
            data=json.dumps(
                {
                    "role": Profile.ROLE_USER,
                    "name": "New API User",
                    "contact": "new-api-user@example.com",
                    "password": "secret123",
                    "confirmPassword": "secret123",
                }
            ),
            content_type="application/json",
        )

        send_body = self._json(send_response)

        self.assertEqual(send_response.status_code, 201)
        self.assertTrue(send_body["ok"])
        self.assertIn("request_id", send_body)
        self.assertIn("otp_preview", send_body)

        verify_response = self.client.post(
            "/api/register/verify-otp/",
            data=json.dumps(
                {
                    "request_id": send_body["request_id"],
                    "otp": send_body["otp_preview"],
                }
            ),
            content_type="application/json",
        )

        verify_body = self._json(verify_response)

        self.assertEqual(verify_response.status_code, 201)
        self.assertTrue(verify_body["ok"])
        self.assertEqual(verify_body["user"]["contact"], "new-api-user@example.com")
        self.assertTrue(
            Profile.objects.filter(contact="new-api-user@example.com", role=Profile.ROLE_USER).exists()
        )
        self.assertTrue(
            OTPRequest.objects.filter(id=send_body["request_id"], is_used=True).exists()
        )
        self.assertIn("_auth_user_id", self.client.session)

    def test_api_events_returns_serialized_data(self):
        Event.objects.create(
            title="API Event",
            category="Workshop",
            location="Delhi",
            date=timezone.localdate(),
            time="10:00 AM - 12:00 PM",
            price=999,
            description="API listing test event",
            organizer_name="Organizer Name",
            organizer_phone="+91 9999999999",
            organizer_email="org@example.com",
        )

        response = self.client.get("/api/events/")
        body = self._json(response)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertGreaterEqual(body["count"], 1)
        self.assertTrue(any(event["title"] == "API Event" for event in body["events"]))


class UsernameGenerationTests(TestCase):
    def test_web_username_generation_is_normalized_and_case_insensitive_unique(self):
        User.objects.create_user(
            username="mixed@example.com::user",
            password="secret123",
        )

        normalized = build_auth_username("  MIXED@Example.com  ", " USER ")
        unique_candidate = build_unique_auth_username("MIXED@Example.com", "USER")

        self.assertEqual(normalized, "mixed@example.com::user")
        self.assertEqual(normalized, normalized.lower())
        self.assertNotEqual(unique_candidate, "mixed@example.com::user")
        self.assertEqual(unique_candidate, unique_candidate.lower())
        self.assertFalse(User.objects.filter(username__iexact=unique_candidate).exists())

    def test_api_username_generation_is_normalized_and_case_insensitive_unique(self):
        User.objects.create_user(
            username="api-mixed@example.com::organizer",
            password="secret123",
        )

        normalized = _build_auth_username("  API-MIXED@Example.com ", " ORGANIZER ")
        unique_candidate = _build_unique_auth_username("API-MIXED@Example.com", "ORGANIZER")

        self.assertEqual(normalized, "api-mixed@example.com::organizer")
        self.assertEqual(normalized, normalized.lower())
        self.assertNotEqual(unique_candidate, "api-mixed@example.com::organizer")
        self.assertEqual(unique_candidate, unique_candidate.lower())
        self.assertFalse(User.objects.filter(username__iexact=unique_candidate).exists())


class BookingTicketReferenceTests(TestCase):
    def test_ticket_reference_is_stable_and_formatted(self):
        user = User.objects.create_user(
            username="ticket-ref-user@example.com",
            password="secret123",
            first_name="Ticket User",
            email="ticket-ref-user@example.com",
        )

        event = Event.objects.create(
            title="Reference Event",
            category="Workshop",
            location="Lucknow",
            date=timezone.localdate(),
            time="10:00 AM - 12:00 PM",
            price=100,
            description="Ticket reference test event",
            organizer_name="Organizer Name",
            organizer_phone="+91 9999999999",
            organizer_email="org@example.com",
        )

        booking = Booking.objects.create(
            user=user,
            event=event,
            tickets=1,
            attendee_name="Ticket User",
            total_amount=100,
        )

        ticket_id = booking.ticket_reference
        self.assertRegex(ticket_id, r"^TKT-E[A-Z0-9]+-B[A-Z0-9]+$")
        self.assertEqual(ticket_id, booking.ticket_reference)

        parsed = parse_ticket_reference(ticket_id)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[1], booking.event_id)
        self.assertEqual(parsed[2], booking.id)

    def test_legacy_ticket_reference_is_still_parsed(self):
        parsed = parse_ticket_reference("TKT-0001-000001")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[1], 1)
        self.assertEqual(parsed[2], 1)


class TicketLookupTests(TestCase):
    def test_organizer_can_open_ticket_by_ticket_id(self):
        organizer = User.objects.create_user(
            username="lookup-organizer@example.com",
            password="secret123",
            first_name="Lookup Organizer",
            email="lookup-organizer@example.com",
        )
        organizer_profile = organizer.profile
        organizer_profile.role = Profile.ROLE_ORGANIZER
        organizer_profile.contact = organizer.username
        organizer_profile.save(update_fields=["role", "contact"])

        attendee = User.objects.create_user(
            username="lookup-attendee@example.com",
            password="secret123",
            first_name="Lookup Attendee",
            email="lookup-attendee@example.com",
        )

        event = Event.objects.create(
            title="Lookup Event",
            category="Workshop",
            location="Delhi",
            date=timezone.localdate(),
            time="11:00 AM - 1:00 PM",
            price=150,
            description="Ticket lookup test event",
            organizer_name="Lookup Organizer",
            organizer_phone="+91 9999999999",
            organizer_email="lookup-organizer@example.com",
            created_by=organizer,
        )

        booking = Booking.objects.create(
            user=attendee,
            event=event,
            tickets=1,
            attendee_name="Lookup Attendee",
            total_amount=150,
        )

        self.client.force_login(organizer)
        response = self.client.get(
            reverse("ticket_lookup"),
            {"ticket_id": booking.ticket_reference.lower()},
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/ticket-scan/", response.url)


class TicketScanViewTests(TestCase):
    def setUp(self):
        self.organizer = User.objects.create_user(
            username="scan-organizer@example.com",
            password="secret123",
            first_name="Scan Organizer",
            email="scan-organizer@example.com",
        )
        organizer_profile = self.organizer.profile
        organizer_profile.role = Profile.ROLE_ORGANIZER
        organizer_profile.contact = self.organizer.username
        organizer_profile.save(update_fields=["role", "contact"])

        self.attendee = User.objects.create_user(
            username="scan-attendee@example.com",
            password="secret123",
            first_name="Scan Attendee",
            email="scan-attendee@example.com",
        )
        self.public_scanner = User.objects.create_user(
            username="scan-public@example.com",
            password="secret123",
            first_name="Public Scanner",
            email="scan-public@example.com",
        )

        self.event = Event.objects.create(
            title="Scan Event",
            category="Workshop",
            location="Delhi",
            date=timezone.localdate(),
            time="11:00 AM - 1:00 PM",
            price=150,
            description="Ticket scan view test event",
            organizer_name="Scan Organizer",
            organizer_phone="+91 9999999999",
            organizer_email="scan-organizer@example.com",
            created_by=self.organizer,
        )

        self.booking = Booking.objects.create(
            user=self.attendee,
            event=self.event,
            tickets=1,
            attendee_name="Scan Attendee",
            total_amount=150,
            payment_status=Booking.PAYMENT_PAID,
            status=Booking.STATUS_CONFIRMED,
            invoice_no="INV-TEST-001",
        )
        self.payment = Payment.objects.create(
            booking=self.booking,
            amount=150,
            method="UPI",
            status="paid",
        )

    def test_event_organizer_scan_marks_attendance_and_shows_full_info(self):
        token = generate_ticket_token(self.booking)

        self.client.force_login(self.organizer)
        response = self.client.get(reverse("ticket_qr_scan", args=[token]))
        self.booking.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Organizer View")
        self.assertContains(response, "Attendance marked successfully.")
        self.assertContains(response, "Payment Method")
        self.assertContains(response, "UPI")
        self.assertEqual(self.booking.status, Booking.STATUS_COMPLETED)
        self.assertIsNotNone(self.booking.attendance_marked_at)

    def test_event_organizer_ticket_id_scan_marks_attendance_even_if_unpaid(self):
        unpaid_booking = Booking.objects.create(
            user=self.attendee,
            event=self.event,
            tickets=1,
            attendee_name="Scan Attendee",
            total_amount=150,
            payment_status=Booking.PAYMENT_UNPAID,
            status=Booking.STATUS_CONFIRMED,
            invoice_no="INV-TEST-UNPAID",
        )
        token = generate_ticket_token(unpaid_booking)

        self.client.force_login(self.organizer)
        response = self.client.get(reverse("ticket_qr_scan", args=[token]))
        unpaid_booking.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Organizer View")
        self.assertContains(response, "Attendance marked. Payment status is Unpaid.")
        self.assertEqual(unpaid_booking.status, Booking.STATUS_COMPLETED)
        self.assertIsNotNone(unpaid_booking.attendance_marked_at)

    def test_public_scan_shows_limited_info_and_upload_form(self):
        token = generate_ticket_token(self.booking)

        response = self.client.get(reverse("ticket_qr_scan", args=[token]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Public View")
        self.assertContains(response, self.event.title)
        self.assertContains(response, self.attendee.first_name)
        self.assertContains(response, self.event.organizer_name)
        self.assertContains(response, 'name="public_media"', html=False)
        self.assertContains(response, 'name="public_note"', html=False)
        self.assertNotContains(response, "Contact")
        self.assertNotContains(response, "Payment Method")

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_public_scan_can_send_media_to_organizer_email(self):
        token = generate_ticket_token(self.booking)
        media_file = SimpleUploadedFile(
            "scan-proof.jpg",
            b"fake-image-content",
            content_type="image/jpeg",
        )

        response = self.client.post(
            reverse("ticket_qr_scan", args=[token]),
            data={
                "public_note": "Sharing entry issue proof.",
                "public_media": media_file,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "File sent to organizer successfully.")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("scan-organizer@example.com", mail.outbox[0].to)
        self.assertEqual(mail.outbox[0].attachments[0].filename, "scan-proof.jpg")

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_public_scan_logged_user_uses_user_email_as_sender(self):
        token = generate_ticket_token(self.booking)
        media_file = SimpleUploadedFile(
            "scan-proof-2.jpg",
            b"fake-image-content",
            content_type="image/jpeg",
        )

        self.client.force_login(self.public_scanner)
        response = self.client.post(
            reverse("ticket_qr_scan", args=[token]),
            data={
                "public_note": "Sharing from account email.",
                "public_media": media_file,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "File sent to organizer successfully.")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, "scan-public@example.com")
        self.assertEqual(mail.outbox[0].reply_to, ["scan-public@example.com"])


class EventParticipantsExportTests(TestCase):
    def setUp(self):
        self.organizer = User.objects.create_user(
            username="excel-organizer@example.com",
            password="secret123",
            first_name="Excel Organizer",
            email="excel-organizer@example.com",
        )
        organizer_profile = self.organizer.profile
        organizer_profile.role = Profile.ROLE_ORGANIZER
        organizer_profile.contact = self.organizer.username
        organizer_profile.save(update_fields=["role", "contact"])

        self.attendee = User.objects.create_user(
            username="excel-attendee@example.com",
            password="secret123",
            first_name="Excel Attendee",
            email="excel-attendee@example.com",
        )
        attendee_profile = self.attendee.profile
        attendee_profile.phone = "+91 9000000000"
        attendee_profile.save(update_fields=["phone"])

        self.event = Event.objects.create(
            title="Excel Export Event",
            category="Workshop",
            location="Mumbai",
            date=timezone.localdate(),
            time="9:00 AM - 11:00 AM",
            price=500,
            description="Excel participant export test event",
            organizer_name="Excel Organizer",
            organizer_phone="+91 9999999999",
            organizer_email="excel-organizer@example.com",
            created_by=self.organizer,
        )
        self.booking = Booking.objects.create(
            user=self.attendee,
            event=self.event,
            tickets=2,
            attendee_name="Excel Attendee",
            payment_status=Booking.PAYMENT_PAID,
            status=Booking.STATUS_CONFIRMED,
            total_amount=1000,
        )
        self.booking.attendance_marked_at = timezone.now()
        self.booking.save(update_fields=["attendance_marked_at"])

    def test_organizer_can_download_event_participants_excel(self):
        self.client.force_login(self.organizer)

        response = self.client.get(
            reverse("download_event_participants_excel", args=[self.event.id])
        )

        content = response.content.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/vnd.ms-excel", response["Content-Type"])
        self.assertIn("participants.xls", response["Content-Disposition"])
        self.assertIn(self.booking.ticket_reference, content)
        self.assertIn("Excel Attendee", content)
        self.assertIn("Attendance Time", content)

    def test_organizer_can_download_attendance_excel_only(self):
        self.client.force_login(self.organizer)

        response = self.client.get(
            reverse("download_event_participants_excel", args=[self.event.id]),
            {"section": "attendance"},
        )

        content = response.content.decode("utf-8")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/vnd.ms-excel", response["Content-Type"])
        self.assertIn("attendance.xls", response["Content-Disposition"])
        self.assertIn("<th>Attendance</th>", content)
        self.assertIn("<th>Attendance Time</th>", content)
        self.assertIn("Present", content)
        self.assertNotIn("Participant Name", content)
        self.assertNotIn("Role", content)

    def test_non_owner_organizer_cannot_download_event_participants_excel(self):
        another_organizer = User.objects.create_user(
            username="another-organizer@example.com",
            password="secret123",
            first_name="Another Organizer",
            email="another-organizer@example.com",
        )
        another_profile = another_organizer.profile
        another_profile.role = Profile.ROLE_ORGANIZER
        another_profile.contact = another_organizer.username
        another_profile.save(update_fields=["role", "contact"])

        self.client.force_login(another_organizer)
        response = self.client.get(
            reverse("download_event_participants_excel", args=[self.event.id])
        )

        self.assertEqual(response.status_code, 404)

    def test_organizer_can_open_event_participants_excel_inline(self):
        self.client.force_login(self.organizer)

        response = self.client.get(
            reverse("download_event_participants_excel", args=[self.event.id]),
            {"open": "1"},
        )

        ticket_scan_url = reverse("ticket_qr_scan", args=[generate_ticket_token(self.booking)])
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/event_participants_table.html")
        self.assertContains(response, "Participants")
        self.assertContains(response, "Attendance List")
        self.assertContains(response, self.booking.ticket_reference)
        self.assertContains(response, ticket_scan_url)
        self.assertNotIn("Content-Disposition", response)


class EventDetailParticipantsPanelTests(TestCase):
    def setUp(self):
        self.organizer = User.objects.create_user(
            username="panel-organizer@example.com",
            password="secret123",
            first_name="Panel Organizer",
            email="panel-organizer@example.com",
        )
        organizer_profile = self.organizer.profile
        organizer_profile.role = Profile.ROLE_ORGANIZER
        organizer_profile.contact = self.organizer.username
        organizer_profile.save(update_fields=["role", "contact"])

        self.attendee = User.objects.create_user(
            username="panel-attendee@example.com",
            password="secret123",
            first_name="Panel Attendee",
            email="panel-attendee@example.com",
        )

        self.event = Event.objects.create(
            title="Panel Event",
            category="Seminar",
            location="Delhi",
            date=timezone.localdate(),
            time="4:00 PM - 6:00 PM",
            price=400,
            description="Panel participant listing event",
            organizer_name="Panel Organizer",
            organizer_phone="+91 9999999999",
            organizer_email="panel-organizer@example.com",
            created_by=self.organizer,
        )
        self.booking = Booking.objects.create(
            user=self.attendee,
            event=self.event,
            tickets=1,
            attendee_name="Panel Attendee",
            payment_status=Booking.PAYMENT_PAID,
            status=Booking.STATUS_CONFIRMED,
            total_amount=400,
        )

    def test_owner_organizer_sees_participants_panel_with_open_button(self):
        self.client.force_login(self.organizer)
        response = self.client.get(reverse("event_detail", args=[self.event.id]))

        ticket_scan_url = reverse("ticket_qr_scan", args=[generate_ticket_token(self.booking)])
        participants_file_url = reverse("download_event_participants_excel", args=[self.event.id])
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Participants")
        self.assertContains(response, self.booking.ticket_reference)
        self.assertContains(response, ticket_scan_url)
        self.assertContains(response, participants_file_url)
        self.assertContains(response, f"{participants_file_url}?open=1")
        self.assertContains(response, "Open")

    def test_regular_user_does_not_see_participants_panel(self):
        self.client.force_login(self.attendee)
        response = self.client.get(reverse("event_detail", args=[self.event.id]))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "participant-slot-box")


class PublicEventActiveParticipantFlowTests(TestCase):
    def setUp(self):
        self.organizer = User.objects.create_user(
            username="public-role-organizer@example.com",
            password="secret123",
            first_name="Public Role Organizer",
            email="public-role-organizer@example.com",
        )
        organizer_profile = self.organizer.profile
        organizer_profile.role = Profile.ROLE_ORGANIZER
        organizer_profile.contact = self.organizer.username
        organizer_profile.save(update_fields=["role", "contact"])

        self.user = User.objects.create_user(
            username="public-role-user@example.com",
            password="secret123",
            first_name="Public Role User",
            email="public-role-user@example.com",
        )
        self.user_two = User.objects.create_user(
            username="public-role-user-two@example.com",
            password="secret123",
            first_name="Public Role User Two",
            email="public-role-user-two@example.com",
        )

    def test_organizer_can_set_active_participant_requirement_for_public_event(self):
        self.client.force_login(self.organizer)

        response = self.client.post(
            reverse("new_event"),
            data={
                "title": "Public Role Event",
                "category": "Workshop",
                "location": "Pune",
                "date": timezone.localdate().strftime("%Y-%m-%d"),
                "startTime": "10:00",
                "endTime": "12:00",
                "price": "300",
                "description": "Public event with active participant registration.",
                "is_private": "false",
                "activeActivityId[]": [""],
                "activeActivityName[]": ["Stage activity support"],
                "activeActivityRequired[]": ["5"],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("my_events"))
        event = Event.objects.get(title="Public Role Event")
        self.assertFalse(event.is_private)
        self.assertEqual(event.active_participants_required, 5)
        self.assertEqual(event.active_participants_usage, "Stage activity support")
        slot = EventActivitySlot.objects.get(event=event)
        self.assertEqual(slot.name, "Stage activity support")
        self.assertEqual(slot.required_count, 5)

    def test_organizer_can_set_multiple_activity_requirements_separately(self):
        self.client.force_login(self.organizer)

        response = self.client.post(
            reverse("new_event"),
            data={
                "title": "Public Multi Activity Event",
                "category": "Workshop",
                "location": "Pune",
                "date": timezone.localdate().strftime("%Y-%m-%d"),
                "startTime": "10:00",
                "endTime": "12:00",
                "price": "300",
                "description": "Public event with multiple activities.",
                "is_private": "false",
                "activeActivityId[]": ["", ""],
                "activeActivityName[]": ["Stage Coordination", "Registration Desk"],
                "activeActivityRequired[]": ["2", "3"],
            },
        )

        self.assertEqual(response.status_code, 302)
        event = Event.objects.get(title="Public Multi Activity Event")
        self.assertEqual(event.active_participants_required, 5)
        slots = list(event.active_activity_slots.values_list("name", "required_count"))
        self.assertEqual(slots, [("Stage Coordination", 2), ("Registration Desk", 3)])

    def test_user_can_register_as_active_participant_when_slots_exist(self):
        event = Event.objects.create(
            title="Public Role Signup Event",
            category="Festival",
            location="Mumbai",
            date=timezone.localdate(),
            time="4:00 PM - 6:00 PM",
            price=250,
            description="Users can apply as active participants.",
            active_participants_required=2,
            active_participants_usage="Main stage coordination",
            organizer_name="Public Role Organizer",
            organizer_phone="+91 9999999999",
            organizer_email="public-role-organizer@example.com",
            created_by=self.organizer,
        )

        self.client.force_login(self.user)
        response = self.client.post(
            reverse("book_event", args=[event.id]),
            data={
                "attendeeName": "Public Role User",
                "applicationRole": Booking.ROLE_ACTIVE_PARTICIPANT,
            },
        )

        self.assertEqual(response.status_code, 302)
        booking = Booking.objects.get(user=self.user, event=event)
        self.assertEqual(response.url, reverse("payment_page", args=[booking.id]))
        self.assertEqual(booking.application_role, Booking.ROLE_ACTIVE_PARTICIPANT)
        self.assertEqual(booking.total_amount, event.price)

    def test_active_participant_registration_is_tracked_per_activity(self):
        event = Event.objects.create(
            title="Per Activity Slot Event",
            category="Festival",
            location="Mumbai",
            date=timezone.localdate(),
            time="4:00 PM - 6:00 PM",
            price=250,
            description="Separate activity slots for active participants.",
            active_participants_required=2,
            active_participants_usage="Stage Coordination, Registration Desk",
            organizer_name="Public Role Organizer",
            organizer_phone="+91 9999999999",
            organizer_email="public-role-organizer@example.com",
            created_by=self.organizer,
        )
        slot_stage = EventActivitySlot.objects.create(
            event=event,
            name="Stage Coordination",
            required_count=1,
        )
        slot_desk = EventActivitySlot.objects.create(
            event=event,
            name="Registration Desk",
            required_count=1,
        )

        self.client.force_login(self.user)
        first_response = self.client.post(
            reverse("book_event", args=[event.id]),
            data={
                "attendeeName": "Public Role User",
                "applicationRole": Booking.ROLE_ACTIVE_PARTICIPANT,
                "activeActivityId": str(slot_stage.id),
            },
        )
        self.assertEqual(first_response.status_code, 302)
        first_booking = Booking.objects.get(user=self.user, event=event)
        self.assertEqual(first_booking.active_activity_slot_id, slot_stage.id)

        self.client.logout()
        self.client.force_login(self.user_two)
        full_response = self.client.post(
            reverse("book_event", args=[event.id]),
            data={
                "attendeeName": "Public Role User Two",
                "applicationRole": Booking.ROLE_ACTIVE_PARTICIPANT,
                "activeActivityId": str(slot_stage.id),
            },
            follow=True,
        )
        self.assertEqual(full_response.status_code, 200)
        self.assertFalse(
            Booking.objects.filter(
                user=self.user_two,
                event=event,
                active_activity_slot=slot_stage,
            ).exists()
        )
        feedback = [message.message for message in get_messages(full_response.wsgi_request)]
        self.assertTrue(any("Selected activity slots are full" in message for message in feedback))

        second_response = self.client.post(
            reverse("book_event", args=[event.id]),
            data={
                "attendeeName": "Public Role User Two",
                "applicationRole": Booking.ROLE_ACTIVE_PARTICIPANT,
                "activeActivityId": str(slot_desk.id),
            },
        )
        self.assertEqual(second_response.status_code, 302)
        second_booking = Booking.objects.get(user=self.user_two, event=event)
        self.assertEqual(second_booking.active_activity_slot_id, slot_desk.id)

    def test_organizer_can_set_multiple_helper_requirements_separately(self):
        self.client.force_login(self.organizer)

        response = self.client.post(
            reverse("new_event"),
            data={
                "title": "Public Multi Helper Event",
                "category": "Workshop",
                "location": "Pune",
                "date": timezone.localdate().strftime("%Y-%m-%d"),
                "startTime": "10:00",
                "endTime": "12:00",
                "price": "300",
                "description": "Public event with multiple helper sections.",
                "is_private": "false",
                "helperActivityId[]": ["", ""],
                "helperActivityName[]": ["Registration Desk", "Backstage Support"],
                "helperActivityRequired[]": ["2", "1"],
            },
        )

        self.assertEqual(response.status_code, 302)
        event = Event.objects.get(title="Public Multi Helper Event")
        self.assertEqual(event.helpers_required, 3)
        slots = list(event.helper_activity_slots.values_list("name", "required_count"))
        self.assertEqual(slots, [("Registration Desk", 2), ("Backstage Support", 1)])

    def test_helper_team_registration_is_tracked_per_helper_activity(self):
        event = Event.objects.create(
            title="Per Helper Slot Event",
            category="Festival",
            location="Mumbai",
            date=timezone.localdate(),
            time="4:00 PM - 6:00 PM",
            price=250,
            description="Separate helper slots for organizer help.",
            helpers_required=2,
            helpers_usage="Registration Desk, Backstage Support",
            organizer_name="Public Role Organizer",
            organizer_phone="+91 9999999999",
            organizer_email="public-role-organizer@example.com",
            created_by=self.organizer,
        )
        slot_reg = EventHelperSlot.objects.create(
            event=event,
            name="Registration Desk",
            required_count=1,
        )
        slot_backstage = EventHelperSlot.objects.create(
            event=event,
            name="Backstage Support",
            required_count=1,
        )

        self.client.force_login(self.user)
        first_response = self.client.post(
            reverse("book_event", args=[event.id]),
            data={
                "attendeeName": "Public Role User",
                "applicationRole": Booking.ROLE_HELPER_TEAM,
                "helperActivityId": str(slot_reg.id),
            },
        )
        self.assertEqual(first_response.status_code, 302)
        first_booking = Booking.objects.get(user=self.user, event=event)
        self.assertEqual(first_booking.helper_activity_slot_id, slot_reg.id)

        self.client.logout()
        self.client.force_login(self.user_two)
        full_response = self.client.post(
            reverse("book_event", args=[event.id]),
            data={
                "attendeeName": "Public Role User Two",
                "applicationRole": Booking.ROLE_HELPER_TEAM,
                "helperActivityId": str(slot_reg.id),
            },
            follow=True,
        )
        self.assertEqual(full_response.status_code, 200)
        self.assertFalse(
            Booking.objects.filter(
                user=self.user_two,
                event=event,
                helper_activity_slot=slot_reg,
            ).exists()
        )
        feedback = [message.message for message in get_messages(full_response.wsgi_request)]
        self.assertTrue(any("Selected helper activity slots are full" in message for message in feedback))

        second_response = self.client.post(
            reverse("book_event", args=[event.id]),
            data={
                "attendeeName": "Public Role User Two",
                "applicationRole": Booking.ROLE_HELPER_TEAM,
                "helperActivityId": str(slot_backstage.id),
            },
        )
        self.assertEqual(second_response.status_code, 302)
        second_booking = Booking.objects.get(user=self.user_two, event=event)
        self.assertEqual(second_booking.helper_activity_slot_id, slot_backstage.id)


class PrivateEventInvitationEmailTests(TestCase):
    def setUp(self):
        self.organizer = User.objects.create_user(
            username="private-invite-organizer@example.com",
            password="secret123",
            first_name="Invite Organizer",
            email="private-invite-organizer@example.com",
        )
        organizer_profile = self.organizer.profile
        organizer_profile.role = Profile.ROLE_ORGANIZER
        organizer_profile.contact = self.organizer.username
        organizer_profile.save(update_fields=["role", "contact"])

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_new_private_event_redirects_to_payment_gateway_with_10_per_guest(self):
        self.client.force_login(self.organizer)
        response = self.client.post(
            reverse("new_event"),
            data={
                "title": "Private Launch",
                "category": "Meetup",
                "location": "Lucknow",
                "date": timezone.localdate().strftime("%Y-%m-%d"),
                "startTime": "10:00",
                "endTime": "12:00",
                "price": "0",
                "description": "Private launch event for invited guests.",
                "is_private": "true",
                "guest_emails": "Guest1@example.com, guest2@example.com\nGuest1@example.com",
            },
        )

        self.assertEqual(response.status_code, 302)
        payment = PrivateEventPayment.objects.get(event__title="Private Launch")
        self.assertEqual(
            response.url,
            reverse("private_event_payment_page", args=[payment.id]),
        )
        event = Event.objects.get(title="Private Launch")
        self.assertEqual(event.price, 20)
        self.assertEqual(event.guest_emails, "guest1@example.com, guest2@example.com")
        self.assertEqual(payment.status, PrivateEventPayment.STATUS_PENDING)
        self.assertEqual(payment.guest_count, 2)
        self.assertEqual(payment.amount, 20)
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_new_private_event_rejects_invalid_guest_email(self):
        self.client.force_login(self.organizer)
        response = self.client.post(
            reverse("new_event"),
            data={
                "title": "Invalid Private Event",
                "category": "Workshop",
                "location": "Noida",
                "date": timezone.localdate().strftime("%Y-%m-%d"),
                "startTime": "15:00",
                "endTime": "16:00",
                "price": "100",
                "description": "This should fail email validation.",
                "is_private": "true",
                "guest_emails": "good@example.com, not-an-email",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(Event.objects.filter(title="Invalid Private Event").exists())
        self.assertEqual(len(mail.outbox), 0)
        feedback = [message.message for message in get_messages(response.wsgi_request)]
        self.assertTrue(any("Invalid email address(es)" in message for message in feedback))

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_private_event_payment_sends_invites_after_successful_payment(self):
        self.client.force_login(self.organizer)
        create_response = self.client.post(
            reverse("new_event"),
            data={
                "title": "Private Paid Event",
                "category": "Seminar",
                "location": "Delhi",
                "date": timezone.localdate().strftime("%Y-%m-%d"),
                "startTime": "10:00",
                "endTime": "12:00",
                "price": "0",
                "description": "Private paid event",
                "is_private": "true",
                "guest_emails": "paid1@example.com, paid2@example.com",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        payment = PrivateEventPayment.objects.get(event__title="Private Paid Event")
        self.assertEqual(payment.amount, 20)
        self.assertEqual(len(mail.outbox), 0)

        pay_response = self.client.post(
            reverse("private_event_payment_pay", args=[payment.id]),
            data={"method": "UPI"},
        )

        self.assertEqual(pay_response.status_code, 302)
        self.assertEqual(pay_response.url, reverse("my_events"))
        payment.refresh_from_db()
        self.assertEqual(payment.status, PrivateEventPayment.STATUS_PAID)
        self.assertEqual(payment.method, "UPI")
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(mail.outbox[0].to, ["paid1@example.com"])
        self.assertEqual(mail.outbox[1].to, ["paid2@example.com"])


class DeleteAccountViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="delete-user@example.com",
            password="secret123",
            first_name="Delete User",
            email="delete-user@example.com",
        )
        self.profile = self.user.profile

    def _set_security_question(self, answer="my first school"):
        self.profile.security_question = "What is your first school name?"
        self.profile.security_answer_hash = make_password(answer)
        self.profile.save(update_fields=["security_question", "security_answer_hash"])

    def test_delete_account_redirects_to_settings_when_security_not_set(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("delete_account"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("settings"))

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_delete_account_send_otp_requires_correct_answer(self):
        self._set_security_question()
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("delete_account"),
            data={
                "action": "send_otp",
                "confirm_delete": "1",
                "username_confirm": self.user.username,
                "security_answer": "wrong answer",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            OTPRequest.objects.filter(
                purpose=OTPRequest.PURPOSE_DELETE_ACCOUNT,
                user=self.user,
            ).count(),
            0,
        )
        self.assertTrue(User.objects.filter(id=self.user.id).exists())

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_delete_account_send_otp_creates_delete_otp_request(self):
        self._set_security_question()
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("delete_account"),
            data={
                "action": "send_otp",
                "confirm_delete": "1",
                "username_confirm": self.user.username,
                "security_answer": "My First School",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("delete_account"))
        otp_request = OTPRequest.objects.filter(
            purpose=OTPRequest.PURPOSE_DELETE_ACCOUNT,
            user=self.user,
            is_used=False,
        ).latest("id")
        self.assertEqual(otp_request.contact, "delete-user@example.com")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("delete-user@example.com", mail.outbox[0].to)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_delete_account_deletes_user_only_after_valid_otp(self):
        self._set_security_question()
        self.client.force_login(self.user)
        send_response = self.client.post(
            reverse("delete_account"),
            data={
                "action": "send_otp",
                "confirm_delete": "1",
                "username_confirm": self.user.username,
                "security_answer": "my first school",
            },
        )
        self.assertEqual(send_response.status_code, 302)

        otp_request = OTPRequest.objects.filter(
            purpose=OTPRequest.PURPOSE_DELETE_ACCOUNT,
            user=self.user,
            is_used=False,
        ).latest("id")
        verify_response = self.client.post(
            reverse("delete_account"),
            data={"action": "verify_otp", "otp": otp_request.otp},
        )

        self.assertEqual(verify_response.status_code, 302)
        self.assertEqual(verify_response.url, reverse("home"))
        self.assertFalse(User.objects.filter(id=self.user.id).exists())


class SettingsSecurityQuestionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="security-q-user@example.com",
            password="secret123",
            first_name="Security User",
            email="security-q-user@example.com",
        )

    def test_settings_security_question_endpoint_saves_question(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("settings_security_question"),
            data={
                "securityQuestion": "What is my favorite color?",
                "securityAnswer": "Blue",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("settings"))
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.security_question, "What is my favorite color?")
        self.assertTrue(check_password("blue", self.user.profile.security_answer_hash))

    def test_settings_post_fallback_saves_question(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("settings"),
            data={
                "securityQuestion": "What is my pet name?",
                "securityAnswer": "Milo",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("settings"))
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.security_question, "What is my pet name?")
        self.assertTrue(check_password("milo", self.user.profile.security_answer_hash))


class ProfileUsernameEditTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="editable-user@example.com",
            password="secret123",
            first_name="editable-user@example.com",
            email="editable-user@example.com",
        )
        self.other_user = User.objects.create_user(
            username="taken-user@example.com",
            password="secret123",
            first_name="taken-user@example.com",
            email="taken-user@example.com",
        )

    def test_profile_can_update_username(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("profile"),
            data={
                "username": "new-user@example.com",
                "email": "new-user@example.com",
                "phone": "9999999999",
                "address": "Test address",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.username, "new-user@example.com")
        self.assertEqual(self.user.first_name, "new-user@example.com")
        self.assertEqual(self.user.last_name, "")
        self.assertEqual(self.user.profile.contact, "new-user@example.com")

    def test_profile_rejects_duplicate_username_case_insensitive(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("profile"),
            data={
                "username": "TAKEN-USER@example.com",
                "email": "editable-user@example.com",
                "phone": "",
                "address": "",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.username, "editable-user@example.com")
        self.assertEqual(self.user.profile.contact, "editable-user@example.com")

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_forgot_password_accepts_username_and_sends_otp_to_user_email(self):
        self.client.force_login(self.user)
        self.client.post(
            reverse("profile"),
            data={
                "username": "profile-login-username",
                "email": "editable-user@example.com",
                "phone": "",
                "address": "",
            },
        )
        self.client.logout()

        response = self.client.post(
            reverse("forgot_password_send_otp"),
            data={
                "role": Profile.ROLE_USER,
                "contact": "profile-login-username",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("editable-user@example.com", mail.outbox[0].to)
