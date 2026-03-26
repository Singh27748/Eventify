from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.conf import settings

from .models import Booking, Payment, Profile, SupportConversation, SupportTicket


class SupportAIError(Exception):
    """Raised when the configured AI support provider cannot fulfill a request."""


@dataclass(frozen=True)
class SupportAIConfig:
    provider: str
    ollama_base_url: str
    chat_model: str
    timeout_seconds: int


class BaseSupportAIProvider:
    provider_name = "base"

    def __init__(self, config: SupportAIConfig):
        self.config = config

    def chat(self, messages: list[dict[str, str]]) -> dict:
        raise NotImplementedError


class OllamaSupportAIProvider(BaseSupportAIProvider):
    provider_name = "ollama"

    def chat(self, messages: list[dict[str, str]]) -> dict:
        response = self._request(
            "/chat",
            {
                "model": self.config.chat_model,
                "stream": False,
                "messages": messages,
            },
        )
        message = response.get("message") or {}
        content = (message.get("content") or "").strip()
        if not content:
            raise SupportAIError("AI assistant returned an empty reply.")
        return {
            "content": content,
            "model_provider": self.provider_name,
            "model_name": (response.get("model") or self.config.chat_model).strip() or self.config.chat_model,
        }

    def _request(self, path: str, payload: dict) -> dict:
        url = f"{self.config.ollama_base_url.rstrip('/')}{path}"
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            url,
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw_payload = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise SupportAIError(
                detail or f"Ollama request failed with status {exc.code}."
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SupportAIError(
                "AI assistant is unavailable right now. You can still submit a support ticket."
            ) from exc

        try:
            return json.loads(raw_payload or "{}")
        except json.JSONDecodeError as exc:
            raise SupportAIError("AI assistant returned an invalid response.") from exc


def get_support_ai_config() -> SupportAIConfig:
    return SupportAIConfig(
        provider=(getattr(settings, "AI_SUPPORT_PROVIDER", "ollama") or "ollama").strip().lower(),
        ollama_base_url=(
            getattr(settings, "AI_SUPPORT_OLLAMA_BASE_URL", "http://127.0.0.1:11434/api")
            or "http://127.0.0.1:11434/api"
        ).rstrip("/"),
        chat_model=(getattr(settings, "AI_SUPPORT_CHAT_MODEL", "llama3.1:8b") or "llama3.1:8b").strip(),
        timeout_seconds=max(3, int(getattr(settings, "AI_SUPPORT_TIMEOUT_SECONDS", 15) or 15)),
    )


def get_support_ai_provider() -> BaseSupportAIProvider:
    config = get_support_ai_config()
    if config.provider == "ollama":
        return OllamaSupportAIProvider(config)
    raise SupportAIError(f"Unsupported AI support provider: {config.provider}.")


def build_support_ai_banner() -> str:
    config = get_support_ai_config()
    if config.provider == "ollama":
        return (
            f"AI assistant uses local Ollama with {config.chat_model}. "
            "If the local model is offline, your manual ticket form still works."
        )
    return "AI assistant is configured for support help."


def _summarize_recent_bookings(user) -> str:
    bookings = (
        Booking.objects.select_related("event", "ticket_type")
        .filter(user=user)
        .order_by("-booking_date")[:3]
    )
    if not bookings:
        return "No recent bookings."

    lines = []
    for booking in bookings:
        ticket_name = booking.ticket_type.name if booking.ticket_type_id else "General"
        lines.append(
            f"{booking.event.title} | status={booking.status} | payment={booking.payment_status} | ticket={ticket_name}"
        )
    return "; ".join(lines)


def _summarize_recent_payments(user) -> str:
    payments = (
        Payment.objects.select_related("booking__event")
        .filter(booking__user=user)
        .order_by("-paid_at")[:3]
    )
    if not payments:
        return "No recent payments."

    lines = []
    for payment in payments:
        lines.append(
            f"{payment.booking.event.title} | {payment.method} | status={payment.status} | amount={payment.amount}"
        )
    return "; ".join(lines)


def _summarize_recent_tickets(user) -> str:
    tickets = SupportTicket.objects.filter(user=user).order_by("-created_at")[:3]
    if not tickets:
        return "No past support tickets."

    return "; ".join(f"#{ticket.id} {ticket.subject} ({ticket.status})" for ticket in tickets)


def build_user_support_context(user) -> str:
    profile = getattr(user, "profile", None)
    role = getattr(profile, "role", Profile.ROLE_USER)
    language = getattr(profile, "language", "English")
    return (
        "Customer context:\n"
        f"- Name: {user.get_full_name() or user.username}\n"
        f"- Role: {role}\n"
        f"- Preferred language: {language}\n"
        f"- Contact: {getattr(profile, 'contact', '') or user.email or user.username}\n"
        f"- Recent bookings: {_summarize_recent_bookings(user)}\n"
        f"- Recent payments: {_summarize_recent_payments(user)}\n"
        f"- Recent support tickets: {_summarize_recent_tickets(user)}"
    )


def _map_message_role(sender_type: str) -> str:
    if sender_type == "user":
        return "user"
    return "assistant"


def _conversation_prompt_messages(conversation: SupportConversation) -> list[dict[str, str]]:
    messages = []
    for item in conversation.messages.order_by("id")[:16]:
        content = (item.content or "").strip()
        if not content:
            continue
        messages.append(
            {
                "role": _map_message_role(item.sender_type),
                "content": content,
            }
        )
    return messages


def generate_user_support_reply(user, conversation: SupportConversation) -> dict:
    provider = get_support_ai_provider()
    system_prompt = (
        "You are Eventify Support AI. Help users with Eventify booking, payment, ticket, "
        "profile, support, organizer, and security questions. Use the provided Eventify user "
        "context and conversation history. Be concise, practical, and safe. Do not invent "
        "refunds, admin actions, or account changes you cannot perform. If the issue needs a "
        "human, explicitly recommend creating a support ticket and explain what details to include.\n\n"
        f"{build_user_support_context(user)}"
    )
    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(_conversation_prompt_messages(conversation))
    return provider.chat(messages)


def build_fallback_handoff_summary(conversation: SupportConversation) -> str:
    recent_user_messages = [
        item.content.strip()
        for item in conversation.messages.filter(sender_type="user").order_by("-id")[:3]
        if (item.content or "").strip()
    ]
    recent_user_messages.reverse()
    if not recent_user_messages:
        return "User requested human support follow-up."

    issue_text = " | ".join(recent_user_messages)
    return f"User requested escalation to human support. Recent issue details: {issue_text}"[:1000]


def summarize_support_conversation(user, conversation: SupportConversation) -> dict:
    provider = get_support_ai_provider()
    transcript = "\n".join(
        f"{item.sender_type.title()}: {item.content.strip()}"
        for item in conversation.messages.order_by("id")[:20]
        if (item.content or "").strip()
    )
    messages = [
        {
            "role": "system",
            "content": (
                "Summarize this Eventify support conversation for a human support agent. "
                "Mention the user goal, the attempted troubleshooting, and the exact next action needed. "
                "Keep it under 120 words."
            ),
        },
        {
            "role": "user",
            "content": f"{build_user_support_context(user)}\n\nConversation transcript:\n{transcript}",
        },
    ]
    response = provider.chat(messages)
    summary = (response.get("content") or "").strip() or build_fallback_handoff_summary(conversation)
    response["content"] = summary[:1000]
    return response


def _ticket_context_for_admin(ticket: SupportTicket) -> str:
    conversation_text = "No linked AI conversation."
    if ticket.conversation_id:
        conversation_lines = [
            f"{item.sender_type.title()}: {item.content.strip()}"
            for item in ticket.conversation.messages.order_by("id")[:24]
            if (item.content or "").strip()
        ]
        if conversation_lines:
            conversation_text = "\n".join(conversation_lines)

    return (
        "Support ticket context:\n"
        f"- Ticket ID: {ticket.id}\n"
        f"- Subject: {ticket.subject}\n"
        f"- Status: {ticket.status}\n"
        f"- Source: {ticket.source}\n"
        f"- User: {ticket.user.get_full_name() or ticket.user.username}\n"
        f"- User email: {ticket.user.email or 'missing'}\n"
        f"- Original ticket message: {ticket.message}\n"
        f"- AI summary: {ticket.ai_summary or 'none'}\n"
        f"- Conversation transcript:\n{conversation_text}"
    )


def _parse_email_draft(raw_content: str, ticket: SupportTicket) -> tuple[str, str]:
    cleaned = (raw_content or "").strip()
    if not cleaned:
        raise SupportAIError("AI assistant returned an empty draft.")

    subject_match = re.search(r"^Subject:\s*(.+)$", cleaned, flags=re.IGNORECASE | re.MULTILINE)
    body_match = re.search(r"^Body:\s*(.+)$", cleaned, flags=re.IGNORECASE | re.DOTALL | re.MULTILINE)

    subject = (
        subject_match.group(1).strip()
        if subject_match
        else f"Update on your Eventify support request #{ticket.id}"
    )
    body = body_match.group(1).strip() if body_match else cleaned
    return subject[:180], body[:4000]


def generate_admin_email_draft(ticket: SupportTicket) -> dict:
    provider = get_support_ai_provider()
    messages = [
        {
            "role": "system",
            "content": (
                "You are Eventify's admin support drafting assistant. Write a professional, helpful email reply. "
                "Acknowledge the issue, explain the next step, avoid overpromising, and do not mention internal-only data. "
                "Return the draft in exactly this format:\n"
                "Subject: <subject>\n"
                "Body: <email body>"
            ),
        },
        {
            "role": "user",
            "content": _ticket_context_for_admin(ticket),
        },
    ]
    response = provider.chat(messages)
    subject, body = _parse_email_draft(response.get("content") or "", ticket)
    response["subject"] = subject
    response["body"] = body
    return response
