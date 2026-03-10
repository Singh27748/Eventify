import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class StrongPasswordPolicyValidator:
    def validate(self, password, user=None):
        errors = []
        if not re.search(r"[A-Z]", password or ""):
            errors.append(_("Password must contain at least one uppercase letter."))
        if not re.search(r"[a-z]", password or ""):
            errors.append(_("Password must contain at least one lowercase letter."))
        if not re.search(r"\d", password or ""):
            errors.append(_("Password must contain at least one number."))
        if not re.search(r"[^A-Za-z0-9]", password or ""):
            errors.append(_("Password must contain at least one special character."))
        if errors:
            raise ValidationError(errors)

    def get_help_text(self):
        return _(
            "Your password must include uppercase, lowercase, numeric, and special characters."
        )
