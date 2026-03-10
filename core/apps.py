"""
Core App Configuration - Eventify app ka configuration.
Yahan hum app ke initialization ke time kuch setup karte hain.
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"

    def ready(self):
        """
        Ready method - App load hone par chalega.
        Yahan signals import karte hain taaki automatically Profile create ho jab User banega.
        """
        import core.signals  # noqa: F401
