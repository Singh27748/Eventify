from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Profile


@receiver(post_save, sender=User)
def ensure_profile(sender, instance, created, **kwargs):
    if kwargs.get("raw"):
        return
    if created:
        Profile.objects.get_or_create(
            user=instance,
            defaults={
                "role": Profile.ROLE_USER,
                "contact": instance.username,
            },
        )
