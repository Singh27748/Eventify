"""
Signals - Django signals jo automatically chalte hain jab koi event occur hota hai.
Yahan hum automatically Profile create karte hain jab naya User banaya jata hai.
"""

from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Profile


@receiver(post_save, sender=User)
def ensure_profile(sender, instance, created, **kwargs):
    """
    Ensure Profile - Jab bhi naya User create hota hai, toh automatically ek Profile bhi ban jata hai.
    Isse har user ki extra information store karne ke liye Profile mil jata hai.
    """
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
