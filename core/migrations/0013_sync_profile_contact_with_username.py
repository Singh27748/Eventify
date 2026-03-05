from django.db import migrations


def sync_profile_contact_with_username(apps, schema_editor):
    Profile = apps.get_model("core", "Profile")
    for profile in Profile.objects.select_related("user").all():
        username = (profile.user.username or "").strip()
        if username and profile.contact != username:
            profile.contact = username
            profile.save(update_fields=["contact"])


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0012_normalize_user_name_fields"),
    ]

    operations = [
        migrations.RunPython(sync_profile_contact_with_username, migrations.RunPython.noop),
    ]
