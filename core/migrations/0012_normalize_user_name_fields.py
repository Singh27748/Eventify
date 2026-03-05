from django.db import migrations


def normalize_user_name_fields(apps, schema_editor):
    User = apps.get_model("auth", "User")
    for user in User.objects.all().only("id", "username", "first_name", "last_name"):
        updated_fields = []
        if user.first_name != user.username:
            user.first_name = user.username
            updated_fields.append("first_name")
        if user.last_name:
            user.last_name = ""
            updated_fields.append("last_name")
        if updated_fields:
            user.save(update_fields=updated_fields)


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0011_profile_security_answer_hash_and_more"),
    ]

    operations = [
        migrations.RunPython(normalize_user_name_fields, migrations.RunPython.noop),
    ]
