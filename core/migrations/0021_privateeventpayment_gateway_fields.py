from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0020_booking_ticket_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="privateeventpayment",
            name="failure_reason",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="privateeventpayment",
            name="gateway_order_id",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="privateeventpayment",
            name="gateway_payment_id",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="privateeventpayment",
            name="gateway_provider",
            field=models.CharField(blank=True, default="", max_length=80),
        ),
        migrations.AddField(
            model_name="privateeventpayment",
            name="payment_meta",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="privateeventpayment",
            name="verification_signature",
            field=models.CharField(blank=True, default="", max_length=180),
        ),
        migrations.AddField(
            model_name="privateeventpayment",
            name="verification_status",
            field=models.CharField(default="pending", max_length=20),
        ),
    ]
