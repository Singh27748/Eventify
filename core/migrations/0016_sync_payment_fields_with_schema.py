from django.db import migrations, models


def sync_payment_schema(apps, schema_editor):
    connection = schema_editor.connection
    table_name = "core_payment"

    with connection.cursor() as cursor:
        existing_columns = {
            column.name for column in connection.introspection.get_table_description(cursor, table_name)
        }

    refunded_at_field = models.DateTimeField(blank=True, null=True)
    transaction_ref_field = models.CharField(max_length=80, blank=True)
    upi_id_field = models.CharField(max_length=120, blank=True)

    refunded_at_type = refunded_at_field.db_type(connection)
    transaction_ref_type = transaction_ref_field.db_type(connection)
    upi_id_type = upi_id_field.db_type(connection)
    quoted_table = schema_editor.quote_name(table_name)

    if "refunded_at" not in existing_columns:
        schema_editor.execute(
            f"ALTER TABLE {quoted_table} ADD COLUMN refunded_at {refunded_at_type} NULL"
        )
    if "transaction_ref" not in existing_columns:
        schema_editor.execute(
            f"ALTER TABLE {quoted_table} ADD COLUMN transaction_ref {transaction_ref_type} NOT NULL DEFAULT ''"
        )
    if "upi_id" not in existing_columns:
        schema_editor.execute(
            f"ALTER TABLE {quoted_table} ADD COLUMN upi_id {upi_id_type} NOT NULL DEFAULT ''"
        )


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0015_eventhelperslot_and_booking_helper_slot"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(sync_payment_schema, migrations.RunPython.noop),
            ],
            state_operations=[
                migrations.AlterModelOptions(
                    name="payment",
                    options={"ordering": ["-paid_at", "-id"]},
                ),
                migrations.AddField(
                    model_name="payment",
                    name="refunded_at",
                    field=models.DateTimeField(blank=True, null=True),
                ),
                migrations.AddField(
                    model_name="payment",
                    name="transaction_ref",
                    field=models.CharField(blank=True, max_length=80),
                ),
                migrations.AddField(
                    model_name="payment",
                    name="upi_id",
                    field=models.CharField(blank=True, max_length=120),
                ),
                migrations.AlterField(
                    model_name="payment",
                    name="status",
                    field=models.CharField(
                        choices=[
                            ("paid", "Paid"),
                            ("refunded", "Refunded"),
                            ("failed", "Failed"),
                        ],
                        default="paid",
                        max_length=20,
                    ),
                ),
            ],
        ),
    ]
