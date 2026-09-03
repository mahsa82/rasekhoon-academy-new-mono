import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="google_id",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="مقدار sub برگشتی از Google ID Token؛ برای اتصال ورود با گوگل.",
                max_length=255,
                null=True,
                unique=True,
                verbose_name="شناسه گوگل",
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="phone_number",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text=(
                    "برای کاربرانی که فقط از طریق گوگل ثبت‌نام کرده‌اند، تا زمان افزودن و "
                    "تایید شماره موبایل خالی می‌ماند."
                ),
                max_length=11,
                null=True,
                unique=True,
                validators=[
                    django.core.validators.RegexValidator(
                        message="شماره موبایل باید با ۰۹ شروع شده و ۱۱ رقم باشد.",
                        regex="^09\\d{9}$",
                    )
                ],
                verbose_name="شماره موبایل",
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="username",
            field=models.CharField(
                db_index=True,
                max_length=30,
                unique=True,
                validators=[
                    django.core.validators.RegexValidator(
                        message=(
                            "نام کاربری فقط می‌تواند شامل حروف انگلیسی، عدد، نقطه (.) و "
                            "آندرلاین (_) باشد، بین ۳ تا ۳۰ کاراکتر باشد و نباید با نقطه "
                            "شروع/پایان یابد یا دو نقطه پشت‌سرهم داشته باشد."
                        ),
                        regex="^(?!.*\\.\\.)(?!\\.)[A-Za-z0-9._]{3,30}(?<!\\.)$",
                    )
                ],
                verbose_name="نام کاربری",
            ),
        ),
    ]
