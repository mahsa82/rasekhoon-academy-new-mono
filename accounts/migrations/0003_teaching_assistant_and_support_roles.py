from django.db import migrations, models


def convert_legacy_supervisor_role(apps, schema_editor):
    """
    [Data migration]
    نقش قدیمی «supervisor» (سوپروایزر) با نقش جدید «support» (پشتیبانی) +
    زیرنوع support_type جایگزین شده. هر کاربری که از قبل با نقش قدیمی
    ثبت شده، به support/عمومی (GENERAL) منتقل می‌شه تا:
        ۱) هیچ رکوردی با یک user_type نامعتبر (خارج از choices جدید) باقی نمونه.
        ۲) هیچ کاربری به‌طور غیرمنتظره دسترسی/محدودیتش عوض نشه — «عمومی»
           محافظه‌کارانه‌ترین زیرنوعه؛ مدیر ارشد می‌تونه بعداً از همون
           اندپوینت change-role زیرنوع دقیق‌تر (فنی/مالی) رو تنظیم کنه.
    """
    User = apps.get_model("accounts", "User")
    User.objects.filter(user_type="supervisor").update(user_type="support", support_type="general")


def revert_legacy_supervisor_role(apps, schema_editor):
    """برگردوندن migrate backward: هر کاربر support/general رو به supervisor قدیمی برمی‌گردونه."""
    User = apps.get_model("accounts", "User")
    User.objects.filter(user_type="support", support_type="general").update(
        user_type="supervisor", support_type=None
    )


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0002_google_login_and_username_rules"),
    ]

    operations = [
        # ابتدا فیلد جدید support_type رو اضافه می‌کنیم (nullable، پس روی
        # داده‌ی موجود بی‌خطره) تا وقتی داده‌ی قدیمی رو در ادامه منتقل
        # می‌کنیم، مدل تاریخی (apps.get_model) این فیلد رو داشته باشه.
        migrations.AddField(
            model_name="user",
            name="support_type",
            field=models.CharField(
                blank=True,
                choices=[
                    ("technical", "فنی"),
                    ("financial", "مالی"),
                    ("general", "عمومی"),
                ],
                help_text=(
                    "فقط برای کاربرانی با نقش «پشتیبانی» پر می‌شود؛ برای بقیه‌ی نقش‌ها "
                    "باید خالی بماند."
                ),
                max_length=20,
                null=True,
                verbose_name="زیرنوع پشتیبانی",
            ),
        ),
        # داده‌ی قدیمی رو *قبل* از تغییر choices منتقل می‌کنیم تا در بازه‌ی
        # بین این دو عملیات هیچ رکوردی با مقدار نامعتبر برای choices جدید نداشته باشیم.
        migrations.RunPython(convert_legacy_supervisor_role, revert_legacy_supervisor_role),
        migrations.AlterField(
            model_name="user",
            name="user_type",
            field=models.CharField(
                choices=[
                    ("student", "دانش‌آموز"),
                    ("instructor", "مدرس"),
                    ("teaching_assistant", "کمک مدرس"),
                    ("admin", "مدیر ارشد"),
                    ("support", "پشتیبانی"),
                ],
                default="student",
                max_length=20,
                verbose_name="نقش کاربر",
            ),
        ),
    ]
