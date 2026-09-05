import uuid

import django.db.models.deletion
from django.db import migrations, models

# نگاشت مقدار رشته‌ای قدیمی (support_type) به عنوان نقش پشتیبانیِ جدید
# (SupportRole.name). یک‌جا تعریف شده تا هم seed هم انتقال داده و هم
# برگردوندن به عقب (reverse) دقیقاً از همین یک منبع استفاده کنن.
LEGACY_SUPPORT_TYPE_TO_ROLE_NAME = {
    "technical": "فنی",
    "financial": "مالی",
    "general": "عمومی",
}


def seed_default_support_roles(apps, schema_editor):
    """
    [Data migration - قدم ۱]
    سه نقش پیش‌فرضی که قبلاً به‌صورت choices ثابت (TECHNICAL/FINANCIAL/
    GENERAL) در کد بودن رو به‌عنوان رکورد واقعی در جدول جدید SupportRole
    می‌سازه — این‌طوری کاربرهایی که از قبل یکی از این سه زیرنوع رو داشتن،
    بعد از migration چیزی گم نمی‌کنن؛ و از همون لحظه مدیر ارشد می‌تونه از
    طریق API نقش‌های بیشتری هم اضافه کنه.
    """
    SupportRole = apps.get_model("accounts", "SupportRole")
    for role_name in LEGACY_SUPPORT_TYPE_TO_ROLE_NAME.values():
        SupportRole.objects.get_or_create(name=role_name, defaults={"is_active": True})


def unseed_default_support_roles(apps, schema_editor):
    """
    برگردوندن قدم ۱: این تابع *آخرین* قدمی است که در جهت reverse اجرا
    می‌شه (چون در forward اولین قدم بود) — یعنی وقتی به اینجا می‌رسیم،
    فیلد support_role (FK) قبلاً توسط reverse همین migration حذف شده،
    پس دیگه هیچ کاربری به این نقش‌ها ارجاع نمی‌ده و حذفشون با
    on_delete=PROTECT تداخلی نداره.
    """
    SupportRole = apps.get_model("accounts", "SupportRole")
    SupportRole.objects.filter(name__in=LEGACY_SUPPORT_TYPE_TO_ROLE_NAME.values()).delete()


def migrate_support_type_values_to_fk(apps, schema_editor):
    """
    [Data migration - قدم ۲]
    برای هر کاربری که قبلاً support_type رشته‌ای داشته (technical/
    financial/general)، رکورد SupportRole متناظر (که در قدم ۱ ساخته شد)
    رو به support_role_id وصل می‌کنه.
    """
    User = apps.get_model("accounts", "User")
    SupportRole = apps.get_model("accounts", "SupportRole")
    for old_value, role_name in LEGACY_SUPPORT_TYPE_TO_ROLE_NAME.items():
        role = SupportRole.objects.filter(name=role_name).first()
        if role is not None:
            User.objects.filter(support_type=old_value).update(support_role_id=role.id)


def migrate_fk_values_back_to_support_type(apps, schema_editor):
    """
    برگردوندن قدم ۲: از روی نام نقش فعلیِ کاربر، مقدار رشته‌ای قدیمی رو
    در ستون support_type (که reverse قدم بعدی، یعنی RemoveField، دوباره
    اضافه‌اش کرده) می‌نویسه.
    """
    User = apps.get_model("accounts", "User")
    for old_value, role_name in LEGACY_SUPPORT_TYPE_TO_ROLE_NAME.items():
        User.objects.filter(support_role__name=role_name).update(support_type=old_value)


class Migration(migrations.Migration):
    """
    جایگزینی زیرنوع پشتیبانی از یک CharField با choices ثابت (support_type)
    با یک ForeignKey واقعی به مدل جدید SupportRole — تا مدیر ارشد بتونه
    خودش از طریق API نقش‌های پشتیبانی رو تعریف/ویرایش/غیرفعال کنه، بدون
    نیاز به تغییر کد یا migration جدید برای هر نقش تازه.

    ترتیب عملیات عمداً طوری چیده شده که هم forward و هم reverse (migrate
    به عقب) بدون خطای ProtectedError یا FieldDoesNotExist کار کنه؛
    توضیح دقیق ترتیب در داکِ‌استرینگ هر تابع RunPython بالاست.
    """

    dependencies = [
        ("accounts", "0003_teaching_assistant_and_support_roles"),
    ]

    operations = [
        migrations.CreateModel(
            name="SupportRole",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        verbose_name="شناسه یکتا",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        help_text="مثلاً «فنی»، «مالی»، «پشتیبانی محتوا».",
                        max_length=50,
                        unique=True,
                        verbose_name="عنوان نقش پشتیبانی",
                    ),
                ),
                (
                    "description",
                    models.CharField(blank=True, max_length=255, verbose_name="توضیحات"),
                ),
                (
                    "is_active",
                    models.BooleanField(
                        default=True,
                        help_text="نقش‌های غیرفعال دیگر برای اختصاص به کاربر جدید قابل انتخاب نیستند.",
                        verbose_name="فعال",
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="تاریخ ایجاد"),
                ),
            ],
            options={
                "verbose_name": "نقش پشتیبانی",
                "verbose_name_plural": "نقش‌های پشتیبانی",
                "db_table": "accounts_support_role",
                "ordering": ["name"],
            },
        ),
        migrations.RunPython(seed_default_support_roles, unseed_default_support_roles),
        migrations.AddField(
            model_name="user",
            name="support_role",
            field=models.ForeignKey(
                blank=True,
                help_text=(
                    "فقط برای کاربرانی با نقش «پشتیبانی» پر می‌شود؛ برای بقیه‌ی نقش‌ها "
                    "باید خالی بماند. مقادیر مجاز از طریق API مدیریت نقش‌های پشتیبانی "
                    "(فقط مدیر ارشد) تعریف/مدیریت می‌شوند، نه در کد."
                ),
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="users",
                to="accounts.supportrole",
                verbose_name="نقش پشتیبانی",
            ),
        ),
        migrations.RunPython(
            migrate_support_type_values_to_fk, migrate_fk_values_back_to_support_type
        ),
        migrations.RemoveField(
            model_name="user",
            name="support_type",
        ),
    ]
