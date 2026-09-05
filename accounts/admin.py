import jdatetime
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import SupportRole, User


@admin.register(SupportRole)
class SupportRoleAdmin(admin.ModelAdmin):
    """
    مدیریت نقش‌های پشتیبانی از پنل ادمین جنگو — همون کاری که
    SupportRoleListCreateView/SupportRoleDetailView از طریق API انجام
    می‌دن، اینجا هم برای مدیر ارشدی که ترجیح می‌ده از پنل ادمین کار کنه
    در دسترسه. search_fields لازمه چون CustomUserAdmin پایین از
    autocomplete_fields برای support_role استفاده می‌کنه.
    """

    list_display = ("name", "description", "is_active", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name", "description")
    ordering = ("name",)
    readonly_fields = ("created_at",)


@admin.register(User)
class CustomUserAdmin(BaseUserAdmin):
    # ستون‌های لیست کاربران
    list_display = (
        "phone_number",
        "username",
        "full_name",
        "user_type",
        "support_role",
        "is_phone_verified",
        "is_active",
        "is_staff",
        "get_date_joined_jalali",
    )

    # ستون‌های دارای لینک به صفحه ویرایش
    list_display_links = ("phone_number", "username")

    # فیلترهای سمت راست
    list_filter = (
        "user_type",
        "support_role",
        "is_phone_verified",
        "is_active",
        "is_staff",
        "is_superuser",
        "groups",
    )

    # فیلدهای قابل جستجو
    search_fields = ("phone_number", "username", "full_name", "email", "id")

    # ترتیب مرتب‌سازی پیش‌فرض
    ordering = ("-date_joined",)

    # چون support_role حالا یک ForeignKey (به SupportRole) است نه یک
    # choices ثابت، از یک ویجت جست‌وجوپذیر استفاده می‌کنیم (نیازمند
    # SupportRoleAdmin.search_fields که بالا تعریف شده) به‌جای یک dropdown
    # ساده که با رشد تعداد نقش‌ها ناکارآمد می‌شه.
    autocomplete_fields = ("support_role",)

    # چیدمان فیلدها در صفحه ویرایش کاربر
    fieldsets = (
        (_("اطلاعات حساب کاربر"), {
            "fields": ("phone_number", "email", "username", "password")
        }),
        (_("اطلاعات شخصی"), {
            "fields": ("full_name", "user_type", "support_role")
        }),
        (_("دسترسیا و وضعیت‌ها"), {
            "fields": (
                "is_active",
                "is_phone_verified",
                "is_staff",
                "is_superuser",
                "groups",
                "user_permissions",
            )
        }),
        (_("تواريخ مهم"), {
            "fields": ("last_login", "date_joined")
        }),
    )

    # چیدمان فیلدها هنگام ساخت کاربر جدید در پنل ادمین
    add_fieldsets = (
        (_("ایجاد کاربر جدید"), {
            "classes": ("wide",),
            "fields": (
                "phone_number",
                "email",
                "username",
                "full_name",
                "user_type",
                "support_role",
                "password1",
                "password2",
                "is_active",
                "is_phone_verified",
                "is_staff",
            ),
        }),
    )

    # فیلدهای غیرقابل ویرایش مستقیم
    readonly_fields = ("date_joined", "last_login")

    @admin.display(description=_("تاریخ عضویت (شمسی)"), ordering="date_joined")
    def get_date_joined_jalali(self, obj):
        """
        تبدیل تاریخ میلادی ذخیره‌شده در DB به خروجی شمسی در لیست ادمین.

        قبلاً از پکیج jalali_date (django-jalali-date) استفاده می‌شد که روی
        پایتون ۳.۱۲+ به خاطر وابستگی به distutils کرش می‌کرد و دیگه نگه‌داری
        هم نمی‌شه. چون پروژه از قبل به django-jalali وابسته‌ست (که خودش روی
        jdatetime ساخته شده)، همون jdatetime رو مستقیم استفاده می‌کنیم —
        یک پکیج کمتر، بدون نیاز به هیچ compat شیمی.
        """
        if obj.date_joined:
            return jdatetime.datetime.fromgregorian(datetime=obj.date_joined).strftime(
                "%Y/%m/%d - %H:%M"
            )
        return "-"