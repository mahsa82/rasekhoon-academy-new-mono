from rest_framework.permissions import BasePermission


class IsAdminRole(BasePermission):
    """
    [ISP - Interface Segregation Principle]
    این کلاس فقط یک قانون رو چک می‌کنه: «آیا کاربر مدیر ارشد (بیزینسی) هست».
    عمداً چک‌های نامرتبط دیگه (مثل verified بودن موبایل، یا فعال بودن حساب) رو
    اینجا قاطی نکردیم — هرکدوم اگه لازم شد، یه permission class جدای خودشو
    می‌گیره (مثل IsPhoneVerified که می‌تونی جدا بسازی) و در view کنار هم
    ترکیب می‌شن: permission_classes = [IsAuthenticated, IsAdminRole].
    این‌طوری هیچ کلاسی مجبور نیست منطقی رو "پیاده‌سازی" کنه که بهش نیازی نداره.

    [LSP]
    از BasePermission درست ارث‌بری شده و has_permission همون امضایی رو داره
    که DRF انتظار داره؛ هر جا BasePermission قابل استفاده‌ست، این کلاس هم هست.
    """

    message = "فقط مدیر ارشد به این عملیات دسترسی دارد."

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and (user.user_type == user.UserType.ADMIN or user.is_superuser)
        )


class IsInstructorRole(BasePermission):
    """[ISP] فقط یک قانون: کاربر نقش «مدرس» داره یا نه."""

    message = "فقط مدرس به این عملیات دسترسی دارد."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.user_type == user.UserType.INSTRUCTOR)


class IsTeachingAssistantRole(BasePermission):
    """[ISP] فقط یک قانون: کاربر نقش «کمک مدرس» داره یا نه."""

    message = "فقط کمک مدرس به این عملیات دسترسی دارد."

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user and user.is_authenticated and user.user_type == user.UserType.TEACHING_ASSISTANT
        )


class IsSupportRole(BasePermission):
    """
    [ISP]
    فقط یک قانون: کاربر نقش «پشتیبانی» داره یا نه — فارغ از زیرنوعش (فنی،
    مالی، عمومی و...). برای عملیاتی که هر نوع پشتیبانی باید بهش دسترسی
    داشته باشه (مثلاً دیدن تیکت‌ها)، کافیه.
    """

    message = "فقط پشتیبانی به این عملیات دسترسی دارد."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.user_type == user.UserType.SUPPORT)


def support_role_permission(role_name: str) -> type[BasePermission]:
    """
    [OCP - Open/Closed Principle] + Factory
    نقش‌های پشتیبانی (accounts.models.SupportRole) دیگه در کد ثابت نیستن —
    مدیر ارشد خودش از طریق API تعریف/ویرایش/غیرفعالشون می‌کنه (به همین
    خاطر دیگه یک enum بسته مثل قبل اینجا نداریم). این factory یک کلاس
    permission می‌سازه که فقط کاربرِ دارای همون نقش پشتیبانیِ *مشخص*
    (با تطبیق روی نام فعلی‌اش در دیتابیس) رو قبول می‌کنه.

    نکته: چون name این‌جا در لحظه‌ی درخواست با دیتابیس مقایسه می‌شه (نه یک
    مقدار ثابت کامپایل‌شده)، اگه مدیر ارشد بعداً اسم نقش رو عوض کنه، همین
    مقدار رشته‌ای که به support_role_permission پاس دادید هم باید عوض بشه —
    برای گیت‌های حیاتی که نباید با تغییر نام نقش بشکنن، بهتره به‌جای این
    factory از IsSupportRole (هر پشتیبانی) به همراه یک چک دستی روی
    support_role_id (شناسه‌ی پایدار UUID) استفاده بشه.

    مثال استفاده:
        IsNetworkSupport = support_role_permission("فنی")
        permission_classes = [IsAuthenticated, IsNetworkSupport]
    """

    class _SupportRolePermission(BasePermission):
        message = f"فقط پشتیبانی «{role_name}» به این عملیات دسترسی دارد."

        def has_permission(self, request, view):
            user = request.user
            return bool(
                user
                and user.is_authenticated
                and user.user_type == user.UserType.SUPPORT
                and user.support_role_id
                and user.support_role.name == role_name
            )

    _SupportRolePermission.__name__ = f"IsSupportRole_{role_name}"
    return _SupportRolePermission