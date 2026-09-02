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