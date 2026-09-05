"""
احراز هویتِ سفارشی‌شده‌ی پروژه روی JWTAuthentication استاندارد simplejwt.

[SRP - Single Responsibility Principle]
این ماژول فقط یک مسئولیتِ اضافه بر رفتار پیش‌فرض داره: رد کردن access
tokenی که رمز عبور صاحبش از زمان صدور آن عوض شده. تشخیص/دیکود امضا،
انقضا، user_id و غیره همچنان کامل بر عهده‌ی خودِ JWTAuthentication استاندارد
می‌مونه (LSP: این کلاس هر جا JWTAuthentication قبلاً استفاده می‌شد، بدون
تغییر رفتار جایگزینش می‌شه).

چرا اینجا (نه در یک middleware یا یک‌بار در view خاص):
DEFAULT_AUTHENTICATION_CLASSES پروژه (settings.py) این کلاس رو برای *همه‌ی*
endpointهای احرازهویت‌شده صدا می‌زنه؛ یعنی این تنها نقطه‌ایه که تضمین می‌کنه
هیچ endpointی، از قلم افتاده یا نه، بعد از تغییر رمز عبور کاربر همچنان با
access token قدیمی قابل استفاده نمونه. این دقیقاً جایگزین blacklist_all_
refresh_tokens (که قبلاً بر پایه‌ی جدول OutstandingToken در دیتابیس کار
می‌کرد) هست — بدون ذخیره‌ی هیچ توکن یا رکوردی در دیتابیس یا حتی کش؛ فقط
یک مقایسه‌ی امضا با رمز عبور *فعلی* کاربر (که به‌هرحال در دیتابیس هست).
"""

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed

from accounts.services.tokens import _password_signature


class AppJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user = super().get_user(validated_token)

        token_sig = validated_token.get("pwd_sig")
        if token_sig is None or token_sig != _password_signature(user):
            # یا توکنِ خیلی قدیمی (صادرشده قبل از این تغییر) بدون pwd_sig,
            # یا رمز عبور کاربر بعد از صدور همین توکن عوض شده — در هر دو
            # حالت، این توکن دیگه معتبر نیست و باید دوباره لاگین کنه.
            raise AuthenticationFailed(
                "نشست شما به دلیل تغییر رمز عبور منقضی شده است. لطفاً دوباره وارد شوید.",
                code="password_changed",
            )
        return user
