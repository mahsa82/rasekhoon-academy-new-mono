"""
تمام منطق مربوط به «چه چیزی داخل توکن‌های JWT این پروژه قرار می‌گیره و چطور
اعتبارسنجی می‌شه» فقط اینجا زندگی می‌کنه.

[SRP - Single Responsibility Principle]
هیچ سریالایزر یا ویویی مستقیماً simplejwt.RefreshToken خام یا jwt.encode
صدا نمی‌زنه. همه از همین ماژول استفاده می‌کنن تا:
    ۱) payload توکن‌های لاگین/verify-otp هیچ‌وقت بین این دو مسیر ناهمگون نشه
       (نقش کاربر رو یکی یادش بره اضافه کنه، یکی نه) — یعنی DRY واقعی.
    ۲) اگه فردا claim جدیدی لازم شد (یا نوع توکن تک‌منظوره‌ی دیگه‌ای، مثل
       تایید ایمیل)، فقط همین فایل عوض می‌شه.

[OCP - Open/Closed Principle]
افزودن claim جدید به توکن‌های عادی → فقط AppRefreshToken.for_user تغییر
می‌کنه. افزودن نوع توکن تک‌منظوره‌ی جدید → یک زیرکلاس دیگه از Token، بدون
تغییر PasswordResetToken یا AppRefreshToken.
"""

import hashlib
import hmac
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken as BaseRefreshToken
from rest_framework_simplejwt.tokens import Token


class AppRefreshToken(BaseRefreshToken):
    """
    [LSP - Liskov Substitution Principle]
    هرجا RefreshToken اصلی simplejwt قابل استفاده‌ست، این کلاس هم هست —
    فقط for_user گسترش داده شده؛ access_token property، rotation و بقیه‌ی
    رفتار پایه دست‌نخورده از کلاس اصلی میان.

    [بدون ذخیره در دیتابیس]
    این کلاس دیگه به رفتار خودکار rest_framework_simplejwt.token_blacklist
    (که در for_user هر توکن صادرشده رو به‌عنوان یک ردیف OutstandingToken —
    شامل خودِ متن کامل توکن — در دیتابیس می‌نوشت) وابسته نیست؛ اون اپ از
    INSTALLED_APPS حذف شده. به‌جاش:
        ۱) هر توکن (چه در ثبت‌نام/verify-otp، چه در لاگین) یک pwd_sig هم
           می‌گیره (پایین‌تر توضیح داده شده) که ابطال *همه‌ی* نشست‌های
           کاربر بعد از تغییر رمز رو کاملاً stateless می‌کنه.
        ۲) لاگ‌اوت یک نشست خاص هم از طریق revoke_refresh_token (پایین‌تر)
           فقط jti همون توکن رو در کش (نه دیتابیس) با TTL برابر عمر
           باقی‌مانده‌ی توکن ثبت می‌کنه.

    نقش کاربر (و برای نقش پشتیبانی، زیرنوعش) همیشه داخل access و refresh
    token قرار می‌گیره تا فرانت/سرویس‌های دیگه بدون یک درخواست اضافه به
    API بتونن نقش کاربر رو مستقیماً از payload توکن بخونن.
    """

    @classmethod
    def for_user(cls, user):
        token = super().for_user(user)
        token["role"] = user.user_type
        if user.user_type == user.UserType.SUPPORT and user.support_role_id:
            # support_role_id (UUID پایدار) برای شناسایی دقیق و support_role
            # (نام فعلی نقش) برای نمایش مستقیم در فرانت بدون یک درخواست
            # اضافه. چون نقش‌های پشتیبانی حالا توسط مدیر ارشد و به‌صورت
            # پویا تعریف می‌شن (SupportRole)، نامش می‌تونه بعداً عوض بشه —
            # ولی چون توکن‌ها کوتاه‌عمرن (۵ دقیقه access) و در هر لاگین/
            # رفرش دوباره ساخته می‌شن، این مورد عملاً مشکلی ایجاد نمی‌کنه.
            token["support_role_id"] = str(user.support_role_id)
            token["support_role"] = user.support_role.name
        # امضای وابسته به رمز عبور فعلی — با تغییر رمز، همین لحظه همه‌ی
        # توکن‌های صادرشده‌ی قبلی (access و refresh، روی هر دستگاهی) از کار
        # می‌افتن، بدون نیاز به نگه‌داشتن فهرستی از «توکن‌های صادرشده».
        token["pwd_sig"] = _password_signature(user)
        return token


def _password_signature(user) -> str:
    """
    یک امضای کوتاه و یک‌طرفه (HMAC-SHA256) از رمز عبور هش‌شده‌ی *فعلی*
    کاربر می‌سازه.

    چرا نه خودِ هش رمز عبور:
    JWT فقط امضا می‌شه، نه رمزنگاری — یعنی هرکسی که توکن رو در دست داره،
    بدون نیاز به هیچ کلیدی می‌تونه payload رو بخونه (فقط base64). گذاشتن
    مستقیم هش رمز عبور کاربر در payload یعنی افشای اون هش برای هرکسی که
    توکن رو ببینه. این HMAC با کلید مخفی سرور (SECRET_KEY) ساخته می‌شه و
    یک‌طرفه‌ست؛ از روش نمی‌شه هش اصلی رو بازسازی کرد.

    چرا اصلاً لازمه (و جایگزین ذخیره‌ی توکن در دیتابیس می‌شه):
    به محض تغییر موفق رمز عبور، user.password عوض می‌شه، پس این امضا هم
    عوض می‌شه. این تابع الان توسط دو نوع توکن استفاده می‌شه:
        ۱) PasswordResetToken — همون‌طور که از اول بود: یک‌بارمصرف واقعی
           و stateless برای فرآیند فراموشی رمز.
        ۲) AppRefreshToken/access token عادی — به محض تغییر رمز، امضای
           همه‌ی توکن‌های قبلاً صادرشده (روی هر دستگاهی) دیگه با امضای
           تازه‌محاسبه‌شده مطابقت نداره و AppJWTAuthentication/
           AppTokenRefreshSerializer ردشون می‌کنن؛ این دقیقاً همون کاری
           رو می‌کنه که قبلاً blacklist_all_refresh_tokens (بر پایه‌ی
           جدول OutstandingToken) انجام می‌داد، بدون ذخیره‌ی هیچ رکوردی.
    """
    digest = hmac.new(
        key=settings.SECRET_KEY.encode(),
        msg=f"password-reset:{user.pk}:{user.password}".encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return digest[:32]


class PasswordResetToken(Token):
    """
    [SRP]
    یک نوع توکن کاملاً جدا و مستقل، فقط برای فرآیند «فراموشی رمز عبور».
    این توکن هیچ دسترسی دیگه‌ای به API نمی‌ده: DEFAULT_AUTHENTICATION_CLASSES
    پروژه (JWTAuthentication) فقط AccessToken رو برای احراز هویت معمولی
    قبول می‌کنه، پس اگه این توکن به‌جای Bearer token استفاده بشه، به خاطر
    ناهم‌خوانی token_type رد می‌شه. تنها کاربردش عبور از مرحله‌ی «تایید کد
    پیامکی» به مرحله‌ی «ثبت رمز جدید» است.

    [LSP]
    از Token پایه‌ی simplejwt ارث می‌بره، پس امضا (همون HS256/SIGNING_KEY
    تنظیمات SIMPLE_JWT پروژه)، محاسبه‌ی exp/iat، jti تصادفی، و اعتبارسنجی
    امضا/انقضا/token_type هنگام دیکود، همگی از همون مکانیزم امن و
    تست‌شده‌ی کتابخونه انجام می‌شه — هیچ چیزی دستی/از صفر پیاده نشده.

    بدون ذخیره در دیتابیس:
    این کلاس مستقیماً از Token خامِ simplejwt ارث می‌بره، نه از RefreshToken؛
    و RefreshToken/AppRefreshToken پروژه هم دیگه (از وقتی token_blacklist از
    INSTALLED_APPS حذف شده) هیچ ردیفی در دیتابیس نمی‌سازن. یعنی هیچ رکوردی
    از هیچ‌کدوم از توکن‌های این پروژه در هیچ جدولی ذخیره نمی‌شه؛ یک‌بارمصرف
    بودن این توکن فقط با _password_signature (بالا) تضمین می‌شه.
    """

    token_type = "password_reset"
    lifetime = getattr(settings, "PASSWORD_RESET_TOKEN_LIFETIME", timedelta(minutes=10))

    @classmethod
    def for_user(cls, user):
        token = super().for_user(user)
        token["pwd_sig"] = _password_signature(user)
        return token

    @property
    def user_id(self):
        return self[api_settings.USER_ID_CLAIM]

    def matches_current_password_of(self, user) -> bool:
        """آیا این توکن هنوز با رمز عبور *فعلی* کاربر سازگاره یا قبلاً مصرف/باطل شده."""
        return self.get("pwd_sig") == _password_signature(user)


def _revoked_refresh_key(jti: str) -> str:
    return f"revoked_refresh_jti:{jti}"


def revoke_refresh_token(token: BaseRefreshToken) -> None:
    """
    [SRP]
    یک refresh token خاص (همون‌ی که کاربر با اون لاگ‌اوت کرده) رو باطل
    می‌کنه — بدون هیچ ردیف/جدول دیتابیسی.

    چطور بدون دیتابیس ولی واقعاً مؤثر:
    فقط jti (شناسه‌ی یکتای همین توکن، نه خودِ متن توکن) در کش (Redis) ذخیره
    می‌شه، با TTL دقیقاً برابر زمان باقی‌مانده تا انقضای طبیعی همین توکن.
    یعنی همون لحظه‌ای که توکن به‌هرحال منقضی می‌شد، رکورد کش هم خودش پاک
    می‌شه — برخلاف OutstandingToken/BlacklistedToken قبلی که برای همیشه
    (حتی سال‌ها بعد از انقضای واقعی توکن) در دیتابیس می‌موند.

    این مقدار توسط AppTokenRefreshSerializer چک می‌شه تا با همون refresh
    tokenِ لاگ‌اوت‌شده نشه دوباره access token جدید گرفت. access tokenهای
    از قبل صادرشده (jti جداگانه دارن) عمر کوتاهی دارن (پیش‌فرض ۵ دقیقه) و
    با گذشت همون مدت خودشون از کار می‌افتن — این محدودیت شناخته‌شده و
    پذیرفته‌شده‌ی معماری access+refresh token است، نه یک نقص.
    """
    jti = token[api_settings.JTI_CLAIM]
    exp = token["exp"]
    ttl_seconds = max(int(exp - timezone.now().timestamp()), 1)
    cache.set(_revoked_refresh_key(jti), True, timeout=ttl_seconds)


def is_refresh_token_revoked(jti: str) -> bool:
    """آیا این jti قبلاً (با لاگ‌اوت) باطل اعلام شده — برای رد کردن تلاش رفرش با آن."""
    return cache.get(_revoked_refresh_key(jti)) is not None
