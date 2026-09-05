"""
مدیریت کد OTP با استفاده از کش (Redis) به‌جای دیتابیس.

چرا کش:
- عمر کد کوتاهه (چند دقیقه) و حجم درخواست‌ها می‌تونه زیاد باشه؛
  نوشتن/خوندن مداوم روی Postgres برای دیتای اینقدر ناپایدار به‌صرفه نیست.
- Redis خودش TTL داره، پس نیازی به cleanup job دستی برای پاک کردن رکوردهای
  منقضی/استفاده‌شده نیست — با گذشت زمان خودش پاک می‌شه.
- برای rate limiting هم می‌تونیم از همون Redis با incr/expire استفاده کنیم،
  بدون نیاز به کوئری روی جدول جدا.

پیش‌نیاز settings.py:

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": env("REDIS_URL", default="redis://127.0.0.1:6379/1"),
        "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
    }
}
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from django.core.cache import cache

OTP_TTL_SECONDS = 180          # ۳ دقیقه اعتبار کد
MAX_VERIFY_ATTEMPTS = 5        # حداکثر تلاش برای وارد کردن کد درست
THROTTLE_WINDOW_SECONDS = 600  # ۱۰ دقیقه
THROTTLE_MAX_REQUESTS = 3      # حداکثر تعداد درخواست ارسال کد در بازه بالا


def _hash_code(phone_number: str, purpose: str, code: str) -> str:
    """
    [امنیت]
    به‌جای خودِ کد، فقط هش آن در کش ذخیره می‌شود — درست مثل رمز عبور کاربر
    که هیچ‌وقت خام در دیتابیس نیست. این‌طوری اگر یک روز به هر دلیلی
    (ابزار مانیتورینگ، دسترسی غیرمجاز به Redis و ...) محتوای کش قابل
    مشاهده باشد، کدهای معتبرِ در حال استفاده مستقیماً لو نمی‌روند.

    phone_number/purpose هم داخل ورودی هش شرکت داده شده‌اند تا کد هشِ یک
    شماره/purpose برای شماره یا purpose دیگری قابل استفاده‌ی مجدد نباشد
    (even اگر دو کاربر تصادفاً کد یکسانی گرفته باشند).
    """
    digest_input = f"{phone_number}:{purpose}:{code}".encode()
    return hashlib.sha256(digest_input).hexdigest()


# ساخت کلید ذخیره خودِ کد
def _otp_key(phone_number: str, purpose: str) -> str:
    return f"otp:{purpose}:{phone_number}"

# ساخت کلید شمارش تعداد تلاش‌های ناموفق ورود کد.
def _attempts_key(phone_number: str, purpose: str) -> str:
    return f"otp:{purpose}:{phone_number}:attempts"

# ساخت کلید شمارش تعداد درخواست‌های ارسال SMS برای جلوگیری از اسپم.
def _throttle_key(phone_number: str) -> str:
    return f"otp:throttle:{phone_number}"


@dataclass
class OTPRequestResult:
    success: bool
    code: str | None = None
    error: str | None = None  # "throttled" وقتی محدودیت درخواست رد شده باشه


def is_throttled(phone_number: str) -> bool:
    """
    [SRP - Single Responsibility Principle]
    این تابع فقط یه کار می‌کنه: جواب می‌ده که آیا شماره به سقف درخواست رسیده یا نه.
    خودش تصمیم نمی‌گیره چه خطایی نمایش داده بشه یا چیکار باید کرد — اون تصمیم
    مال لایه بالاتر (سریالایزر) هست.
    """
    return cache.get(_throttle_key(phone_number), 0) >= THROTTLE_MAX_REQUESTS


def request_otp(phone_number: str, purpose: str = "register") -> OTPRequestResult:
    """یک کد جدید تولید و در کش ذخیره می‌کنه. rate limit رو هم چک می‌کنه."""
    throttle_key = _throttle_key(phone_number)
    request_count = cache.get(throttle_key, 0)

    if request_count >= THROTTLE_MAX_REQUESTS:
        return OTPRequestResult(success=False, error="throttled")

    code = f"{secrets.randbelow(90000) + 10000}"  # کد ۵ رقمی، امن در برابر پیش‌بینی

    # فقط هش کد در کش ذخیره می‌شود؛ خودِ کد فقط در همین لحظه (برای ارسال
    # پیامک) در پاسخ این تابع برمی‌گردد و جایی ذخیره نمی‌شود.
    cache.set(_otp_key(phone_number, purpose), _hash_code(phone_number, purpose, code), timeout=OTP_TTL_SECONDS)
    cache.delete(_attempts_key(phone_number, purpose))  # ریست شمارنده تلاش برای کد جدید

    # افزایش شمارنده throttle؛ اولین بار TTL رو ست می‌کنیم، بعدش فقط incr
    if request_count == 0:
        cache.set(throttle_key, 1, timeout=THROTTLE_WINDOW_SECONDS)
    else:
        cache.incr(throttle_key)

    return OTPRequestResult(success=True, code=code)


def verify_otp(phone_number: str, code: str, purpose: str = "register") -> bool:
    """
    کد وارد شده رو (بعد از هش کردن) با هشِ ذخیره‌شده در کش مقایسه می‌کنه.
    در صورت موفقیت، کد رو از کش پاک می‌کنه (یک‌بارمصرف واقعی).

    مقایسه با hmac.compare_digest انجام می‌شه، نه ==، تا زمان مقایسه به
    تعداد کاراکترهای مشترکِ ابتدای رشته وابسته نباشه (جلوگیری از timing
    attack روی خودِ فرآیند مقایسه — یک لایه‌ی دفاعی اضافه، در کنار throttle
    و سقف تلاش که اصل حمله‌ی brute-force رو مسدود می‌کنن).
    """
    attempts_key = _attempts_key(phone_number, purpose)
    attempts = cache.get(attempts_key, 0)

    if attempts >= MAX_VERIFY_ATTEMPTS:
        return False

    stored_hash = cache.get(_otp_key(phone_number, purpose))

    if stored_hash is None:
        return False  # منقضی شده یا اصلاً درخواست نشده

    if not hmac.compare_digest(stored_hash, _hash_code(phone_number, purpose, code)):
        cache.set(attempts_key, attempts + 1, timeout=OTP_TTL_SECONDS)
        return False

    # موفق — پاک‌سازی کامل کلیدهای مربوطه
    cache.delete(_otp_key(phone_number, purpose))
    cache.delete(attempts_key)
    return True