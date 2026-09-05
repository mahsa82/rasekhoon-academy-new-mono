"""
مدیریت کوکی httpOnly برای refresh token.

[SRP - Single Responsibility Principle]
تنها مسئولیت این ماژول: ساخت/پاک‌کردن کوکی refresh token با تنظیمات امنیتی
یک‌دست (HttpOnly/Secure/SameSite/Path). هیچ Viewی مستقیم response.set_cookie
با پارامترهای دستی صدا نمی‌زنه — این‌طوری اگه فردا یکی از این تنظیمات
(مثلاً SameSite) باید عوض بشه، فقط همین یک فایل تغییر می‌کنه (OCP)، و
احتمال ناهماهنگی بین Login/VerifyOTP/Refresh/Logout (یکی Secure رو یادش
بره) از بین می‌ره.

چرا refresh token در کوکی httpOnly و access token فقط در پاسخ JSON:
- access token عمر کوتاهی داره (پیش‌فرض ۵ دقیقه) و قراره فرانت فقط در
  حافظه‌ی موقت (یک متغیر جاوااسکریپت، نه localStorage/sessionStorage) نگهش
  داره؛ با رفرش صفحه از بین می‌ره ولی همون لحظه از طریق /token/refresh/
  (که این کوکی رو خودکار همراه درخواست می‌فرسته) دوباره گرفته می‌شه.
- refresh token هیچ‌وقت در بدنه‌ی JSON برنمی‌گرده و هیچ‌وقت با جاوااسکریپت
  قابل خوندن نیست (HttpOnly=True) — یعنی حتی یک حمله‌ی XSS موفق هم نمی‌تونه
  این توکنِ بلندعمر (تا ۳۶۵ روز) رو بخونه/بدزده؛ فقط خودِ مرورگر با هر
  درخواست به همون مسیرها خودکار می‌فرستدش.

نکته‌ی مهم درباره‌ی CORS (که طبق تصمیم قبلی فعلاً پیکربندی نشده):
اگه فرانت روی دامنه/پورت متفاوتی از این API اجرا بشه (cross-site)، مرورگر
فقط در صورتی این کوکی رو در درخواست‌های fetch/XHR (با credentials: "include")
می‌فرسته که هم SAMESITE روی "None" باشه (به‌همراه Secure=True، یعنی فقط
روی HTTPS)، هم سمت سرور CORS_ALLOW_CREDENTIALS=True با یک origin مشخص
(نه "*") تنظیم شده باشه. تا وقتی CORS پیکربندی نشده (طبق درخواست قبلی)،
این فلو فقط برای فرانت هم‌-origin (یا پشت یک reverse proxy مشترک) درست کار
می‌کنه؛ SAMESITE پیش‌فرض این پروژه فعلاً روی "Lax" گذاشته شده، مناسب همین
حالت. اگه بعداً فرانت روی دامنه‌ی جدا رفت، باید همزمان CORS و
REFRESH_TOKEN_COOKIE_SAMESITE="None" تنظیم بشه.

همچنین: کوکی httpOnly مفهومی مرورگری است — اگه در آینده کلاینت غیرمرورگری
(مثلاً اپ موبایل بومی) به همین API وصل بشه، باید یک مسیر جایگزین (پذیرفتن
refresh از بدنه‌ی درخواست) براش در نظر گرفت؛ چیزی که فعلاً چون فرانت این
پروژه یک وب‌اپ است، پیاده نشده.
"""

from django.conf import settings

REFRESH_TOKEN_COOKIE_NAME = "refresh_token"

# فقط مسیرهای مربوط به احراز هویت این کوکی رو می‌گیرن، نه کل دامنه —
# جلوی ارسال بی‌مورد این کوکی حساس با هر درخواست دیگه‌ای به سایت رو می‌گیره.
REFRESH_TOKEN_COOKIE_PATH = "/accounts/api/v1/"


def set_refresh_cookie(response, refresh_token: str) -> None:
    lifetime = settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        max_age=int(lifetime.total_seconds()),
        httponly=True,
        secure=settings.REFRESH_TOKEN_COOKIE_SECURE,
        samesite=settings.REFRESH_TOKEN_COOKIE_SAMESITE,
        path=REFRESH_TOKEN_COOKIE_PATH,
    )


def clear_refresh_cookie(response) -> None:
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        path=REFRESH_TOKEN_COOKIE_PATH,
        samesite=settings.REFRESH_TOKEN_COOKIE_SAMESITE,
    )
