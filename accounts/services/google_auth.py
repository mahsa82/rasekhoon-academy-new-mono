"""
احراز هویت با گوگل.

[SRP]
این ماژول دو مسئولیت جدا اما مرتبط داره که عمداً در دو تابع جدا نگه داشته شدن:
    - verify_google_id_token: فقط توکن رو نزد گوگل تایید می‌کنه.
    - get_or_create_user_from_google: فقط تصمیم می‌گیره با یه پروفایل تاییدشده
      چیکار کنه (پیدا کردن کاربر موجود / اتصال به حساب موجود / ساخت کاربر جدید).
هیچ‌کدوم نمی‌دونن JWT چطور صادر می‌شه — اون مسئولیت View (لایه HTTP) است.

پیش‌نیاز settings.py / .env:
    GOOGLE_OAUTH_CLIENT_ID = env("GOOGLE_OAUTH_CLIENT_ID")
    # همون Client ID اپ گوگل که فرانت (وب/موبایل) هنگام Sign in with Google
    # استفاده کرده و id_token رو باهاش گرفته. verify_oauth2_token چک می‌کنه
    # که claim «aud» توی توکن دقیقاً همین مقدار باشه — یعنی توکنی که برای
    # یک اپ دیگه صادر شده، اینجا رد می‌شه.

پیش‌نیاز requirements.txt:
    google-auth==2.*
"""

import re
import secrets
from dataclasses import dataclass

from django.conf import settings
from django.contrib.auth import get_user_model
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token

User = get_user_model()


class GoogleTokenError(Exception):
    """توکن گوگل نامعتبره، منقضی شده، یا ایمیل حسابش تایید نشده."""


@dataclass
class GoogleProfile:
    google_id: str
    email: str
    full_name: str


def verify_google_id_token(token: str) -> GoogleProfile:
    """
    توکن رو مستقیماً نزد گوگل (نه با دیکود ساده JWT) تایید می‌کنه — یعنی
    امضا، تاریخ انقضا و audience (aud == Client ID خودمون) همه چک می‌شن.
    """
    try:
        payload = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), settings.GOOGLE_OAUTH_CLIENT_ID
        )
    except (ValueError, GoogleAuthError):
        raise GoogleTokenError("توکن گوگل نامعتبر یا منقضی شده است.")

    if not payload.get("email_verified", False):
        raise GoogleTokenError("ایمیل حساب گوگل تایید نشده است.")

    return GoogleProfile(
        google_id=payload["sub"],
        email=payload["email"],
        full_name=(payload.get("name") or "").strip(),
    )


def _generate_unique_username(email: str) -> str:
    """
    از قسمت قبل از @ ایمیل، یک نام کاربری یکتا و مطابق قوانین یوزرنیم پروژه
    (فقط حروف انگلیسی/عدد/نقطه/آندرلاین) می‌سازه.
    """
    local_part = email.split("@")[0]
    base = re.sub(r"[^A-Za-z0-9._]", "", local_part).strip(".")[:24]
    base = base or "user"
    if len(base) < 3:
        base = f"{base}{'0' * (3 - len(base))}"

    username = base
    while User.objects.filter(username=username).exists():
        username = f"{base}{secrets.randbelow(9000) + 1000}"
    return username


def get_or_create_user_from_google(profile: GoogleProfile):
    """
    کاربر متناظر با این پروفایل گوگل رو برمی‌گردونه (user, created).

    ترتیب تصمیم‌گیری:
    ۱) اگه قبلاً یه کاربر با همین google_id وصل شده، همونه.
    ۲) اگه کاربری با همین ایمیل از قبل ثبت‌نام (مثلاً با موبایل) کرده، حساب
       گوگل بهش وصل می‌شه — چون گوگل خودش تضمین کرده این ایمیل تایید شده،
       این اتصال امن حساب می‌شه.
    ۳) در غیر این صورت کاربر تازه ساخته می‌شه. is_active=True چون Google
       OAuth خودش یک احراز هویت قوی محسوب می‌شه؛ is_phone_verified همچنان
       False می‌مونه چون شماره موبایل جداگانه و طبق فرایند OTP پروژه تایید
       می‌شه (کاربر می‌تونه بعداً از پروفایلش شماره اضافه/تایید کنه).
    """
    user = User.objects.filter(google_id=profile.google_id).first()
    if user:
        return user, False

    user = User.objects.filter(email=profile.email).first()
    if user:
        user.google_id = profile.google_id
        user.save(update_fields=["google_id"])
        return user, False

    username = _generate_unique_username(profile.email)
    user = User(
        username=username,
        email=profile.email,
        full_name=profile.full_name,
        google_id=profile.google_id,
        is_active=True,
        is_phone_verified=False,
    )
    user.set_unusable_password()
    user.save()
    return user, True
