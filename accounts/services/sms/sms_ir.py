import logging

import requests
from django.conf import settings

from .base import SMSProvider

logger = logging.getLogger(__name__)


class SmsIrProvider(SMSProvider):
    """
    [LSP - Liskov Substitution Principle]
    هر جا کد یه SMSProvider انتظار داره، این کلاس بدون تغییر رفتار قابل جایگزینیه —
    امضای send_otp دقیقاً همون چیزیه که base.py قول داده (ورودی/خروجی یکسان،
    بدون exception غیرمنتظره‌ی جدید که کد صدازننده رو غافلگیر کنه).

    [OCP - Open/Closed Principle]
    اگه فردا provider دومی (مثلاً کاوه‌نگار) لازم شد، یه کلاس جدید مثل
    KavenegarProvider(SMSProvider) می‌سازیم — این فایل و هر کدی که ازش استفاده
    می‌کنه دست نمی‌خوره. کد "باز برای توسعه، بسته برای تغییر" می‌مونه.
    """

    API_URL = "https://api.sms.ir/v1/send/verify"

    def send_otp(self, phone_number: str, code: str) -> bool:
        payload = {
            "mobile": phone_number,
            "templateId": settings.SMS_IR_OTP_TEMPLATE_ID,
            "parameters": [{"name": "CODE", "value": code}],
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/plain",
            "x-api-key": settings.SMS_IR_API_KEY,
        }
        try:
            response = requests.post(self.API_URL, headers=headers, json=payload, timeout=5)
            if not response.ok:
                logger.warning("sms.ir OTP send failed: %s - %s", response.status_code, response.text)
            return response.ok
        except requests.RequestException:
            logger.exception("sms.ir request failed for phone=%s", phone_number)
            return False