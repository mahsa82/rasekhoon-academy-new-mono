from django.conf import settings
from django.utils.module_loading import import_string

from accounts.services.sms.base import SMSProvider


def get_sms_provider() -> SMSProvider:
    """
    [DIP]
    کد صدازننده (مثلاً accounts/services/registration.py) نمی‌دونه و نباید بدونه
    کدوم کلاس concrete ساخته می‌شه — این تصمیم از settings.SMS_PROVIDER_CLASS
    خونده می‌شه. یعنی حتی provider هم از طریق تنظیمات قابل تعویضه، بدون تغییر کد.

    settings.py:
        SMS_PROVIDER_CLASS = "accounts.services.sms.sms_ir.SmsIrProvider"
    """
    provider_class = import_string(settings.SMS_PROVIDER_CLASS)
    return provider_class()
