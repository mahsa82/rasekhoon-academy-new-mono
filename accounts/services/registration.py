from accounts.services import otp as otp_service
from accounts.services.otp import OTPRequestResult
from accounts.services.sms import get_sms_provider


def send_registration_otp(phone_number: str) -> OTPRequestResult:
    """
    [SRP]
    این تابع فقط «هماهنگ‌کننده» (orchestrator) هست — خودش نه می‌دونه کد چطور
    تولید می‌شه (اون کار otp_service است) نه می‌دونه پیامک چطور ارسال می‌شه
    (اون کار SMSProvider است). فقط این دو رو کنار هم می‌ذاره.
    این جدایی یعنی اگه فردا otp_service یا SMSProvider عوض بشن، این فایل
    دست‌نخورده می‌مونه.
    """
    result = otp_service.request_otp(phone_number, purpose="register")
    if result.success:
        provider = get_sms_provider()
        provider.send_otp(phone_number, result.code)
    return result