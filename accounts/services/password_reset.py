from accounts.services import otp as otp_service
from accounts.services.otp import OTPRequestResult
from accounts.services.sms import get_sms_provider


def send_password_reset_otp(phone_number: str) -> OTPRequestResult:
    """
    [SRP]
    درست مثل accounts.services.registration.send_registration_otp، این
    تابع فقط «هماهنگ‌کننده»ست: نه تولید کد (otp_service) نه ارسال پیامک
    (SMSProvider) رو خودش انجام نمی‌ده، فقط این دو رو کنار هم می‌ذاره.

    از همون accounts.services.otp با purpose جدا ("password_reset")
    استفاده می‌کنه، پس کد بازیابی رمز از کد ثبت‌نام کاملاً مستقل و
    غیرقابل استفاده‌ی متقابله (کدِ گرفته‌شده برای ثبت‌نام روی یک شماره،
    برای بازیابی رمز همون شماره اعتبار نداره و برعکس) — بدون نیاز به
    نوشتن دوباره‌ی منطق کش/throttle/تلاش مجدد.
    """
    result = otp_service.request_otp(phone_number, purpose="password_reset")
    if result.success:
        provider = get_sms_provider()
        provider.send_otp(phone_number, result.code)
    return result
