from abc import ABC, abstractmethod


class SMSProvider(ABC):
    """
    [DIP - Dependency Inversion Principle]
    این یه انتزاعه، نه پیاده‌سازی. بقیه‌ی کد پروژه (سریالایزرها، ویوها) فقط به
    همین interface وابسته‌ان و هیچ‌وقت مستقیماً import 'requests' یا آدرس sms.ir
    رو نمی‌بینن. یعنی ماژول سطح‌بالا (منطق ثبت‌نام) به جزئیات سطح‌پایین
    (کدوم provider پیامکی) وابسته نیست — هر دو به این abstraction وابسته‌ان.
    """

    @abstractmethod
    def send_otp(self, phone_number: str, code: str) -> bool:
        """کد رو به شماره داده‌شده می‌فرسته. True/False برای موفقیت برمی‌گردونه."""
        raise NotImplementedError