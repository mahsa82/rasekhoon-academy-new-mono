from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.db.models import Q
from rest_framework import serializers
from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import phone_regex, username_regex
from accounts.services import otp as otp_service

# ورود با گوگل فعلاً غیرفعاله — پایین‌تر کنار GoogleLoginSerializer توضیح داده شده
# from accounts.services.google_auth import (
#     GoogleTokenError,
#     get_or_create_user_from_google,
#     verify_google_id_token,
# )
from accounts.services.otp import verify_otp
from accounts.services.registration import send_registration_otp

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    """
    [SRP]
    این سریالایزر فقط مسئول اعتبارسنجی و ساخت/به‌روزرسانی کاربرِ در-انتظارِ-تایید
    است. ارسال OTP به سرویس جداگانه (accounts.services.registration) واگذار
    شده تا این کلاس مجبور نباشه چیزی درباره‌ی پیامک بدونه.

    نکته مهم: فیلدهای username/phone_number/email عمداً به‌صورت صریح
    (نه با تولید خودکار ModelSerializer) تعریف شده‌اند. اگر تولید خودکار
    می‌شدند، چون این فیلدها در مدل unique=True دارند، DRF به‌طور خودکار یک
    UniqueValidator روی هرکدوم اضافه می‌کرد که *قبل از* متدهای validate_*
    پایین اجرا می‌شه و همیشه با پیام عمومی انگلیسی رد می‌کنه — یعنی منطق
    سفارشی ما (مثلاً اجازه‌ی ثبت‌نام مجدد با شماره‌ای که هنوز تایید نشده)
    هیچ‌وقت اجرا نمی‌شد.
    """

    username = serializers.CharField(validators=[username_regex])
    phone_number = serializers.CharField(validators=[phone_regex])
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True, label="تکرار رمز عبور")

    class Meta:
        model = User
        fields = ["full_name", "username", "phone_number", "email", "password", "password2"]

    def validate_password(self, value):
        validate_password(value)
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("این نام کاربری قبلاً گرفته شده است.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value, is_phone_verified=True).exists():
            raise serializers.ValidationError("این ایمیل قبلاً ثبت و تایید شده است.")
        return value

    def validate_phone_number(self, value):
        if User.objects.filter(phone_number=value, is_phone_verified=True).exists():
            raise serializers.ValidationError("این شماره موبایل قبلاً ثبت و تایید شده است.")
        if otp_service.is_throttled(value):
            raise serializers.ValidationError(
                "تعداد درخواست‌های کد برای این شماره بیش از حد مجاز است. کمی بعد تلاش کنید."
            )
        return value

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password2": "رمز عبور و تکرار آن یکسان نیستند."})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        password = validated_data.pop("password")
        phone_number = validated_data["phone_number"]

        # update_or_create روی phone_number: اگه قبلاً همین شماره ثبت‌نام ناقص
        # (تایید‌نشده) داشته، رکورد قبلی بازنویسی می‌شه به‌جای خطای یکتا بودن —
        # همون چیزی که validate_phone_number بالا تضمینش می‌کنه.
        user, _created = User.objects.update_or_create(
            phone_number=phone_number,
            defaults={**validated_data, "is_active": False, "is_phone_verified": False},
        )
        user.set_password(password)
        user.save(update_fields=["password"])

        send_registration_otp(phone_number)
        return user


class VerifyOTPSerializer(serializers.Serializer):
    """
    [SRP]
    فقط یک کار: چک کردن اینکه کد وارد‌شده درسته یا نه، و در صورت درست بودن
    کاربر رو فعال می‌کنه. منطق تولید/مقایسه کد داخل accounts.services.otp
    هست، نه اینجا.
    """

    phone_number = serializers.CharField()
    code = serializers.CharField(max_length=6)

    def validate(self, attrs):
        if not User.objects.filter(phone_number=attrs["phone_number"]).exists():
            raise serializers.ValidationError("کاربری با این شماره یافت نشد.")

        if not verify_otp(attrs["phone_number"], attrs["code"], purpose="register"):
            raise serializers.ValidationError("کد نامعتبر یا منقضی شده است.")

        return attrs

    def save(self, **kwargs):
        user = User.objects.get(phone_number=self.validated_data["phone_number"])
        user.is_phone_verified = True
        user.is_active = True
        user.save(update_fields=["is_phone_verified", "is_active"])
        return user


class LoginSerializer(TokenObtainPairSerializer):
    """
    [LSP - Liskov Substitution Principle]
    این کلاس از TokenObtainPairSerializer ارث‌بری می‌کنه، نه اینکه از صفر
    بسازتش. یعنی LoginView می‌تونه به‌جای TokenObtainPairView معمولی از این
    استفاده کنه بدون اینکه رفتار پایه (خروجی access/refresh استاندارد،
    سازگاری با هر ابزاری که انتظار شکل استاندارد simplejwt رو داره) بشکنه.

    [OCP]
    فقط validate() رو override کردیم تا به‌جای پذیرفتن صرفاً phone_number
    (که پیش‌فرض simplejwt ازش استفاده می‌کنه)، هم ایمیل هم موبایل رو قبول
    کنه. منطق ساخت توکن (self.get_token) دست‌نخورده از کلاس پایه میاد —
    چیزی که قبلاً با RefreshToken.for_user() دستی بازسازی کرده بودیم، الان
    از خودِ فریم‌ورک میاد.

    نکته امنیتی: پیام خطا برای "کاربر نیست" و "رمز اشتباه" عمداً یکسانه،
    تا مهاجم نتونه با آزمون‌وخطا بفهمه کدوم ایمیل/موبایل تو سیستم ثبت‌نام کرده
    (جلوگیری از user enumeration).
    """

    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # فیلد پیش‌فرض simplejwt (phone_number چون USERNAME_FIELD ماست) رو
        # حذف می‌کنیم چون identifier جایگزینش شده
        self.fields.pop(User.USERNAME_FIELD, None)

    def validate(self, attrs):
        identifier = attrs["identifier"]
        password = attrs["password"]

        user = User.objects.filter(Q(phone_number=identifier) | Q(email=identifier)).first()

        if user is None or not user.check_password(password):
            raise AuthenticationFailed("شماره موبایل/ایمیل یا رمز عبور اشتباه است.")

        if not user.is_active:
            raise AuthenticationFailed("حساب کاربری هنوز فعال نشده است.")

        refresh = self.get_token(user)  # این متد از TokenObtainPairSerializer میاد
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }


# ورود با گوگل فعلاً غیرفعاله (تا وقتی GOOGLE_OAUTH_CLIENT_ID توی .env تنظیم
# بشه و آماده‌ی وصل کردنش به فرانت باشید). سرویس accounts/services/google_auth.py
# دست‌نخورده و تست‌شده باقی مونده. برای فعال‌سازی دوباره: این کلاس، importهای
# بالا، GoogleLoginView در views.py و مسیر login/google/ در urls.py رو از
# کامنت دربیارید.
#
# class GoogleLoginSerializer(serializers.Serializer):
#     """
#     [SRP]
#     این سریالایزر فقط id_token گوگل رو می‌گیره، نزد گوگل تاییدش می‌کنه (کار
#     accounts.services.google_auth) و کاربر متناظر رو پیدا/می‌سازه. صدور JWT
#     مسئولیت View هست (دقیقاً مثل الگوی VerifyOTPView).
#
#     [OCP/DIP]
#     منطق تایید توکن و پیدا/ساخت کاربر در سرویس جداست تا اگه فردا provider
#     دیگه‌ای (اپل و ...) اضافه شد، همین الگو بدون تغییر این فایل قابل تکرار باشه.
#     """
#
#     id_token = serializers.CharField(write_only=True)
#
#     def validate(self, attrs):
#         try:
#             profile = verify_google_id_token(attrs["id_token"])
#         except GoogleTokenError as exc:
#             raise serializers.ValidationError(str(exc))
#
#         user, created = get_or_create_user_from_google(profile)
#
#         if not user.is_active:
#             raise AuthenticationFailed("حساب کاربری غیرفعال است.")
#
#         attrs["user"] = user
#         attrs["created"] = created
#         return attrs


class LogoutSerializer(serializers.Serializer):
    """
    [SRP]
    فقط یک کار: توکن refresh ارسالی رو باطل (blacklist) می‌کنه. این دقیقاً
    همون نقطه‌ایه که طبق مشخصات پروژه، کاربر «خودش» از سیستم خارج می‌شه —
    در غیر این صورت (طبق تنظیمات SIMPLE_JWT) نشست تا ۳۶۵ روز پابرجاست.
    """

    refresh = serializers.CharField()

    def validate_refresh(self, value):
        try:
            self._token = RefreshToken(value)
        except TokenError:
            raise serializers.ValidationError("توکن نامعتبر یا از قبل باطل‌شده است.")
        return value

    def save(self, **kwargs):
        self._token.blacklist()


class ChangeUserRoleSerializer(serializers.Serializer):
    """
    [SRP]
    فقط validate می‌کنه که مقدار نقش جدید معتبره و اعمالش می‌کنه.
    تصمیم "کی اجازه داره این سریالایزر رو صدا بزنه" اصلاً مسئولیت این کلاس
    نیست — اون به IsAdminRole (در accounts/permissions.py) و View واگذار
    شده. این جدایی یعنی سریالایزر رو می‌شه کاملاً مستقل تست کرد بدون درگیر
    شدن با authorization.
    """

    user_type = serializers.ChoiceField(choices=User.UserType.choices)

    def update(self, instance, validated_data):
        instance.user_type = validated_data["user_type"]
        instance.save(update_fields=["user_type"])
        return instance
