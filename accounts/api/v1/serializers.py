import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.db.models import Q
from rest_framework import serializers
from rest_framework_simplejwt.exceptions import AuthenticationFailed, InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import SupportRole, phone_regex, username_regex
from accounts.services import otp as otp_service

logger = logging.getLogger(__name__)

# ورود با گوگل فعلاً غیرفعاله — پایین‌تر کنار GoogleLoginSerializer توضیح داده شده
# from accounts.services.google_auth import (
#     GoogleTokenError,
#     get_or_create_user_from_google,
#     verify_google_id_token,
# )
from accounts.services.otp import verify_otp
from accounts.services.password_reset import send_password_reset_otp
from accounts.services.registration import send_registration_otp
from accounts.services.tokens import (
    AppRefreshToken,
    PasswordResetToken,
    is_refresh_token_revoked,
    revoke_refresh_token,
)
from accounts.services.tokens import _password_signature

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
            logger.warning("verify-otp برای شماره‌ی ثبت‌نشده: %s", attrs["phone_number"])
            raise serializers.ValidationError("کاربری با این شماره یافت نشد.")

        if not verify_otp(attrs["phone_number"], attrs["code"], purpose="register"):
            logger.warning("کد OTP اشتباه/منقضی برای شماره: %s", attrs["phone_number"])
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

    [OCP]
    token_class پیش‌فرض simplejwt (RefreshToken خام) رو با AppRefreshToken
    خودمون (accounts/services/tokens.py) عوض کردیم — همین یک خط کافیه تا
    get_token ارثی از TokenObtainPairSerializer، بدون این‌که این کلاس یا
    متد validate پایین‌تر تغییری بکنه، نقش کاربر رو هم داخل payload بذاره.
    """

    token_class = AppRefreshToken

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
            # [امنیت] هیچ‌وقت خودِ رمز عبور رو لاگ نمی‌کنیم — فقط identifier،
            # برای مانیتورینگ الگوی brute-force (مثلاً چند شکست پشت‌سرهم
            # روی یک شماره/ایمیل خاص).
            logger.warning("تلاش ورود ناموفق برای identifier=%s", identifier)
            raise AuthenticationFailed("شماره موبایل/ایمیل یا رمز عبور اشتباه است.")

        if not user.is_active:
            logger.warning("تلاش ورود برای حساب غیرفعال: user_id=%s", user.id)
            raise AuthenticationFailed("حساب کاربری هنوز فعال نشده است.")

        refresh = self.get_token(user)  # این متد از TokenObtainPairSerializer میاد
        logger.info(
            "ورود موفق: user_id=%s username=%s role=%s", user.id, user.username, user.user_type
        )

        # [SRP] این دیکشنری همون چیزیه که از توکن هم قابل استخراجه (نقش،
        # شناسه کاربر و ...) — عمداً اینجا هم مستقیم توی بدنه‌ی JSON
        # می‌ذاریمش تا فرانت مجبور نباشه برای نمایش ساده‌ی نام/نقش کاربر،
        # payload توکن رو decode کنه. منبع حقیقت هنوز خودِ توکنه (این فقط
        # یک کپی راحت برای UI است، نه یک claim امنیتی جدا).
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user_id": str(user.id),
            "username": user.username,
            "full_name": user.full_name,
            "role": user.user_type,
            "support_role_id": str(user.support_role_id) if user.support_role_id else None,
            "support_role": user.support_role.name if user.support_role_id else None,
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


class AppTokenRefreshSerializer(TokenRefreshSerializer):
    """
    [LSP]
    از TokenRefreshSerializer استاندارد simplejwt ارث می‌بره؛ رفتار اصلی
    (اعتبارسنجی امضا/انقضا، rotation طبق ROTATE_REFRESH_TOKENS) دست‌نخورده
    می‌مونه — فقط دو تا چک امنیتی *قبل* از صدور access token جدید اضافه
    شده که هیچ‌کدوم توسط TokenRefreshSerializer پیش‌فرض انجام نمی‌شن:

    ۱) آیا همین refresh token قبلاً با /logout/ باطل شده؟ (revoke_refresh_token)
    ۲) آیا رمز عبور صاحبش از زمان صدور این توکن عوض شده؟ (pwd_sig)

    بدون این override، حتی بعد از logout یا تغییر رمز، هنوز می‌شد با همون
    refresh token قدیمی به /token/refresh/ زد و access token تازه گرفت —
    چون خودِ TokenRefreshSerializer پیش‌فرض فقط امضا/انقضا/token_type رو
    چک می‌کنه، نه این دو تا قانون امنیتی مخصوص این پروژه.
    """

    def validate(self, attrs):
        try:
            refresh = RefreshToken(attrs["refresh"])
        except TokenError as exc:
            raise InvalidToken(exc.args[0]) from exc

        jti = refresh[api_settings.JTI_CLAIM]
        if is_refresh_token_revoked(jti):
            raise InvalidToken("این نشست قبلاً از سیستم خارج شده (logout) است.")

        user_id = refresh[api_settings.USER_ID_CLAIM]
        user = User.objects.filter(**{api_settings.USER_ID_FIELD: user_id}).first()
        if user is None:
            raise InvalidToken("کاربر مرتبط با این توکن یافت نشد.")

        if refresh.get("pwd_sig") != _password_signature(user):
            raise InvalidToken("این نشست به دلیل تغییر رمز عبور دیگر معتبر نیست. لطفاً دوباره وارد شوید.")

        return super().validate(attrs)


class LogoutSerializer(serializers.Serializer):
    """
    [SRP]
    فقط یک کار: توکن refresh ارسالی رو باطل می‌کنه. این دقیقاً همون نقطه‌ایه
    که طبق مشخصات پروژه، کاربر «خودش» از سیستم خارج می‌شه — در غیر این
    صورت (طبق تنظیمات SIMPLE_JWT) نشست تا ۳۶۵ روز پابرجاست.

    [بدون ذخیره در دیتابیس]
    برخلاف قبل (که RefreshToken.blacklist() یک ردیف BlacklistedToken در
    دیتابیس می‌ساخت)، این‌جا revoke_refresh_token فقط jti این توکن رو در
    کش با TTL برابر عمر باقی‌مانده‌اش ثبت می‌کنه — نگاه کنید به
    accounts/services/tokens.py برای جزئیات.
    """

    refresh = serializers.CharField()

    def validate_refresh(self, value):
        try:
            self._token = RefreshToken(value)
        except TokenError:
            raise serializers.ValidationError("توکن نامعتبر یا از قبل باطل‌شده است.")
        return value

    def save(self, **kwargs):
        revoke_refresh_token(self._token)


class ChangeUserRoleSerializer(serializers.Serializer):
    """
    [SRP]
    فقط validate می‌کنه که مقدار نقش جدید (و در صورت لزوم نقش پشتیبانی)
    معتبره و اعمالش می‌کنه. تصمیم "کی اجازه داره این سریالایزر رو صدا بزنه"
    اصلاً مسئولیت این کلاس نیست — اون به IsAdminRole (در
    accounts/api/v1/permissions.py) و View واگذار شده. این جدایی یعنی
    سریالایزر رو می‌شه کاملاً مستقل تست کرد بدون درگیر شدن با authorization.

    [OCP/DIP]
    support_role_id به‌جای یک ChoiceField ثابت، یک PrimaryKeyRelatedField
    روی مدل SupportRoleه — یعنی نقش‌های پشتیبانیِ مجاز از دیتابیس خونده
    می‌شن (همون‌هایی که مدیر ارشد از طریق SupportRoleListCreateView تعریف
    کرده)، نه از یک enum ثابت در کد. queryset فقط نقش‌های is_active=True رو
    قبول می‌کنه تا نتونید یک نقشِ از قبل غیرفعال‌شده رو به کاربر جدید بدید.

    این فیلد اختیاریه چون فقط وقتی user_type == SUPPORT باشه معنا داره؛
    validate پایین دقیقاً همون قانونی رو چک می‌کنه که User.clean() هم چک
    می‌کنه (DRF به‌طور پیش‌فرض Model.clean رو صدا نمی‌زنه، پس این تکرارِ
    عمدی لازمه تا خطا با پیام فارسی و ساختار serializer-error برگرده، نه
    یک 500 غیرمنتظره).
    """

    user_type = serializers.ChoiceField(choices=User.UserType.choices)
    support_role_id = serializers.PrimaryKeyRelatedField(
        source="support_role",
        queryset=SupportRole.objects.filter(is_active=True),
        required=False,
        allow_null=True,
    )

    def validate(self, attrs):
        user_type = attrs["user_type"]
        support_role = attrs.get("support_role")

        if user_type == User.UserType.SUPPORT and not support_role:
            raise serializers.ValidationError(
                {"support_role_id": "برای نقش «پشتیبانی»، انتخاب نقش پشتیبانی الزامی است."}
            )
        if user_type != User.UserType.SUPPORT and support_role:
            raise serializers.ValidationError(
                {"support_role_id": "این فیلد فقط برای نقش «پشتیبانی» قابل استفاده است."}
            )
        return attrs

    def update(self, instance, validated_data):
        instance.user_type = validated_data["user_type"]
        instance.support_role = validated_data.get("support_role")
        instance.save(update_fields=["user_type", "support_role"])
        return instance


def _find_user_by_identifier(identifier: str):
    """[DRY] پیدا کردن کاربر با موبایل یا ایمیل — همون منطق LoginSerializer، یک‌جا."""
    return User.objects.filter(Q(phone_number=identifier) | Q(email=identifier)).first()


class ForgotPasswordRequestSerializer(serializers.Serializer):
    """
    [SRP]
    قدم اول فراموشی رمز عبور: فقط یک کد OTP (با purpose جدای
    "password_reset") به موبایل کاربر می‌فرسته. هیچ توکنی اینجا صادر
    نمی‌شه — صرفاً هماهنگ‌کردن otp_service/SMSProvider از طریق
    send_password_reset_otp.

    [امنیت - ضد User Enumeration]
    این سریالایزر عمداً هیچ‌وقت raise نمی‌کنه که «کاربری با این مشخصات
    نیست» — چه identifier با کاربری مطابقت داشته باشه چه نه، چه شماره‌ی
    آن کاربر throttle شده باشه یا نه، از دید فراخوان (ForgotPasswordRequestView)
    خروجی و پیام همیشه یکسانه. اگه اینجا خطای متفاوت برای «کاربر نیست»
    برمی‌گردوندیم، مهاجم می‌تونست با امتحان شماره‌های مختلف بفهمه کدوم‌ها
    توی سیستم ثبت‌نام شدن.
    """

    identifier = serializers.CharField()

    def save(self, **kwargs):
        user = _find_user_by_identifier(self.validated_data["identifier"])

        # کاربر گوگلی بدون موبایل تاییدشده، یا کاربر غیرفعال/موبایل تاییدنشده:
        # راهی برای ارسال OTP نداریم، پس بی‌سروصدا هیچ کاری نمی‌کنیم (نه خطا).
        if user is None or not user.phone_number or not user.is_active or not user.is_phone_verified:
            return

        # throttle از قبل توی otp_service پیاده‌ست؛ اگه سقف زده باشه request_otp
        # خودش موفق نمی‌شه و SMS ارسال نمی‌شه — نیازی به چک جدا و افشای این
        # وضعیت به کاربر نیست.
        send_password_reset_otp(user.phone_number)


class ForgotPasswordVerifySerializer(serializers.Serializer):
    """
    [SRP]
    قدم دوم: کد پیامکی رو تایید می‌کنه و در صورت درست بودن، یک
    PasswordResetToken (JWT تک‌منظوره‌ی کوتاه‌عمر، بدون ذخیره در دیتابیس)
    برمی‌گردونه که فقط اجازه‌ی رفتن به قدم سوم (ثبت رمز جدید) رو می‌ده.

    نکته امنیتی: پیام خطا برای «کاربری با این مشخصات نیست» و «کد اشتباه/
    منقضی» عمداً یکسانه (دقیقاً همون الگوی LoginSerializer) تا این
    اندپوینت هم قابل استفاده برای user enumeration نباشه.
    """

    identifier = serializers.CharField()
    code = serializers.CharField(max_length=6)

    def validate(self, attrs):
        generic_error = "کد نامعتبر یا منقضی شده است."
        user = _find_user_by_identifier(attrs["identifier"])

        if user is None or not user.phone_number:
            raise serializers.ValidationError(generic_error)

        if not verify_otp(user.phone_number, attrs["code"], purpose="password_reset"):
            raise serializers.ValidationError(generic_error)

        attrs["user"] = user
        return attrs


class ForgotPasswordConfirmSerializer(serializers.Serializer):
    """
    [SRP]
    قدم سوم و آخر: reset_token صادرشده در قدم قبل رو اعتبارسنجی می‌کنه و
    در صورت معتبر بودن، رمز جدید رو ثبت می‌کنه.

    اعتبارسنجی reset_token شامل سه لایه‌ست (هر سه از PasswordResetToken/
    Token پایه‌ی simplejwt میان، چیزی دستی چک نشده):
        ۱) امضا و انقضا (Token.__init__ با verify=True)
        ۲) token_type == "password_reset" (جلوگیری از استفاده‌ی access/
           refresh token عادی به‌جای reset_token و برعکس)
        ۳) matches_current_password_of: امضای HMAC وابسته به رمز *فعلی*
           کاربر — یعنی اگه این توکن قبلاً یک‌بار برای عوض کردن رمز
           استفاده شده باشه (یا کاربر از راه دیگه‌ای رمزش عوض شده باشه)،
           دیگه معتبر نیست. این همون یک‌بارمصرف‌بودنیه که معمولاً با ذخیره‌ی
           توکن در دیتابیس پیاده می‌شه؛ اینجا کاملاً stateless انجام شده.
    """

    reset_token = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate_reset_token(self, value):
        try:
            token = PasswordResetToken(value)
        except TokenError:
            raise serializers.ValidationError("توکن بازیابی نامعتبر یا منقضی شده است.")

        user = User.objects.filter(id=token.user_id).first()
        if user is None:
            raise serializers.ValidationError("توکن بازیابی نامعتبر است.")

        if not token.matches_current_password_of(user):
            raise serializers.ValidationError(
                "این توکن بازیابی قبلاً استفاده شده یا دیگر معتبر نیست. لطفاً دوباره درخواست بازیابی رمز بدهید."
            )

        self._user = user
        return value

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError({"new_password2": "رمز عبور جدید و تکرار آن یکسان نیستند."})

        # validate_password باید *بعد* از پیدا شدن self._user صدا زده بشه
        # (validate_reset_token زودتر اجرا می‌شه چون DRF ابتدا validate_<field>
        # هر فیلد و بعد validate کلی رو صدا می‌زنه) تا اعتبارسنج‌های وابسته
        # به کاربر (مثل UserAttributeSimilarityValidator) هم درست کار کنن.
        validate_password(attrs["new_password"], user=self._user)
        return attrs

    def save(self, **kwargs):
        self._user.set_password(self.validated_data["new_password"])
        self._user.save(update_fields=["password"])
        # نیازی به هیچ فراخوانی جداگانه‌ای برای ابطال نشست‌های دیگر نیست:
        # همین که user.password عوض شد، pwd_sig همه‌ی توکن‌های قبلاً
        # صادرشده (روی هر دستگاهی) دیگه با AppJWTAuthentication/
        # AppTokenRefreshSerializer مطابقت نداره و خودکار رد می‌شن.
        return self._user


class ChangePasswordSerializer(serializers.Serializer):
    """
    [SRP]
    فقط عوض کردن رمز برای کاربرِ *لاگین‌شده*. برخلاف فرآیند فراموشی رمز،
    اینجا کاربر از request.user (که IsAuthenticated + JWTAuthentication
    قبلاً احرازش کرده) گرفته می‌شه، نه از ورودی کاربر — یعنی هیچ کاربری
    نمی‌تونه با تغییر یک شناسه توی بدنه‌ی درخواست، رمز شخص دیگه‌ای رو عوض
    کنه (IDOR). context["request"] باید توسط View پاس داده بشه.
    """

    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("رمز عبور فعلی اشتباه است.")
        return value

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError(
                {"new_password2": "رمز عبور جدید و تکرار آن یکسان نیستند."}
            )
        if attrs["old_password"] == attrs["new_password"]:
            raise serializers.ValidationError(
                {"new_password": "رمز عبور جدید نباید با رمز عبور فعلی یکسان باشد."}
            )

        user = self.context["request"].user
        validate_password(attrs["new_password"], user=user)
        return attrs

    def save(self, **kwargs):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save(update_fields=["password"])
        # طبق همون منطق ForgotPasswordConfirmSerializer: نیازی به فراخوانی
        # جداگانه‌ای نیست، ابطال نشست‌های دیگر خودکار (از طریق pwd_sig) است.
        return user


class UserListSerializer(serializers.ModelSerializer):
    """
    [SRP - Single Responsibility Principle]
    فقط مسئول شکل خروجیِ فهرست کاربران برای مدیر ارشد است — نه احراز هویت
    (که مسئولیت IsAdminRole/View است)، نه فیلتر/جست‌وجو (که مسئولیت
    UserListView + DjangoFilterBackend/SearchFilter است).

    [امنیت]
    فیلدهای حساس (password، google_id) عمداً اینجا نیستند. برخلاف
    ModelSerializer با fields="__all__"، لیست فیلدها صریح نوشته شده تا اگر
    فردا فیلد حساس جدیدی به مدل User اضافه شد، به‌طور پیش‌فرض *بیرون* از این
    خروجی بمونه، نه اینکه ناخواسته لو بره.

    support_role_name جدا از support_role (که فقط UUID خامه) نگه داشته شده
    تا فرانت مجبور نباشه برای نمایش ساده‌ی نام نقش پشتیبانی، یک درخواست
    اضافه به SupportRoleListCreateView بزنه.
    """

    support_role_name = serializers.SerializerMethodField()

    def get_support_role_name(self, obj):
        return obj.support_role.name if obj.support_role_id else None

    class Meta:
        model = User
        fields = [
            "id",
            "full_name",
            "username",
            "phone_number",
            "email",
            "user_type",
            "support_role",
            "support_role_name",
            "is_phone_verified",
            "is_active",
            "is_staff",
            "date_joined",
        ]
        read_only_fields = fields


class SupportRoleSerializer(serializers.ModelSerializer):
    """
    [SRP]
    فقط شکل ورودی/خروجی «تعریف یک نقش پشتیبانی» رو مشخص می‌کنه. مثل
    ChangeUserRoleSerializer، تصمیم "کی اجازه داره" مسئولیت این کلاس نیست —
    به IsAdminRole + SupportRoleListCreateView/SupportRoleDetailView واگذار
    شده.

    id و created_at عمداً read_only هستن (سرور می‌سازتشون)؛ is_active رو
    مدیر ارشد هم موقع ساخت هم موقع ویرایش می‌تونه ست کنه (پیش‌فرض True) —
    غیرفعال کردن، جایگزین امنِ حذف واقعیه (به‌خاطر on_delete=PROTECT روی
    User.support_role، توضیح کامل در accounts/models.py::SupportRole).
    """

    class Meta:
        model = SupportRole
        fields = ["id", "name", "description", "is_active", "created_at"]
        read_only_fields = ["id", "created_at"]
