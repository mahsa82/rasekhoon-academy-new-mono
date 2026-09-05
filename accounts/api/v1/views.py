import logging

from django.contrib.auth import get_user_model
from django.db.models.deletion import ProtectedError

# from django.contrib.auth.models import update_last_login  # فقط برای GoogleLoginView (کامنت‌شده) لازمه
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from accounts.api.v1.cookies import (
    REFRESH_TOKEN_COOKIE_NAME,
    clear_refresh_cookie,
    set_refresh_cookie,
)
from accounts.api.v1.permissions import IsAdminRole
from accounts.api.v1.serializers import (
    AppTokenRefreshSerializer,
    ChangePasswordSerializer,
    ChangeUserRoleSerializer,
    ForgotPasswordConfirmSerializer,
    ForgotPasswordRequestSerializer,
    ForgotPasswordVerifySerializer,
    # GoogleLoginSerializer,  # ورود با گوگل فعلاً غیرفعاله — پایین‌تر توضیح داده شده
    LoginSerializer,
    LogoutSerializer,
    RegisterSerializer,
    SupportRoleSerializer,
    UserListSerializer,
    VerifyOTPSerializer,
)
from accounts.models import SupportRole
from accounts.services.tokens import AppRefreshToken, PasswordResetToken

logger = logging.getLogger(__name__)

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    """
    [SRP]
    این View فقط مسئول ترجمه‌ی HTTP request/response ثبت‌نامه؛
    منطق واقعی (ساخت کاربر، ارسال OTP) در سریالایزر/سرویس‌هاست، نه اینجا.
    """

    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]  # جلوگیری از spam ثبت‌نام از یک IP


class VerifyOTPView(APIView):
    """
    اینجا (بر خلاف Login) از simplejwt ارث‌بری نمی‌کنیم چون verify-otp یه
    "لاگین" استاندارد نیست (ورودیش username/password نیست، بلکه phone+code)،
    پس صدور دستی توکن با AppRefreshToken.for_user اینجا منطقی‌تره.

    [DRY]
    از AppRefreshToken (accounts/services/tokens.py) استفاده می‌کنیم، نه
    RefreshToken خام simplejwt — همون کلاسی که LoginSerializer هم از طریق
    token_class استفاده می‌کنه. این‌طوری claim نقش کاربر توی توکن‌های
    verify-otp هم دقیقاً مثل لاگین معمولی قرار می‌گیره، بدون این‌که منطق
    اضافه‌کردن claim دو جای مختلف نوشته/تکرار بشه.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = AppRefreshToken.for_user(user)
        logger.info(
            "ثبت‌نام/verify-otp موفق: user_id=%s username=%s role=%s", user.id, user.username, user.user_type
        )
        # refresh token هرگز در بدنه‌ی JSON برنمی‌گرده — فقط در کوکی httpOnly
        # (accounts/api/v1/cookies.py) قرار می‌گیره تا با جاوااسکریپت قابل
        # خوندن نباشه. access token در پاسخ می‌مونه تا فرانت در حافظه‌ی
        # موقت (نه localStorage) نگهش داره.
        response = Response(
            {
                "access": str(refresh.access_token),
                "user_id": str(user.id),
                "username": user.username,
                "full_name": user.full_name,
                "role": user.user_type,
                "support_role_id": str(user.support_role_id) if user.support_role_id else None,
                "support_role": user.support_role.name if user.support_role_id else None,
            },
            status=status.HTTP_200_OK,
        )
        set_refresh_cookie(response, str(refresh))
        return response


class LoginView(TokenObtainPairView):
    """
    [LSP - Liskov Substitution Principle]
    از TokenObtainPairView ارث‌بری می‌کنیم (نه APIView خام) — یعنی این View
    دقیقاً همون قرارداد ویوی استاندارد simplejwt رو داره. فقط serializer_class
    رو با نسخه سفارشی خودمون (LoginSerializer) عوض کردیم که identifier
    دوگانه (ایمیل/موبایل) رو پشتیبانی می‌کنه.

    [OCP]
    تنها بخشی که override شده post() است — نه برای بازنویسی منطق لاگین
    (که کامل در LoginSerializer.validate می‌مونه)، بلکه فقط برای اینکه
    refresh token به‌جای بدنه‌ی JSON، در کوکی httpOnly گذاشته بشه (نگاه
    کنید به accounts/api/v1/cookies.py).
    """

    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]  # جلوگیری از brute-force روی رمز عبور

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = dict(serializer.validated_data)
        refresh_token = data.pop("refresh")

        response = Response(data, status=status.HTTP_200_OK)
        set_refresh_cookie(response, refresh_token)
        return response


# ورود با گوگل فعلاً غیرفعاله (تا وقتی GOOGLE_OAUTH_CLIENT_ID توی .env تنظیم
# بشه). کد کامل و تست‌شده‌ست — سرویس accounts/services/google_auth.py و
# GoogleLoginSerializer دست‌نخورده باقی موندن. برای فعال‌سازی: این کلاس رو از
# کامنت دربیارید، importِ GoogleLoginSerializer رو بالا از کامنت دربیارید، و
# مسیر login/google/ رو در accounts/api/v1/urls.py هم از کامنت دربیارید.
#
# class GoogleLoginView(APIView):
#     """
#     ورود/ثبت‌نام با گوگل. فرانت (وب/موبایل) با Google Sign-In یک id_token
#     می‌گیره و همون رو اینجا POST می‌کنه؛ خودمون هیچ redirect یا session
#     سمت گوگل نداریم — دقیقاً هم‌خانواده با بقیه‌ی این API که کاملاً JWT-محوره.
#
#     طبق مشخصات پروژه («کاربر خارج نشه مگر خودش لاگ‌اوت کنه یا از گوگل خارج
#     شده باشه»)، اینجا هم مثل VerifyOTPView یک جفت access/refresh استاندارد
#     صادر می‌شه — یعنی نشست همون قانون ۳۶۵ روزه‌ی SIMPLE_JWT رو داره.
#     """
#
#     permission_classes = [AllowAny]
#     throttle_classes = [AnonRateThrottle]
#
#     def post(self, request):
#         serializer = GoogleLoginSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data["user"]
#         created = serializer.validated_data["created"]
#
#         refresh = AppRefreshToken.for_user(user)
#         update_last_login(None, user)
#
#         return Response(
#             {
#                 "access": str(refresh.access_token),
#                 "refresh": str(refresh),
#                 "created": created,
#             },
#             status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
#         )


class LogoutView(APIView):
    """
    خروج دستی کاربر: refresh token رو (که دیگه در بدنه‌ی درخواست فرستاده
    نمی‌شه، بلکه از همون کوکی httpOnly که در لاگین/verify-otp ست شده خونده
    می‌شه) باطل می‌کنه (در کش، نه دیتابیس — نگاه کنید به
    accounts.services.tokens.revoke_refresh_token) تا دیگه قابل تمدید
    نباشه، و در پایان خودِ کوکی رو هم از مرورگر پاک می‌کنه. این تنها راهیه
    که طبق مشخصات پروژه نشست ۳۶۵ روزه‌ی کاربر زودتر از موعد باطل می‌شه
    (وگرنه کاربر لاگین‌شده می‌مونه).
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get(REFRESH_TOKEN_COOKIE_NAME)
        serializer = LogoutSerializer(data={"refresh": refresh_token} if refresh_token else {})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        response = Response(status=status.HTTP_205_RESET_CONTENT)
        clear_refresh_cookie(response)
        return response


class AppTokenRefreshView(TokenRefreshView):
    """
    [OCP]
    جایگزین مستقیم TokenRefreshView استاندارد simplejwt در urls.py.
    دو تفاوت با نسخه‌ی پیش‌فرض:
        ۱) serializer_class عوض شده تا قبل از صدور access token جدید،
           لاگ‌اوت‌شدن و تغییر رمز عبور هم چک بشن
           (accounts.api.v1.serializers.AppTokenRefreshSerializer).
        ۲) refresh token دیگه از بدنه‌ی درخواست خونده نمی‌شه، بلکه از کوکی
           httpOnly گرفته می‌شه؛ و چون ROTATE_REFRESH_TOKENS=True است،
           refresh token جدیدِ صادرشده هم به‌جای برگشتن در بدنه، دوباره در
           همون کوکی جایگزین می‌شه — یعنی فرانت هیچ‌وقت این توکن رو
           نمی‌بینه، نه در ورودی نه در خروجی.
    """

    serializer_class = AppTokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get(REFRESH_TOKEN_COOKIE_NAME)
        if not refresh_token:
            return Response(
                {"detail": "نشست یافت نشد. لطفاً دوباره وارد شوید."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        serializer = self.get_serializer(data={"refresh": refresh_token})
        serializer.is_valid(raise_exception=True)
        data = dict(serializer.validated_data)

        new_refresh = data.pop("refresh", None)
        response = Response(data, status=status.HTTP_200_OK)
        if new_refresh:
            set_refresh_cookie(response, new_refresh)
        return response


class ChangeUserRoleView(generics.UpdateAPIView):
    """
    [OCP - Open/Closed Principle]
    اگه فردا قانون جدیدی برای تغییر نقش لازم شد (مثلاً "فقط ADMIN اصلی، نه هر
    ADMIN ای، بتونه SUPERVISOR جدید بسازه")، کافیه یه permission class دیگه
    بسازیم و به لیست permission_classes اضافه کنیم — این View و سریالایزرش
    عوض نمی‌شن.

    [DIP]
    این View به abstraction های IsAdminRole و ChangeUserRoleSerializer وابسته‌ست،
    نه به پیاده‌سازی خام "if user.user_type == 'admin'".
    """

    queryset = User.objects.all()
    serializer_class = ChangeUserRoleSerializer
    permission_classes = [IsAuthenticated, IsAdminRole]
    lookup_field = "id"
    lookup_url_kwarg = "user_id"


class ForgotPasswordRequestView(APIView):
    """
    قدم ۱ از ۳ فراموشی رمز عبور: با موبایل/ایمیل، یک کد OTP پیامکی
    (purpose="password_reset", کاملاً مستقل از کد ثبت‌نام) درخواست می‌کنه.

    [امنیت]
    پاسخ همیشه ۲۰۰ با یک پیام عمومیه، صرف‌نظر از اینکه identifier واقعاً
    به کاربری تعلق داره یا نه، آن کاربر موبایل تاییدشده داره یا نه، یا
    throttle شده یا نه — منطق واقعی توی ForgotPasswordRequestSerializer.save
    به‌صورت «بی‌سروصدا موفق/ناموفق» انجام می‌شه، نه اینجا. این یعنی این
    اندپوینت نمی‌تونه برای user enumeration استفاده بشه.

    throttle_scope="password_security" مانع اسپم پیامکی روی یک شماره/IP
    می‌شه (جدا از AnonRateThrottle عمومی که برای ثبت‌نام/لاگینه).
    """

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_security"

    def post(self, request):
        serializer = ForgotPasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": "در صورت وجود حساب کاربری با این مشخصات، کد بازیابی برای آن پیامک شد."},
            status=status.HTTP_200_OK,
        )


class ForgotPasswordVerifyView(APIView):
    """
    قدم ۲ از ۳: کد پیامکی رو تایید می‌کنه و در ازاش یک PasswordResetToken
    (JWT تک‌منظوره، عمر کوتاه، بدون ذخیره در دیتابیس) برمی‌گردونه که فقط
    برای قدم ۳ (ثبت رمز جدید) معتبره — نه برای هیچ اندپوینت دیگه‌ای.
    """

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_security"

    def post(self, request):
        serializer = ForgotPasswordVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        reset_token = PasswordResetToken.for_user(user)
        return Response({"reset_token": str(reset_token)}, status=status.HTTP_200_OK)


class ForgotPasswordConfirmView(APIView):
    """
    قدم ۳ از ۳ و پایانی: reset_token قدم قبل + رمز عبور جدید رو می‌گیره،
    اعتبارسنجی توکن و ثبت رمز جدید در ForgotPasswordConfirmSerializer انجام
    می‌شه (امضا/انقضا/token_type/یک‌بارمصرف‌بودن، همه اونجا چک شدن).
    """

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_security"

    def post(self, request):
        serializer = ForgotPasswordConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "رمز عبور با موفقیت بازیابی شد."}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    """
    تغییر رمز عبور برای کاربرِ لاگین‌شده (نیاز به access token معتبر داره).
    برخلاف مسیر فراموشی رمز، اینجا کاربر رمز فعلی‌اش رو می‌دونه، پس نیازی
    به OTP نیست — فقط رمز فعلی به‌عنوان تایید هویت اضافه چک می‌شه
    (ChangePasswordSerializer.validate_old_password).
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "password_security"

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "رمز عبور با موفقیت تغییر کرد."}, status=status.HTTP_200_OK)


class UserListView(generics.ListAPIView):
    """
    فهرست تمام کاربران ثبت‌نام‌شده — فقط برای مدیر ارشد (یا سوپریوزر).

    [SRP]
    این View فقط ترجمه‌ی HTTP request/response رو انجام می‌ده؛ شکل خروجی با
    UserListSerializer و قانون دسترسی با IsAdminRole مشخص شده، نه اینجا.

    [DIP]
    وابسته به abstraction های IsAdminRole و UserListSerializer است، نه به
    پیاده‌سازی خام "if user.user_type == 'admin'" یا لیست دستی فیلدها.

    صفحه‌بندی، همون PageNumberPagination سراسری پروژه (PAGE_SIZE=12 در
    settings.py) رو به ارث می‌بره — نیازی به override نیست.

    فیلتر/جست‌وجو/مرتب‌سازی (مثلاً «فقط دانش‌آموزهای تاییدنشده» یا «جست‌وجوی
    نام/موبایل/ایمیل») روی یک پایگاه‌داده‌ی بزرگ ضروریه؛ چون سایت طبق گفته‌ی
    شما بزرگه و تعداد کاربرها می‌تونه زیاد باشه، دانلود کل لیست بدون فیلتر
    عملاً غیرکاربردیه:
        - filterset_fields: فیلتر دقیق روی نقش/زیرنوع پشتیبانی/وضعیت‌ها
          (مثال: ?user_type=student&is_active=true)
        - search_fields: جست‌وجوی عبارت روی نام/یوزرنیم/موبایل/ایمیل
          (مثال: ?search=0912)
        - ordering_fields: مرتب‌سازی (مثال: ?ordering=-date_joined)
    """

    queryset = User.objects.all().select_related("support_role").order_by("-date_joined")
    serializer_class = UserListSerializer
    permission_classes = [IsAuthenticated, IsAdminRole]

    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["user_type", "support_role", "is_active", "is_phone_verified", "is_staff"]
    search_fields = ["full_name", "username", "phone_number", "email"]
    ordering_fields = ["date_joined", "full_name", "username"]


class SupportRoleListCreateView(generics.ListCreateAPIView):
    """
    فهرست نقش‌های پشتیبانی موجود + تعریف نقش پشتیبانی جدید — فقط مدیر
    ارشد. این دقیقاً همون «FK قابل تعریف توسط خودِ مدیر ارشد» است: قبلاً
    زیرنوع‌های پشتیبانی (فنی/مالی/عمومی) در کد ثابت بودن، الان مدیر ارشد
    هر نقشی که لازم داره رو از همین‌جا اضافه می‌کنه و بلافاصله در
    ChangeUserRoleView (به‌عنوان support_role_id) قابل استفاده‌ست — بدون
    نیاز به تغییر کد یا دیپلوی مجدد.

    نقش‌های غیرفعال (is_active=False) هم اینجا لیست می‌شن (تا مدیر ارشد
    بتونه دوباره فعالشون کنه)؛ فقط از queryset انتخاب support_role_id در
    ChangeUserRoleSerializer حذف شدن.
    """

    queryset = SupportRole.objects.all()
    serializer_class = SupportRoleSerializer
    permission_classes = [IsAuthenticated, IsAdminRole]


class SupportRoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    مشاهده/ویرایش/حذف یک نقش پشتیبانی مشخص — فقط مدیر ارشد.

    [امنیت/یکپارچگی داده]
    چون User.support_role با on_delete=PROTECT تعریف شده، حذف نقشی که به
    یک یا چند کاربر اختصاص داده شده، توسط خودِ دیتابیس رد می‌شه
    (ProtectedError). این‌جا اون خطا رو می‌گیریم و به‌جای یک 500 ناگهانی،
    یک ۴۰۹ با توضیح فارسی روشن برمی‌گردونیم که راه‌حل درست (غیرفعال‌کردن
    به‌جای حذف) رو هم بگه.
    """

    queryset = SupportRole.objects.all()
    serializer_class = SupportRoleSerializer
    permission_classes = [IsAuthenticated, IsAdminRole]
    lookup_field = "id"
    lookup_url_kwarg = "role_id"

    def destroy(self, request, *args, **kwargs):
        try:
            return super().destroy(request, *args, **kwargs)
        except ProtectedError:
            return Response(
                {
                    "detail": (
                        "این نقش هم‌اکنون به یک یا چند کاربر اختصاص داده شده و قابل حذف نیست. "
                        "به‌جای حذف، آن را غیرفعال کنید (is_active=false)."
                    )
                },
                status=status.HTTP_409_CONFLICT,
            )