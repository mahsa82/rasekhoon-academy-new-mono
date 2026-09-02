from django.contrib.auth import get_user_model
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from accounts.api.v1.permissions import IsAdminRole
from accounts.api.v1.serializers import (
    ChangeUserRoleSerializer,
    LoginSerializer,
    RegisterSerializer,
    VerifyOTPSerializer,
)

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
    پس صدور دستی توکن با RefreshToken.for_user اینجا منطقی‌تره.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)
        return Response(
            {"access": str(refresh.access_token), "refresh": str(refresh)},
            status=status.HTTP_200_OK,
        )


class LoginView(TokenObtainPairView):
    """
    [LSP - Liskov Substitution Principle]
    از TokenObtainPairView ارث‌بری می‌کنیم (نه APIView خام) — یعنی این View
    دقیقاً همون قرارداد ویوی استاندارد simplejwt رو داره. فقط serializer_class
    رو با نسخه سفارشی خودمون (LoginSerializer) عوض کردیم که identifier
    دوگانه (ایمیل/موبایل) رو پشتیبانی می‌کنه. کل منطق HTTP اینجا از فریم‌ورک
    میاد، دوباره‌نویسی نشده.
    """

    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]  # جلوگیری از brute-force روی رمز عبور


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