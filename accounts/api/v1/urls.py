from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from accounts.api.v1.views import (
    ChangeUserRoleView,
    # GoogleLoginView,  # ورود با گوگل فعلاً غیرفعاله — پایین‌تر توضیح داده شده
    LoginView,
    LogoutView,
    RegisterView,
    VerifyOTPView,
)

app_name = "accounts"

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
    path("login/", LoginView.as_view(), name="login"),
    # ورود با گوگل: فعلاً کامنته چون GOOGLE_OAUTH_CLIENT_ID هنوز تنظیم نشده.
    # کد کامل (سرویس/سریالایزر/ویو) دست‌نخورده باقی مونده؛ هر وقت Client ID
    # رو از Google Cloud Console گرفتید، همین یک خط و importهای بالا/در
    # serializers.py و views.py رو از کامنت دربیارید تا فعال بشه.
    # path("login/google/", GoogleLoginView.as_view(), name="login-google"),
    # access token فقط ۵ دقیقه عمر داره؛ فرانت باید قبل از انقضا (یا وقتی
    # ۴۰۱ گرفت) با همین endpoint یه access+refresh جدید بگیره. چون
    # ROTATE_REFRESH_TOKENS=True است، هر بار refresh جدیدی هم برمی‌گرده —
    # دقیقاً همون «تا وقتی خودش خارج نشه لاگین بمونه» که مشخصات پروژه خواسته.
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("users/<uuid:user_id>/role/", ChangeUserRoleView.as_view(), name="change-user-role"),
]
