from django.urls import path

from accounts.api.v1.views import (
    AppTokenRefreshView,
    ChangePasswordView,
    ChangeUserRoleView,
    ForgotPasswordConfirmView,
    ForgotPasswordRequestView,
    ForgotPasswordVerifyView,
    # GoogleLoginView,  # ورود با گوگل فعلاً غیرفعاله — پایین‌تر توضیح داده شده
    LoginView,
    LogoutView,
    RegisterView,
    SupportRoleDetailView,
    SupportRoleListCreateView,
    UserListView,
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
    path("token/refresh/", AppTokenRefreshView.as_view(), name="token-refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    # فهرست کاربران ثبت‌نام‌شده — فقط مدیر ارشد؛ فیلتر/جست‌وجو/مرتب‌سازی رو
    # UserListView (accounts/api/v1/views.py) مستند کرده.
    path("users/", UserListView.as_view(), name="user-list"),
    path("users/<uuid:user_id>/role/", ChangeUserRoleView.as_view(), name="change-user-role"),

    # مدیریت نقش‌های پشتیبانی (فنی/مالی/هر نقش دیگری) — فقط مدیر ارشد؛
    # همون شناسه‌هایی (id) که از این دو اندپوینت می‌گیرید، به‌عنوان
    # support_role_id در change-user-role بالا قابل استفاده‌ست.
    path("support-roles/", SupportRoleListCreateView.as_view(), name="support-role-list"),
    path("support-roles/<uuid:role_id>/", SupportRoleDetailView.as_view(), name="support-role-detail"),

    # فراموشی رمز عبور — فرآیند سه‌مرحله‌ای مبتنی بر OTP پیامکی + JWT تک‌منظوره:
    # ۱) درخواست کد  ۲) تایید کد و گرفتن reset_token  ۳) ثبت رمز جدید با reset_token
    path("password/forgot/request/", ForgotPasswordRequestView.as_view(), name="forgot-password-request"),
    path("password/forgot/verify/", ForgotPasswordVerifyView.as_view(), name="forgot-password-verify"),
    path("password/forgot/confirm/", ForgotPasswordConfirmView.as_view(), name="forgot-password-confirm"),

    # تغییر رمز عبور برای کاربر لاگین‌شده (نیاز به access token معتبر)
    path("password/change/", ChangePasswordView.as_view(), name="change-password"),
]
