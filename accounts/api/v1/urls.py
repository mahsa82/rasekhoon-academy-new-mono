from django.urls import path

from accounts.api.v1.views import ChangeUserRoleView, LoginView, RegisterView, VerifyOTPView

app_name = "accounts"

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
    path("login/", LoginView.as_view(), name="login"),
    path("users/<uuid:user_id>/role/", ChangeUserRoleView.as_view(), name="change-user-role"),
]