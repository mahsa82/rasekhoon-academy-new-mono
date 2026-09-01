import uuid
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

# اعتبارسنجی شماره موبایل ایران
phone_regex = RegexValidator(
    regex=r"^09\d{9}$",
    message=_("شماره موبایل باید با ۰۹ شروع شده و ۱۱ رقم باشد."),
)


class UserManager(BaseUserManager):
    """
    منیجر سفارشی برای مدل کاربر.
    """

    def create_user(self, phone_number, email, username, full_name=None, password=None, **extra_fields):
        if not phone_number:
            raise ValueError(_("شماره موبایل الزامی است"))
        if not email:
            raise ValueError(_("ایمیل الزامی است"))
        if not username:
            raise ValueError(_("نام کاربری الزامی است"))

        email = self.normalize_email(email)
        user = self.model(
            phone_number=phone_number,
            email=email,
            username=username,
            full_name=full_name or "",
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, email, username, full_name=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_phone_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("سوپریوزر باید is_staff=True داشته باشد"))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("سوپریوزر باید is_superuser=True داشته باشد"))

        return self.create_user(
            phone_number=phone_number,
            email=email,
            username=username,
            full_name=full_name,
            password=password,
            **extra_fields,
        )


class User(AbstractBaseUser, PermissionsMixin):
    """
    مدل کاربر سفارشی جایگزین مدل پیش‌فرض جنگو.
    """

    class UserType(models.TextChoices):
        STUDENT = "student", _("دانش‌آموز")
        INSTRUCTOR = "instructor", _("مدرس")
        ADMIN = "admin", _("مدیر ارشد")
        SUPERVISOR = "supervisor", _("سوپروایزر")

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name=_("شناسه یکتا"),
    )

    full_name = models.CharField(
        max_length=150,
        blank=True,
        verbose_name=_("نام و نام خانوادگی"),
    )
    username = models.CharField(
        max_length=30,
        unique=True,
        db_index=True,
        verbose_name=_("نام کاربری"),
    )
    phone_number = models.CharField(
        max_length=11,
        unique=True,
        db_index=True,
        validators=[phone_regex],
        verbose_name=_("شماره موبایل"),
    )
    email = models.EmailField(
        unique=True,
        db_index=True,
        verbose_name=_("پست الکترونیکی"),
    )

    user_type = models.CharField(
        max_length=20,
        choices=UserType.choices,
        default=UserType.STUDENT,
        verbose_name=_("نقش کاربر"),
    )

    is_phone_verified = models.BooleanField(
        default=False,
        verbose_name=_("تایید شماره موبایل"),
        help_text=_("مشخص می‌کند که آیا شماره موبایل کاربر با OTP تایید شده است یا خیر."),
    )
    is_active = models.BooleanField(
        default=False,
        verbose_name=_("وضعیت فعال"),
        help_text=_("مشخص می‌کند که آیا این کاربر اجازه ورود به سیستم را دارد یا خیر."),
    )
    is_staff = models.BooleanField(
        default=False,
        verbose_name=_("دسترسی به پنل مدیریت"),
        help_text=_("مشخص می‌کند که آیا کاربر می‌تواند وارد پنل مدیریت (Admin) شود یا خیر."),
    )

    date_joined = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("تاریخ عضویت"),
    )

    objects = UserManager()

    USERNAME_FIELD = "phone_number"
    REQUIRED_FIELDS = ["email", "username", "full_name"]

    class Meta:
        db_table = "accounts_user"
        verbose_name = _("کاربر")
        verbose_name_plural = _("کاربران")

    def __str__(self):
        display_name = self.full_name or self.username
        return f"{display_name} ({self.phone_number})"