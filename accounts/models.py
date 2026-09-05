import uuid
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

# اعتبارسنجی شماره موبایل ایران
phone_regex = RegexValidator(
    regex=r"^09\d{9}$",
    message=_("شماره موبایل باید با ۰۹ شروع شده و ۱۱ رقم باشد."),
)

# اعتبارسنجی نام کاربری: دقیقاً قانون اینستاگرام —
# فقط حروف انگلیسی، عدد، نقطه (.) و آندرلاین (_)؛ حداقل ۳ و حداکثر ۳۰ کاراکتر؛
# نباید با نقطه شروع/پایان یابد یا دو نقطه پشت‌سرهم داشته باشد.
username_regex = RegexValidator(
    regex=r"^(?!.*\.\.)(?!\.)[A-Za-z0-9._]{3,30}(?<!\.)$",
    message=_(
        "نام کاربری فقط می‌تواند شامل حروف انگلیسی، عدد، نقطه (.) و آندرلاین (_) باشد، "
        "بین ۳ تا ۳۰ کاراکتر باشد و نباید با نقطه شروع/پایان یابد یا دو نقطه پشت‌سرهم داشته باشد."
    ),
)


class SupportRole(models.Model):
    """
    [OCP - Open/Closed Principle]
    قبلاً زیرنوع‌های پشتیبانی (فنی/مالی/عمومی) به‌صورت TextChoices ثابت در
    کد تعریف شده بودند — یعنی هر نقش پشتیبانی جدید نیاز به تغییر کد،
    migration و دیپلوی مجدد داشت. حالا مدیر ارشد خودش از طریق API
    (accounts/api/v1/views.py::SupportRoleListCreateView/SupportRoleDetailView)
    هر نقش پشتیبانی دلخواهی رو تعریف/ویرایش/غیرفعال می‌کنه، بدون این‌که یک
    خط از کد پروژه عوض بشه یا release جدیدی لازم باشه.

    [DIP]
    User.support_role به این مدل (abstraction) وابسته‌ست، نه به یک لیست
    ثابت رشته‌ای؛ یعنی «چه نقش‌های پشتیبانی‌ای وجود دارن» یک تصمیم داده‌ایه
    که در دیتابیس زندگی می‌کنه، نه در کد.

    چرا is_active به‌جای حذف واقعی:
    چون User.support_role با on_delete=PROTECT تعریف شده، نقشی که به یک یا
    چند کاربر اختصاص داده شده اصلاً قابل حذف نیست (SupportRoleDetailView
    این حالت رو با یک پیام فارسی روشن رد می‌کنه، نه یک خطای ۵۰۰). راه درست
    کنار گذاشتن یک نقش قدیمی، غیرفعال کردنشه، نه حذفش — این‌طوری سابقه‌ی
    کاربرهایی که قبلاً این نقش رو داشتن هم خراب نمی‌شه.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name=_("شناسه یکتا"),
    )
    name = models.CharField(
        max_length=50,
        unique=True,
        verbose_name=_("عنوان نقش پشتیبانی"),
        help_text=_("مثلاً «فنی»، «مالی»، «پشتیبانی محتوا»."),
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_("توضیحات"),
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name=_("فعال"),
        help_text=_("نقش‌های غیرفعال دیگر برای اختصاص به کاربر جدید قابل انتخاب نیستند."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("تاریخ ایجاد"),
    )

    class Meta:
        db_table = "accounts_support_role"
        verbose_name = _("نقش پشتیبانی")
        verbose_name_plural = _("نقش‌های پشتیبانی")
        ordering = ["name"]

    def __str__(self):
        return self.name


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
        """
        [OCP - Open/Closed Principle]
        این فهرست، سطح اول نقش‌های بیزینسی سایت رو مشخص می‌کنه. اضافه کردن
        یک نقش کاملاً جدید (مثلاً «همکار محتوا») یعنی فقط یک خط اینجا اضافه
        می‌شه؛ چیزی توی permissions.py یا serializers.py که به مقدار دقیق
        این enum وابسته نیست، نیازی به تغییر نداره.

        نکته درباره‌ی «پشتیبانی»: زیرنوع دقیق پشتیبانی (فنی، مالی، عمومی و
        هر مورد دیگه‌ای که مدیر ارشد بعداً تعریف کنه) دیگه توی همین enum
        نیست — چون این‌ها می‌تونن پویا و توسط خودِ مدیر ارشد از طریق API
        تعریف بشن، به یک مدل جدا (SupportRole، بالای همین فایل) منتقل شدن
        و با یک ForeignKey (پایین‌تر: support_role) به کاربر وصل می‌شن.
        SUPPORT اینجا فقط سطح اول (نقش) رو مشخص می‌کنه.
        """

        STUDENT = "student", _("دانش‌آموز")
        INSTRUCTOR = "instructor", _("مدرس")
        TEACHING_ASSISTANT = "teaching_assistant", _("کمک مدرس")
        ADMIN = "admin", _("مدیر ارشد")
        SUPPORT = "support", _("پشتیبانی")

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
        validators=[username_regex],
        verbose_name=_("نام کاربری"),
    )
    phone_number = models.CharField(
        max_length=11,
        unique=True,
        db_index=True,
        null=True,
        blank=True,
        validators=[phone_regex],
        verbose_name=_("شماره موبایل"),
        help_text=_(
            "برای کاربرانی که فقط از طریق گوگل ثبت‌نام کرده‌اند، تا زمان افزودن و "
            "تایید شماره موبایل خالی می‌ماند."
        ),
    )
    email = models.EmailField(
        unique=True,
        db_index=True,
        verbose_name=_("پست الکترونیکی"),
    )
    google_id = models.CharField(
        max_length=255,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("شناسه گوگل"),
        help_text=_("مقدار sub برگشتی از Google ID Token؛ برای اتصال ورود با گوگل."),
    )

    user_type = models.CharField(
        max_length=20,
        choices=UserType.choices,
        default=UserType.STUDENT,
        verbose_name=_("نقش کاربر"),
    )
    support_role = models.ForeignKey(
        SupportRole,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="users",
        verbose_name=_("نقش پشتیبانی"),
        help_text=_(
            "فقط برای کاربرانی با نقش «پشتیبانی» پر می‌شود؛ برای بقیه‌ی نقش‌ها "
            "باید خالی بماند. مقادیر مجاز از طریق API مدیریت نقش‌های پشتیبانی "
            "(فقط مدیر ارشد) تعریف/مدیریت می‌شوند، نه در کد."
        ),
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

    def clean(self):
        """
        [SRP]
        فقط یک قانون سازگاری داده رو تضمین می‌کنه: support_role فقط برای
        نقش SUPPORT معنا داره. این چک هم توی فرم‌های ادمین جنگو (که خودکار
        full_clean صدا می‌زنن) و هم هرجای دیگه‌ای که صریحاً full_clean/clean
        صدا زده بشه اجرا می‌شه؛ سریالایزرها (ChangeUserRoleSerializer) هم
        جدا و صریح همین قانون رو چک می‌کنن چون DRF به‌طور پیش‌فرض
        Model.clean رو صدا نمی‌زنه.
        """
        super().clean()
        if self.user_type == self.UserType.SUPPORT and not self.support_role_id:
            raise ValidationError(
                {"support_role": _("برای نقش «پشتیبانی»، انتخاب نقش پشتیبانی الزامی است.")}
            )
        if self.user_type != self.UserType.SUPPORT and self.support_role_id:
            raise ValidationError(
                {"support_role": _("این فیلد فقط برای نقش «پشتیبانی» قابل استفاده است.")}
            )

    def __str__(self):
        display_name = self.full_name or self.username
        identifier = self.phone_number or self.email
        return f"{display_name} ({identifier})"