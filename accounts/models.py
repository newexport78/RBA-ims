from django.contrib.auth.models import AbstractUser
from django.db import models


class Role(models.TextChoices):
    SUPERADMIN = 'superadmin', 'Superadmin'
    TWOIC = 'twoic', '2IC'
    ADMIN = 'admin', 'Admin'
    USER = 'user', 'User'
    EMPLOYEE = 'employee', 'Employee'


class User(AbstractUser):
    """Custom user with role. No public signup; accounts created by superadmin or 2IC."""
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.USER,
    )
    is_active = models.BooleanField(default=True)
    email = models.EmailField(unique=True)
    force_password_change = models.BooleanField(
        default=False,
        help_text='If set, user must set a new password on next login (after OTP).',
    )
    created_by = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='created_users',
        help_text='Admin who created this user (null if created by superadmin).',
    )
    wing = models.CharField(max_length=100, blank=True, help_text='Wing or department.')
    phone = models.CharField(max_length=32, blank=True, help_text='Phone number.')
    date_of_birth = models.DateField(null=True, blank=True, help_text='Date of birth.')
    employee_number = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        blank=True,
        help_text='Employee number; used as username for employee login.',
    )
    is_approved = models.BooleanField(
        default=True,
        help_text='If False, user cannot log in until a superadmin approves (for admin-created users).',
    )

    class Meta:
        db_table = 'accounts_user'
        indexes = [
            models.Index(fields=['role']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.get_full_name() or self.username} ({self.get_role_display()})"

    @property
    def is_superadmin(self):
        return self.role == Role.SUPERADMIN

    @property
    def is_admin_role(self):
        # In this setup, only SUPERADMIN is considered an admin role.
        return self.role == Role.SUPERADMIN


class OTP(models.Model):
    """One-time password for login. Sent to user email; short expiry."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    code = models.CharField(max_length=8)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'accounts_otp'
        ordering = ['-created_at']

    def __str__(self):
        return f"OTP for {self.user.username}"

    @property
    def is_valid(self):
        from django.utils import timezone
        return not self.used_at and timezone.now() < self.expires_at


class DeviceStatus(models.TextChoices):
    PENDING = 'pending', 'Pending'
    APPROVED = 'approved', 'Approved'
    BLOCKED = 'blocked', 'Blocked'


class Device(models.Model):
    """Track device used at login (after OTP). One user can have multiple devices."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    device_id = models.CharField(max_length=64, blank=True, help_text='Fingerprint or session-derived id')
    user_agent = models.CharField(max_length=512, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    status = models.CharField(
        max_length=20,
        choices=DeviceStatus.choices,
        default=DeviceStatus.PENDING,
    )

    class Meta:
        db_table = 'accounts_device'
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['user', '-last_seen']),
        ]

    def __str__(self):
        return f'{self.user.username} @ {self.ip_address or "?"} ({self.last_seen.date()})'


class AuditAction(models.TextChoices):
    LOGIN_SUCCESS = 'LOGIN_SUCCESS', 'Login success'
    LOGIN_FAILED = 'LOGIN_FAILED', 'Login failed'
    NEW_DEVICE_LOGIN = 'NEW_DEVICE_LOGIN', 'New device login (employee)'
    USER_APPROVED = 'USER_APPROVED', 'User approved (can log in)'
    ORDER_CREATED = 'ORDER_CREATED', 'Order created'
    ORDER_VIEWED = 'ORDER_VIEWED', 'Order viewed'
    ORDER_DOWNLOADED = 'ORDER_DOWNLOADED', 'Order PDF downloaded'
    PROGRESS_UPLOADED = 'PROGRESS_UPLOADED', 'Progress uploaded'
    USER_DOCUMENT_UPLOADED = 'USER_DOCUMENT_UPLOADED', 'User document uploaded'
    ORDER_DELETED = 'ORDER_DELETED', 'Order deleted'
    ACCOUNT_DELETED_FAILED_LOGINS = 'ACCOUNT_DELETED_FAILED_LOGINS', 'Account deleted (3 failed logins)'
    PROFILE_UPDATED = 'PROFILE_UPDATED', 'Profile updated'


class AuditEvent(models.Model):
    """Immutable audit trail: who did what, when, from where."""
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_events',
    )
    action = models.CharField(max_length=64, choices=AuditAction.choices)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, help_text='JSON or free text: order id, etc.')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)

    class Meta:
        db_table = 'accounts_auditevent'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['action']),
        ]

    def __str__(self):
        who = self.user.username if self.user else '—'
        return f'{self.action} by {who} at {self.timestamp}'


class AppSetting(models.Model):
    """Key-value settings (Phase 6). Superadmin can change OTP expiry, session timeout, password rules."""
    key = models.CharField(max_length=64, unique=True, db_index=True)
    value = models.TextField(blank=True)

    class Meta:
        db_table = 'accounts_appsetting'

    def __str__(self):
        return f'{self.key}={self.value}'
