"""Account services: OTP generation and email sending."""
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .models import OTP, User
from .settings_app import get_setting


def create_otp_for_user(user: User) -> OTP:
    """Create a new OTP for user, invalidate any existing unused OTPs, send email."""
    OTP.objects.filter(user=user, used_at__isnull=True).update(used_at=timezone.now())
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    expiry_minutes = get_setting('otp_expiry_minutes', 10)
    expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
    otp = OTP.objects.create(user=user, code=code, expires_at=expires_at)
    send_otp_email(user, code)
    return otp


def send_otp_email(user: User, code: str) -> None:
    """Send OTP code to user's email."""
    subject = 'Your login code'
    expiry_minutes = get_setting('otp_expiry_minutes', 10)
    message = (
        f'Your one-time login code is: {code}\n\n'
        f'It expires in {expiry_minutes} minutes. '
        'Do not share this code.'
    )
    send_mail(
        subject,
        message,
        getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@ims.local'),
        [user.email],
        fail_silently=False,
    )


def verify_otp(user: User, code: str) -> bool:
    """Verify OTP for user; mark as used if valid. Returns True if valid."""
    otp = OTP.objects.filter(user=user, code=code.strip(), used_at__isnull=True).order_by('-created_at').first()
    if not otp or not otp.is_valid:
        return False
    otp.used_at = timezone.now()
    otp.save(update_fields=['used_at'])
    return True
