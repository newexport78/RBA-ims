"""Account services: OTP generation and email sending."""
import secrets
from datetime import timedelta

from django.conf import settings
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


def _send_email_via_sendgrid(subject: str, message: str, to_email: str) -> None:
    """Send an email using SendGrid HTTP API."""
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail

    api_key = getattr(settings, 'SENDGRID_API_KEY', None)
    if not api_key:
        # Fail loudly in production so misconfiguration is obvious.
        raise RuntimeError('SENDGRID_API_KEY is not configured')

    email = Mail(
        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@ims.local'),
        to_emails=to_email,
        subject=subject,
        plain_text_content=message,
    )
    client = SendGridAPIClient(api_key)
    # Raise for any non-2xx response
    response = client.send(email)
    if response.status_code >= 400:
        raise RuntimeError(f'SendGrid error {response.status_code}: {response.body}')


def send_otp_email(user: User, code: str) -> None:
    """Send OTP code to user's email."""
    subject = 'Your login code'
    expiry_minutes = get_setting('otp_expiry_minutes', 10)
    message = (
        f'Your one-time login code is: {code}\n\n'
        f'It expires in {expiry_minutes} minutes. '
        'Do not share this code.'
    )
    _send_email_via_sendgrid(subject, message, user.email)


def verify_otp(user: User, code: str) -> bool:
    """Verify OTP for user; mark as used if valid. Returns True if valid."""
    otp = OTP.objects.filter(user=user, code=code.strip(), used_at__isnull=True).order_by('-created_at').first()
    if not otp or not otp.is_valid:
        return False
    otp.used_at = timezone.now()
    otp.save(update_fields=['used_at'])
    return True
