"""Account services: OTP generation and email sending."""
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import OTP, Role, User
from .settings_app import get_setting

logger = logging.getLogger(__name__)


def create_otp_for_user(user: User) -> OTP:
    """Create a new OTP for user, invalidate any existing unused OTPs, send email."""
    OTP.objects.filter(user=user, used_at__isnull=True).update(used_at=timezone.now())
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    expiry_minutes = get_setting('otp_expiry_minutes', 10)
    expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
    otp = OTP.objects.create(user=user, code=code, expires_at=expires_at)
    send_otp_email(user, code)
    return otp


def _send_email_via_console(subject: str, message: str, to_email: str) -> None:
    from django.core.mail import send_mail

    send_mail(
        subject,
        message,
        getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@ims.local"),
        [to_email],
    )


def _send_email_via_ses(subject: str, message: str, to_email: str) -> None:
    """Send using Amazon SES (uses default boto3 credential chain: ECS task role on Fargate)."""
    import boto3

    region = getattr(settings, "AWS_SES_REGION_NAME", "ap-south-1")
    client = boto3.client("ses", region_name=region)
    src = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@ims.local")
    try:
        client.send_email(
            Source=src,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": message, "Charset": "UTF-8"}},
            },
        )
    except Exception:
        logger.exception(
            "SES send_email failed region=%s from=%s to=%s",
            region,
            src,
            to_email,
        )
        raise
    logger.info("SES OTP email sent to=%s region=%s", to_email, region)


def _send_email_via_sendgrid(subject: str, message: str, to_email: str) -> None:
    """Send an email using SendGrid HTTP API."""
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail

    api_key = getattr(settings, "SENDGRID_API_KEY", None)
    if not api_key:
        raise RuntimeError("SENDGRID_API_KEY is not configured")

    email = Mail(
        from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@ims.local"),
        to_emails=to_email,
        subject=subject,
        plain_text_content=message,
    )
    client = SendGridAPIClient(api_key)
    response = client.send(email)
    if response.status_code >= 400:
        raise RuntimeError(f"SendGrid error {response.status_code}: {response.body}")


def send_otp_via_configured_transport(subject: str, message: str, to_email: str) -> None:
    """Pick SES, SendGrid, or console based on settings (single entry for OTP + async thread).

    USE_SES / SendGrid are checked *before* Django's console EMAIL_BACKEND so that
    production misconfigs like DEBUG=true still send real email when USE_SES=true.
    """
    if getattr(settings, "USE_SES", False):
        _send_email_via_ses(subject, message, to_email)
        return
    api_key = getattr(settings, "SENDGRID_API_KEY", "") or ""
    if api_key.strip():
        _send_email_via_sendgrid(subject, message, to_email)
        return
    backend = getattr(settings, "EMAIL_BACKEND", "")
    if backend == "django.core.mail.backends.console.EmailBackend":
        logger.warning(
            "OTP email via Django console backend (not SES); check CloudWatch logs. to=%s",
            to_email,
        )
        _send_email_via_console(subject, message, to_email)
        return
    if getattr(settings, "DEBUG", False):
        _send_email_via_console(subject, message, to_email)
        return
    raise RuntimeError(
        "No OTP email transport: set USE_SES=true (Amazon SES) or SENDGRID_API_KEY, "
        "or DEBUG=true for console."
    )


def notify_new_device_login_employee(user: User, request) -> None:
    """
    Email the employee and all active superadmins when an employee signs in from a
    fingerprint (IP + browser) not seen before. Does not block login if email fails.
    """
    from .audit import get_client_ip, get_user_agent

    ip = get_client_ip(request)
    ua = get_user_agent(request)
    when = timezone.now().strftime('%Y-%m-%d %H:%M UTC')
    user_body = (
        'A sign-in to your IMS account completed from a device or browser we have not '
        'seen on this account before.\n\n'
        f'Time: {when}\n'
        f'IP address: {ip or "unknown"}\n'
        f'Device / browser: {(ua[:400] if ua else "unknown")}\n\n'
        'If this was you, you can ignore this message.\n'
        'If not, change your password immediately and contact your administrator.\n'
    )
    try:
        send_otp_via_configured_transport(
            'New sign-in from unrecognized device',
            user_body,
            user.email,
        )
    except Exception:
        logger.exception('New-device alert email failed for user id=%s', user.pk)

    label = (user.get_full_name() or '').strip() or user.username
    for sa in User.objects.filter(role=Role.SUPERADMIN, is_active=True).exclude(email=''):
        admin_body = (
            'An employee signed in from a new device or browser (new fingerprint).\n\n'
            f'User: {user.username} ({label})\n'
            f'Email: {user.email}\n'
            f'Time: {when}\n'
            f'IP: {ip or "unknown"}\n'
            f'User-Agent: {(ua[:400] if ua else "unknown")}\n'
        )
        try:
            send_otp_via_configured_transport(
                f'[IMS] New device login: {user.username}',
                admin_body,
                sa.email,
            )
        except Exception:
            logger.exception('New-device alert email failed for superadmin id=%s', sa.pk)


def send_otp_email(user: User, code: str) -> None:
    """Send OTP code to user's email."""
    subject = 'Your login code'
    expiry_minutes = get_setting('otp_expiry_minutes', 10)
    message = (
        f'Your one-time login code is: {code}\n\n'
        f'It expires in {expiry_minutes} minutes. '
        'Do not share this code.'
    )
    # Optional async: return response fast under high load.
    # This does NOT change security (OTP still required); it only changes when email is sent.
    if getattr(settings, "OTP_SEND_ASYNC", False):
        try:
            import threading

            def _run() -> None:
                try:
                    send_otp_via_configured_transport(subject, message, user.email)
                except Exception:
                    logger.exception("Async OTP email failed for %s", user.email)

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            return
        except Exception:
            pass
    send_otp_via_configured_transport(subject, message, user.email)


def verify_otp(user: User, code: str) -> bool:
    """Verify OTP for user; mark as used if valid. Returns True if valid."""
    otp = OTP.objects.filter(user=user, code=code.strip(), used_at__isnull=True).order_by('-created_at').first()
    if not otp or not otp.is_valid:
        return False
    otp.used_at = timezone.now()
    otp.save(update_fields=['used_at'])
    return True
