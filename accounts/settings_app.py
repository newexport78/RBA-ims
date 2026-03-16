"""Read app settings from DB (AppSetting) with fallback to Django settings / env (Phase 6)."""
from django.conf import settings as django_settings


def get_setting(key, default=None, coerce=int):
    """Get value for key: first from AppSetting, then default. coerce: int, str, float, bool."""
    try:
        from .models import AppSetting
        row = AppSetting.objects.filter(key=key).first()
        if row is not None and row.value != '':
            raw = row.value.strip()
            if coerce is int:
                return int(raw)
            if coerce is float:
                return float(raw)
            if coerce is bool:
                return raw.lower() in ('1', 'true', 'yes', 'on')
            return raw
    except Exception:
        pass
    if default is not None:
        return default
    # Fallback to Django settings for known keys
    fallback = {
        'otp_expiry_minutes': getattr(django_settings, 'OTP_EXPIRY_MINUTES', 10),
        'session_timeout_seconds': getattr(django_settings, 'SESSION_COOKIE_AGE', 3600),
        'password_min_length': 8,
        'password_require_upper': True,
        'password_require_lower': True,
        'password_require_digit': True,
        'password_require_special': True,
    }
    return fallback.get(key, default)
