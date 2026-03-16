"""Password validation using app settings (Phase 6)."""
import re

from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import (
    validate_password as django_validate_password,
    get_default_password_validators,
    MinimumLengthValidator,
)

from .settings_app import get_setting


def get_password_validators():
    """Validators that respect AppSetting: min length and optional complexity."""
    validators = list(get_default_password_validators())
    min_length = get_setting('password_min_length', 8)
    validators = [v for v in validators if not isinstance(v, MinimumLengthValidator)]
    validators.append(MinimumLengthValidator(min_length=min_length))
    return validators


def validate_password_ims(password, user=None):
    """
    Validate password: Django default validators + min length and complexity from settings.
    Returns (True, None) if valid, else (False, list of error messages).
    """
    if not password:
        return False, ['Password is required.']
    errors = []
    min_length = get_setting('password_min_length', 8)
    if len(password) < min_length:
        errors.append(f'Password must be at least {min_length} characters.')
    if get_setting('password_require_upper', True):
        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter.')
    if get_setting('password_require_lower', True):
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter.')
    if get_setting('password_require_digit', True):
        if not re.search(r'\d', password):
            errors.append('Password must contain at least one digit.')
    if get_setting('password_require_special', True):
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;/\'`~]', password):
            errors.append('Password must contain at least one special character.')
    if errors:
        return False, errors
    try:
        django_validate_password(password, user=user, password_validators=get_password_validators())
    except ValidationError as e:
        return False, list(e.messages)
    return True, None
