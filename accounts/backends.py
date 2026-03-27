"""
Auth backend: same as ModelBackend, but non-superadmin users must have is_approved=True.

This affects session hydration (get_user), admin authenticate(), and keeps behavior consistent
with login_view / otp_verify checks.
"""
from django.contrib.auth.backends import ModelBackend

from .models import Role


class ApprovedUserBackend(ModelBackend):
    def user_can_authenticate(self, user):
        if not super().user_can_authenticate(user):
            return False
        if getattr(user, 'role', None) == Role.SUPERADMIN:
            return True
        return bool(getattr(user, 'is_approved', True))
