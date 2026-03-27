"""
Auth backend: same as ModelBackend, but non-superadmin users must have is_approved=True.

This affects session hydration (get_user), admin authenticate(), and keeps behavior consistent
with login_view / otp_verify checks.
"""
from django.contrib.auth.backends import ModelBackend

from .rbac import user_may_log_in_per_approval


class ApprovedUserBackend(ModelBackend):
    def user_can_authenticate(self, user):
        if not super().user_can_authenticate(user):
            return False
        return user_may_log_in_per_approval(user)
