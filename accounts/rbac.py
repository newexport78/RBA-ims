"""
RBAC: role-based access control. Use decorators on views to enforce role.
"""
from functools import wraps

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.shortcuts import redirect
from django.urls import reverse

from .models import Role, User


def user_may_log_in_per_approval(user) -> bool:
    """
    Superadmin always allowed. Everyone else must have is_approved=True in the database.

    Uses a fresh EXISTS query (not the in-memory instance) so login matches the DB row.
    """
    if not user or not getattr(user, 'pk', None):
        return False
    if getattr(user, 'role', None) == Role.SUPERADMIN:
        return True
    return User.objects.filter(pk=user.pk, is_approved=True).exists()


def role_required(*allowed_roles: str):
    """
    View decorator: allow only users with one of the given roles.
    Example: @role_required(Role.SUPERADMIN) or @role_required(Role.SUPERADMIN, Role.ADMIN)
    """
    allowed = set(allowed_roles)

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                login_url = reverse('accounts:login')
                return redirect(f'{login_url}?{REDIRECT_FIELD_NAME}={request.get_full_path()}')
            if request.user.role not in allowed:
                return redirect(get_dashboard_url_for_role(request.user.role))
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def get_dashboard_url_for_role(role: str) -> str:
    """Return the dashboard URL for a role (used after login and when forbidden)."""
    from django.urls import reverse
    if role == Role.SUPERADMIN:
        return reverse('accounts:superadmin_dashboard')
    if role == Role.TWOIC:
        return reverse('accounts:twoic_dashboard')
    if role == Role.EMPLOYEE:
        return reverse('accounts:employee_dashboard')
    # Fallback: send any unexpected roles to login.
    return reverse('accounts:login')
