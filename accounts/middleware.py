"""
Redirect authenticated users away from login/OTP; apply configurable session timeout (Phase 6).
"""
from django.shortcuts import redirect
from django.urls import reverse

from .rbac import get_dashboard_url_for_role
from .settings_app import get_setting


class SessionTimeoutMiddleware:
    """Set session expiry from AppSetting (session_timeout_seconds) so superadmin can tune it."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(request, 'session', None) and request.session.session_key:
            seconds = get_setting('session_timeout_seconds', 3600)
            request.session.set_expiry(seconds)
        return self.get_response(request)


class RoleRedirectMiddleware:
    """
    - If user is logged in and visits login or OTP page, redirect to their dashboard.
    - Does not handle role-based view protection (use @role_required for that).
    """
    LOGIN_VIEW_NAME = 'accounts:login'
    OTP_VIEW_NAME = 'accounts:otp_verify'

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and request.user.is_active:
            path = request.path.rstrip('/')
            # Force password change: must complete before going elsewhere
            if getattr(request.user, 'force_password_change', False):
                change_pw_url = reverse('accounts:change_password').rstrip('/')
                if path != change_pw_url:
                    return redirect('accounts:change_password')
            login_url = reverse(self.LOGIN_VIEW_NAME).rstrip('/')
            otp_url = reverse(self.OTP_VIEW_NAME).rstrip('/')
            if path == login_url or path == otp_url:
                return redirect(get_dashboard_url_for_role(request.user.role))
        return self.get_response(request)
