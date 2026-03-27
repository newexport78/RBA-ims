import csv
import io
import logging
import re

from django.core.paginator import Paginator
from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout, update_session_auth_hash
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from pypdf import PdfReader, PdfWriter

logger = logging.getLogger(__name__)

PAGE_SIZE = 25
AUDIT_PAGE_SIZE = 50

from .audit import evaluate_device_login_policy, log_audit_event, record_device
from .models import AuditAction, Device, DeviceStatus, AuditEvent, Role
from .password_validation import validate_password_ims
from .ratelimit import is_login_blocked, record_login_failure
from .rbac import get_dashboard_url_for_role, role_required, user_may_log_in_per_approval
from .services import create_otp_for_user, notify_new_device_login_alert, verify_otp

User = get_user_model()


@require_http_methods(['GET', 'POST'])
def login_view(request):
    """Step 1: username + password. On success, send OTP and redirect to OTP page."""
    if request.user.is_authenticated:
        return redirect(get_dashboard_url_for_role(request.user.role))

    if request.method == 'GET':
        return render(request, 'accounts/login.html')

    username = (request.POST.get('username') or '').strip()
    password = request.POST.get('password') or ''

    blocked, block_msg = is_login_blocked(request, username or None)
    if blocked:
        messages.error(request, block_msg)
        return render(request, 'accounts/login.html', {'username': username})

    if not username or not password:
        messages.error(request, 'Please enter username and password.')
        return render(request, 'accounts/login.html', {'username': username})

    user = User.objects.filter(username__iexact=username).first()
    if not user:
        record_login_failure(request, username)
        log_audit_event('LOGIN_FAILED', request=request, user=None, details='invalid_username')
        messages.error(request, 'Invalid username or password.')
        return render(request, 'accounts/login.html', {'username': username})

    if not user.is_active:
        deleted = record_login_failure(request, user.username)
        log_audit_event('LOGIN_FAILED', request=request, user=user, details='account_deactivated')
        if deleted:
            messages.error(request, 'This account has been permanently deleted due to too many failed login attempts.')
        else:
            messages.error(request, 'This account is deactivated. Contact an administrator.')
        return render(request, 'accounts/login.html', {'username': username})

    if not user.check_password(password):
        deleted = record_login_failure(request, user.username)
        log_audit_event('LOGIN_FAILED', request=request, user=user, details='invalid_password')
        if deleted:
            messages.error(request, 'This account has been permanently deleted due to too many failed login attempts.')
        else:
            messages.error(request, 'Invalid username or password.')
        return render(request, 'accounts/login.html', {'username': username})

    if not user_may_log_in_per_approval(user):
        messages.error(request, 'Your account is pending approval by superadmin. You will be able to log in once approved.')
        return render(request, 'accounts/login.html', {'username': username})

    try:
        create_otp_for_user(user)
        request.session['otp_user_id'] = user.pk
    except Exception:
        logger.exception(
            "Login step 2 failed (OTP create or session save) for username=%s id=%s",
            username,
            getattr(user, "pk", None),
        )
        messages.error(
            request,
            "Could not start email verification. Please try again. "
            "If it keeps failing, check application logs (e.g. Redis session or email).",
        )
        return render(request, "accounts/login.html", {"username": username})
    return redirect('accounts:otp_verify')


@require_http_methods(['GET', 'POST'])
def otp_verify_view(request):
    """Step 2: enter OTP. On success, log user in and redirect by role."""
    if request.user.is_authenticated:
        return redirect(get_dashboard_url_for_role(request.user.role))

    user_id = request.session.get('otp_user_id')
    if not user_id:
        messages.warning(request, 'Please log in with your username and password first.')
        return redirect('accounts:login')

    user = User.objects.filter(pk=user_id, is_active=True).first()
    if not user:
        request.session.pop('otp_user_id', None)
        messages.warning(request, 'Session expired. Please log in again.')
        return redirect('accounts:login')

    if request.method == 'GET':
        return render(request, 'accounts/otp.html', {'email_mask': _mask_email(user.email)})

    code = (request.POST.get('code') or '').strip()
    if not code:
        messages.error(request, 'Please enter the code from your email.')
        return render(request, 'accounts/otp.html', {'email_mask': _mask_email(user.email)})

    blocked, block_msg = is_login_blocked(request, user.username)
    if blocked:
        messages.error(request, block_msg)
        return render(request, 'accounts/otp.html', {'email_mask': _mask_email(user.email)})

    if not verify_otp(user, code):
        deleted = record_login_failure(request, user.username)
        log_audit_event('LOGIN_FAILED', request=request, user=user, details='invalid_or_expired_otp')
        if deleted:
            messages.error(request, 'This account has been permanently deleted due to too many failed login attempts.')
        else:
            messages.error(request, 'Invalid or expired code. Please try again or request a new code.')
        return render(request, 'accounts/otp.html', {'email_mask': _mask_email(user.email)})

    user.refresh_from_db()
    if not user_may_log_in_per_approval(user):
        request.session.pop('otp_user_id', None)
        messages.error(
            request,
            'Your account is pending approval by superadmin. You will be able to log in once approved.',
        )
        return redirect('accounts:login')

    request.session.pop('otp_user_id', None)

    decision, _device, is_new_device = evaluate_device_login_policy(user, request)
    if decision == 'blocked':
        request.session.pop('otp_user_id', None)
        messages.error(
            request,
            'This device is blocked for your account. Contact superadmin.',
        )
        return redirect('accounts:login')

    if decision == 'pending_approval':
        request.session.pop('otp_user_id', None)
        if is_new_device:
            notify_new_device_login_alert(user, request)
            log_audit_event(
                AuditAction.NEW_DEVICE_LOGIN,
                request=request,
                user=user,
                details={'message': f'{user.get_role_display()} login from new device requires superadmin approval'},
            )
            messages.info(
                request,
                'New device detected. Security alert emails were sent to you and superadmin.',
            )
        messages.error(
            request,
            'This new device is pending superadmin approval. You can log in after approval.',
        )
        return redirect('accounts:login')

    login(request, user, backend='accounts.backends.ApprovedUserBackend')
    record_device(user, request)
    log_audit_event('LOGIN_SUCCESS', request=request, user=user)
    if getattr(user, 'force_password_change', False):
        return redirect('accounts:change_password')
    return redirect(get_dashboard_url_for_role(user.role))


@require_GET
def login_redirect(request):
    """After login: redirect to role-specific dashboard. Used as LOGIN_REDIRECT_URL if needed."""
    if not request.user.is_authenticated:
        return redirect('accounts:login')
    return redirect(get_dashboard_url_for_role(request.user.role))


@require_http_methods(['GET', 'POST'])
def logout_view(request):
    """Clear session and redirect to login."""
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('accounts:login')


@require_GET
@role_required(Role.SUPERADMIN)
def superadmin_dashboard(request):
    """Dashboard with summary cards and quick links (Phase 5: new devices, recent events)."""
    from django.utils import timezone
    from datetime import timedelta
    week_ago = timezone.now() - timedelta(days=7)
    new_devices_count = Device.objects.filter(first_seen__gte=week_ago).count()
    recent_failed_logins = AuditEvent.objects.filter(
        action=AuditAction.LOGIN_FAILED,
        timestamp__gte=week_ago,
    ).order_by('-timestamp')[:10]
    recent_new_device_logins = AuditEvent.objects.select_related('user').filter(
        action=AuditAction.NEW_DEVICE_LOGIN,
        timestamp__gte=week_ago,
    ).order_by('-timestamp')[:10]
    return render(request, 'accounts/dashboards/superadmin_dashboard.html', {
        'new_devices_count': new_devices_count,
        'recent_failed_logins': recent_failed_logins,
        'recent_new_device_logins': recent_new_device_logins,
    })


# ---------- Superadmin: Devices (Phase 5) ----------


@require_GET
@role_required(Role.SUPERADMIN)
def superadmin_device_list(request):
    """List all devices. Filter by user (pk or username), status."""
    qs = Device.objects.select_related('user').order_by('-last_seen')
    user_filter = (request.GET.get('user') or '').strip()
    status_filter = (request.GET.get('status') or '').strip()
    if user_filter:
        if user_filter.isdigit():
            qs = qs.filter(user_id=int(user_filter))
        else:
            qs = qs.filter(user__username__icontains=user_filter)
    if status_filter and status_filter in dict(DeviceStatus.choices):
        qs = qs.filter(status=status_filter)
    return render(request, 'accounts/superadmin/device_list.html', {
        'devices': qs,
        'user_filter': user_filter,
        'status_filter': status_filter,
        'status_choices': DeviceStatus.choices,
    })


@require_http_methods(['POST'])
@role_required(Role.SUPERADMIN)
def superadmin_device_approve(request, device_id):
    """Set device status to approved."""
    device = get_object_or_404(Device, pk=device_id)
    device.status = DeviceStatus.APPROVED
    device.save(update_fields=['status'])
    messages.success(request, f'Device for {device.user.username} approved.')
    return redirect('accounts:superadmin_device_list')


@require_http_methods(['POST'])
@role_required(Role.SUPERADMIN)
def superadmin_device_block(request, device_id):
    """Set device status to blocked."""
    device = get_object_or_404(Device, pk=device_id)
    device.status = DeviceStatus.BLOCKED
    device.save(update_fields=['status'])
    messages.success(request, f'Device for {device.user.username} blocked.')
    return redirect('accounts:superadmin_device_list')


# ---------- Superadmin: Audit log (Phase 5) ----------


@require_GET
@role_required(Role.SUPERADMIN)
def superadmin_audit_log(request):
    """Audit log with filters (user, role, action, date range) and CSV/Excel export."""
    qs = AuditEvent.objects.select_related('user').order_by('-timestamp')
    user_filter = (request.GET.get('user') or '').strip()
    role_filter = (request.GET.get('role') or '').strip()
    action_filter = (request.GET.get('action') or '').strip()
    date_from = (request.GET.get('date_from') or '').strip()
    date_to = (request.GET.get('date_to') or '').strip()
    export = (request.GET.get('format') or '').strip().lower()

    if user_filter:
        if user_filter.isdigit():
            qs = qs.filter(user_id=int(user_filter))
        else:
            qs = qs.filter(user__username__icontains=user_filter)
    if role_filter and role_filter in dict(Role.choices):
        qs = qs.filter(user__role=role_filter)
    if action_filter and action_filter in dict(AuditAction.choices):
        qs = qs.filter(action=action_filter)
    if date_from:
        try:
            from datetime import date as date_type
            qs = qs.filter(timestamp__date__gte=date_type.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            from datetime import date as date_type
            qs = qs.filter(timestamp__date__lte=date_type.fromisoformat(date_to))
        except ValueError:
            pass

    if export == 'csv':
        import csv
        from django.http import HttpResponse
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="audit_log.csv"'
        writer = csv.writer(response)
        writer.writerow(['Time', 'User', 'Role', 'Action', 'Details', 'IP', 'User-Agent'])
        for e in qs[:10000]:  # cap for export
            writer.writerow([
                e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else '',
                e.user.username if e.user else '—',
                e.user.get_role_display() if e.user else '—',
                e.get_action_display() if e.action else e.action,
                (e.details or '')[:500],
                e.ip_address or '',
                (e.user_agent or '')[:200],
            ])
        return response

    if export == 'xlsx':
        try:
            import openpyxl
            from django.http import HttpResponse
            from io import BytesIO
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = 'Audit log'
            ws.append(['Time', 'User', 'Role', 'Action', 'Details', 'IP', 'User-Agent'])
            for e in qs[:10000]:
                ws.append([
                    e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else '',
                    e.user.username if e.user else '—',
                    e.user.get_role_display() if e.user else '—',
                    e.get_action_display() if e.action else e.action,
                    (e.details or '')[:500],
                    e.ip_address or '',
                    (e.user_agent or '')[:200],
                ])
            buf = BytesIO()
            wb.save(buf)
            buf.seek(0)
            response = HttpResponse(buf.getvalue(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
            response['Content-Disposition'] = 'attachment; filename="audit_log.xlsx"'
            return response
        except ImportError:
            messages.warning(request, 'Excel export requires openpyxl. Use CSV export instead.')
            # fall through to HTML

    get_copy = request.GET.copy()
    get_copy.pop('format', None)
    query_string_export = get_copy.urlencode()

    paginator = Paginator(qs, AUDIT_PAGE_SIZE)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    get_copy_pag = request.GET.copy()
    get_copy_pag.pop('format', None)
    get_copy_pag.pop('page', None)
    query_string = get_copy_pag.urlencode()
    return render(request, 'accounts/superadmin/audit_log.html', {
        'events': page_obj,
        'page_obj': page_obj,
        'query_string': query_string,
        'user_filter': user_filter,
        'role_filter': role_filter,
        'action_filter': action_filter,
        'date_from': date_from,
        'date_to': date_to,
        'role_choices': Role.choices,
        'action_choices': AuditAction.choices,
        'query_string_export': query_string_export,
    })


# ---------- Superadmin: Settings (Phase 6) ----------


def _get_app_setting(key, default=None, coerce=int):
    from .settings_app import get_setting
    return get_setting(key, default, coerce=coerce)


def _set_app_setting(key, value):
    from .models import AppSetting
    AppSetting.objects.update_or_create(key=key, defaults={'value': str(value)})


@require_http_methods(['GET', 'POST'])
@role_required(Role.SUPERADMIN)
def superadmin_settings(request):
    """Configure OTP expiry, session timeout, password rules. Stored in DB."""
    from .models import AppSetting
    SETTING_KEYS = [
        ('otp_expiry_minutes', int, 'OTP expiry (minutes)'),
        ('session_timeout_seconds', int, 'Session timeout (seconds)'),
        ('password_min_length', int, 'Password minimum length'),
        ('password_require_upper', bool, 'Require uppercase'),
        ('password_require_lower', bool, 'Require lowercase'),
        ('password_require_digit', bool, 'Require digit'),
        ('password_require_special', bool, 'Require special character'),
    ]
    if request.method == 'POST':
        for key, coerce, _ in SETTING_KEYS:
            raw = request.POST.get(key, '').strip()
            if coerce is bool:
                value = '1' if raw in ('1', 'on', 'true', 'yes') else '0'
            else:
                try:
                    value = str(coerce(raw)) if raw else ''
                except (ValueError, TypeError):
                    value = ''
            _set_app_setting(key, value)
        messages.success(request, 'Settings saved.')
        return redirect('accounts:superadmin_settings')
    current = {}
    for key, coerce, _ in SETTING_KEYS:
        current[key] = _get_app_setting(key, None, coerce=coerce)
    # Fallbacks for display when no DB value
    if current.get('otp_expiry_minutes') is None:
        current['otp_expiry_minutes'] = 10
    if current.get('session_timeout_seconds') is None:
        current['session_timeout_seconds'] = 3600
    if current.get('password_min_length') is None:
        current['password_min_length'] = 8
    for k in ('password_require_upper', 'password_require_lower', 'password_require_digit', 'password_require_special'):
        if current.get(k) is None:
            current[k] = True
    return render(request, 'accounts/superadmin/settings.html', {
        'setting_keys': SETTING_KEYS,
        'current': current,
    })


@require_GET
@role_required(Role.ADMIN)
def admin_dashboard(request):
    """Admin dashboard with stats and quick links."""
    from orders.models import Order, UserDocument
    my_users_count = User.objects.filter(role=Role.USER, is_active=True).count()
    orders = Order.objects.filter(created_by=request.user)
    orders_count = orders.count()
    user_documents_count = UserDocument.objects.filter(user__created_by=request.user).count()
    return render(request, 'accounts/dashboards/admin_dashboard.html', {
        'my_users_count': my_users_count,
        'orders_count': orders_count,
        'user_documents_count': user_documents_count,
    })


@require_http_methods(['GET', 'POST'])
@role_required(Role.ADMIN)
def admin_profile(request):
    """Editable profile for admin: change name/email + password. Wing is read-only."""
    user = request.user
    if request.method == 'GET':
        return render(request, 'accounts/admin_profile.html', {
            'form_data': {
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'email': user.email or '',
            },
        })

    first_name = (request.POST.get('first_name') or '').strip()
    last_name = (request.POST.get('last_name') or '').strip()
    email = (request.POST.get('email') or '').strip()
    current_password = request.POST.get('current_password') or ''
    new_password = request.POST.get('new_password') or ''
    confirm_password = request.POST.get('confirm_password') or ''

    if not email:
        messages.error(request, 'Email is required.')
    if not current_password or not new_password or not confirm_password:
        messages.error(request, 'Current password and new password are required.')

    form_ctx = {
        'form_data': {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
        },
    }

    if messages.get_messages(request):
        # Some basic required-field errors already added
        return render(request, 'accounts/admin_profile.html', form_ctx)

    if not user.check_password(current_password):
        messages.error(request, 'Current password is incorrect.')
        return render(request, 'accounts/admin_profile.html', form_ctx)

    if new_password != confirm_password:
        messages.error(request, 'New passwords do not match.')
        return render(request, 'accounts/admin_profile.html', form_ctx)

    ok, errs = validate_password_ims(new_password, user=user)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/admin_profile.html', form_ctx)

    if email and User.objects.filter(email__iexact=email).exclude(pk=user.pk).exists():
        messages.error(request, 'That email is already in use.')
        return render(request, 'accounts/admin_profile.html', form_ctx)

    user.first_name = first_name
    user.last_name = last_name
    user.email = email
    user.set_password(new_password)
    user.save(update_fields=['first_name', 'last_name', 'email', 'password'])
    update_session_auth_hash(request, user)
    log_audit_event(AuditAction.PROFILE_UPDATED, request=request, user=user, details='admin_profile')
    messages.success(request, 'Profile and password updated.')
    return redirect('accounts:admin_profile')


@require_http_methods(['GET', 'POST'])
@role_required(Role.SUPERADMIN)
def superadmin_profile(request):
    """Editable profile for superadmin. Changing username, name, or email requires current password."""
    user = request.user
    if request.method == 'GET':
        return render(request, 'accounts/superadmin_profile.html', {
            'form_data': {
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'username': user.username,
                'email': user.email or '',
            },
        })

    first_name = (request.POST.get('first_name') or '').strip()
    last_name = (request.POST.get('last_name') or '').strip()
    username = (request.POST.get('username') or '').strip()
    email = (request.POST.get('email') or '').strip()
    current_password = request.POST.get('password') or ''
    new_password = (request.POST.get('new_password') or '').strip()
    confirm_password = (request.POST.get('confirm_password') or '').strip()

    if not username:
        messages.error(request, 'Username is required.')
        return render(request, 'accounts/superadmin_profile.html', {
            'form_data': {'first_name': first_name, 'last_name': last_name, 'username': username, 'email': email},
        })
    if not email:
        messages.error(request, 'Email is required.')
        return render(request, 'accounts/superadmin_profile.html', {
            'form_data': {'first_name': first_name, 'last_name': last_name, 'username': username, 'email': email},
        })

    identity_changed = (
        (user.first_name or '') != first_name
        or (user.last_name or '') != last_name
        or user.username != username
        or (user.email or '') != email
    )
    password_change_requested = bool(new_password or confirm_password)

    if identity_changed and not current_password:
        messages.error(request, 'To change name, username, or email you must enter your current password.')
        return render(request, 'accounts/superadmin_profile.html', {
            'form_data': {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'email': email,
            },
        })
    # Apply changes
    user.first_name = first_name
    user.last_name = last_name
    user.username = username
    user.email = email

    if password_change_requested:
        user.set_password(new_password)
        update_session_auth_hash(request, user)

    user.save(update_fields=['first_name', 'last_name', 'username', 'email'] + (['password'] if password_change_requested else []))
    log_audit_event(AuditAction.PROFILE_UPDATED, request=request, user=user, details='superadmin_profile')
    messages.success(request, 'Profile updated.' + (' Password changed.' if password_change_requested else ''))
    return redirect('accounts:superadmin_profile')

    if password_change_requested:
        if not current_password:
            messages.error(request, 'Enter your current password to change password.')
            return render(request, 'accounts/superadmin_profile.html', {
                'form_data': {
                    'first_name': first_name,
                    'last_name': last_name,
                    'username': username,
                    'email': email,
                },
            })
        if not user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return render(request, 'accounts/superadmin_profile.html', {
                'form_data': {
                    'first_name': first_name,
                    'last_name': last_name,
                    'username': username,
                    'email': email,
                },
            })
        if not new_password or not confirm_password:
            messages.error(request, 'New password and confirmation are required.')
            return render(request, 'accounts/superadmin_profile.html', {
                'form_data': {
                    'first_name': first_name,
                    'last_name': last_name,
                    'username': username,
                    'email': email,
                },
            })
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return render(request, 'accounts/superadmin_profile.html', {
                'form_data': {
                    'first_name': first_name,
                    'last_name': last_name,
                    'username': username,
                    'email': email,
                },
            })
        ok, errs = validate_password_ims(new_password, user=user)
        if not ok:
            for msg in errs:
                messages.error(request, msg)
            return render(request, 'accounts/superadmin_profile.html', {
                'form_data': {
                    'first_name': first_name,
                    'last_name': last_name,
                    'username': username,
                    'email': email,
                },
            })

    if username and User.objects.filter(username__iexact=username).exclude(pk=user.pk).exists():
        messages.error(request, 'That username is already in use.')
        return render(request, 'accounts/superadmin_profile.html', {
            'form_data': {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'email': email,
            },
        })
    if email and User.objects.filter(email__iexact=email).exclude(pk=user.pk).exists():
        messages.error(request, 'That email is already in use.')
        return render(request, 'accounts/superadmin_profile.html', {
            'form_data': {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'email': email,
            },
        })

    user.first_name = first_name
    user.last_name = last_name
    user.username = username
    user.email = email
    user.save(update_fields=['first_name', 'last_name', 'username', 'email'])
    log_audit_event(AuditAction.PROFILE_UPDATED, request=request, user=user, details='superadmin_profile')
    messages.success(request, 'Profile updated.')
    return redirect('accounts:superadmin_profile')


@require_GET
@role_required(Role.USER)
def user_dashboard(request):
    """My orders: list orders assigned to this user (via OrderAssignment)."""
    from orders.models import OrderAssignment, AssignmentStatus  # avoid circular import
    assignments = (
        OrderAssignment.objects.filter(user=request.user)
        .select_related('order')
        .order_by('-created_at')
    )
    total = assignments.count()
    completed_count = assignments.filter(status=AssignmentStatus.COMPLETED).count()
    return render(request, 'accounts/dashboards/user_dashboard.html', {
        'assignments': assignments,
        'total_orders': total,
        'completed_count': completed_count,
    })


@require_http_methods(['GET', 'POST'])
@role_required(Role.USER)
def user_profile(request):
    """Editable profile for user: change name/email + password. Wing is read-only."""
    user = request.user
    if request.method == 'GET':
        return render(request, 'accounts/user_profile.html', {
            'form_data': {
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'email': user.email or '',
            },
        })

    first_name = (request.POST.get('first_name') or '').strip()
    last_name = (request.POST.get('last_name') or '').strip()
    email = (request.POST.get('email') or '').strip()
    current_password = request.POST.get('current_password') or ''
    new_password = request.POST.get('new_password') or ''
    confirm_password = request.POST.get('confirm_password') or ''

    if not email:
        messages.error(request, 'Email is required.')
    if not current_password or not new_password or not confirm_password:
        messages.error(request, 'Current password and new password are required.')

    form_ctx = {
        'form_data': {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
        },
    }

    if messages.get_messages(request):
        return render(request, 'accounts/user_profile.html', form_ctx)

    if not user.check_password(current_password):
        messages.error(request, 'Current password is incorrect.')
        return render(request, 'accounts/user_profile.html', form_ctx)

    if new_password != confirm_password:
        messages.error(request, 'New passwords do not match.')
        return render(request, 'accounts/user_profile.html', form_ctx)

    ok, errs = validate_password_ims(new_password, user=user)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/user_profile.html', form_ctx)

    if email and User.objects.filter(email__iexact=email).exclude(pk=user.pk).exists():
        messages.error(request, 'That email is already in use.')
        return render(request, 'accounts/user_profile.html', form_ctx)

    user.first_name = first_name
    user.last_name = last_name
    user.email = email
    user.set_password(new_password)
    user.save(update_fields=['first_name', 'last_name', 'email', 'password'])
    update_session_auth_hash(request, user)
    log_audit_event(AuditAction.PROFILE_UPDATED, request=request, user=user, details='user_profile')
    messages.success(request, 'Profile and password updated.')
    return redirect('accounts:user_profile')


def _mask_email(email: str) -> str:
    """e.g. j***@example.com"""
    if not email or '@' not in email:
        return '***'
    local, domain = email.split('@', 1)
    if len(local) <= 2:
        masked = local[0] + '***'
    else:
        masked = local[0] + '***' + local[-1]
    return f'{masked}@{domain}'


# ---------- Superadmin: user management (Phase 2) ----------


@require_GET
@role_required(Role.SUPERADMIN)
def superadmin_user_list(request):
    """List all users (admins + users). Filter by role, status; search by name/username."""
    qs = User.objects.all().order_by('role', 'username')
    role_filter = (request.GET.get('role') or '').strip()
    status_filter = (request.GET.get('status') or '').strip()
    search = (request.GET.get('q') or '').strip()

    if role_filter and role_filter in dict(Role.choices):
        qs = qs.filter(role=role_filter)
    if status_filter == 'active':
        qs = qs.filter(is_active=True)
    elif status_filter == 'inactive':
        qs = qs.filter(is_active=False)
    if search:
        qs = qs.filter(
            Q(username__icontains=search)
            | Q(email__icontains=search)
            | Q(first_name__icontains=search)
            | Q(last_name__icontains=search)
        )

    paginator = Paginator(qs, PAGE_SIZE)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    qs_copy = request.GET.copy()
    qs_copy.pop('page', None)
    query_string = qs_copy.urlencode()
    return render(
        request,
        'accounts/superadmin/user_list.html',
        {
            'user_list': page_obj,
            'page_obj': page_obj,
            'query_string': query_string,
            'role_filter': role_filter,
            'status_filter': status_filter,
            'search': search,
            'role_choices': Role.choices,
        },
    )


# Role options for superadmin "create user" form: 2IC only (only one 2IC allowed).
CREATE_ROLE_CHOICES = [(r, label) for r, label in Role.choices if r in (Role.TWOIC,)]


@require_http_methods(['GET', 'POST'])
@role_required(Role.SUPERADMIN)
def superadmin_user_create(request):
    """Create a 2IC (only one 2IC allowed)."""
    # Hide 2IC option if one already exists
    roles = [r for r in CREATE_ROLE_CHOICES if not User.objects.filter(role=Role.TWOIC).exists()]
    form_context = {'roles': roles}

    if request.method == 'GET':
        return render(request, 'accounts/superadmin/user_form.html', form_context)

    username = (request.POST.get('username') or '').strip()
    email = (request.POST.get('email') or '').strip().lower()
    role = (request.POST.get('role') or '').strip()
    password = request.POST.get('password') or ''
    first_name = (request.POST.get('first_name') or '').strip()
    last_name = (request.POST.get('last_name') or '').strip()
    wing = (request.POST.get('wing') or '').strip()
    phone = (request.POST.get('phone') or '').strip()
    date_of_birth_str = (request.POST.get('date_of_birth') or '').strip()

    form_context.update({
        'username': username, 'email': email, 'role': role,
        'first_name': first_name, 'last_name': last_name, 'wing': wing,
        'phone': phone, 'date_of_birth': date_of_birth_str,
    })

    if not username:
        messages.error(request, 'Username is required.')
        return render(request, 'accounts/superadmin/user_form.html', form_context)
    if not email:
        messages.error(request, 'Email is required (for OTP).')
        return render(request, 'accounts/superadmin/user_form.html', form_context)
    if role != Role.TWOIC:
        messages.error(request, 'Only 2IC accounts can be created.')
        return render(request, 'accounts/superadmin/user_form.html', form_context)
    if role == Role.TWOIC and User.objects.filter(role=Role.TWOIC).exists():
        messages.error(request, 'Only one 2IC account can exist. A 2IC has already been created.')
        return render(request, 'accounts/superadmin/user_form.html', form_context)
    ok, errs = validate_password_ims(password)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/superadmin/user_form.html', form_context)

    if User.objects.filter(username__iexact=username).exists():
        messages.error(request, f'A user with username "{username}" already exists.')
        return render(request, 'accounts/superadmin/user_form.html', form_context)
    if User.objects.filter(email__iexact=email).exists():
        messages.error(request, f'A user with email "{email}" already exists.')
        return render(request, 'accounts/superadmin/user_form.html', form_context)

    date_of_birth = None
    if role == Role.TWOIC and date_of_birth_str:
        from datetime import datetime
        try:
            date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()
        except ValueError:
            messages.error(request, 'Invalid date of birth. Use YYYY-MM-DD.')
            return render(request, 'accounts/superadmin/user_form.html', form_context)

    create_kwargs = dict(
        username=username,
        email=email,
        password=password,
        role=role,
        first_name=first_name or '',
        last_name=last_name or '',
        wing=wing or '',
        is_staff=(role == Role.ADMIN),
        is_superuser=False,
        is_active=True,
        created_by=None,  # superadmin-created
        is_approved=True,  # superadmin-created accounts can log in immediately
    )
    if role == Role.TWOIC:
        create_kwargs['phone'] = phone or ''
        create_kwargs['date_of_birth'] = date_of_birth
    user = User.objects.create_user(**create_kwargs)
    messages.success(request, f'Account created: {user.username} ({user.get_role_display()}).')
    return redirect('accounts:superadmin_user_list')


# ---------- 2IC ----------


@require_GET
@role_required(Role.TWOIC)
def twoic_dashboard(request):
    """2IC dashboard: My employees, Orders, My profile."""
    from orders.models import Order
    employees_count = User.objects.filter(role=Role.EMPLOYEE, created_by=request.user, is_active=True).count()
    orders_count = Order.objects.filter(created_by=request.user).count()
    export_password = _twoic_export_password(request.user)
    return render(request, 'accounts/dashboards/twoic_dashboard.html', {
        'employees_count': employees_count,
        'orders_count': orders_count,
        'export_csv_password': export_password,
    })


def _twoic_export_password(twoic_user):
    """Password to open the 2IC employees PDF: last 3 digits of phone + DOB(ddmmyy) + '1215'."""
    digits_phone = re.sub(r'\D', '', (twoic_user.phone or ''))
    part_phone = digits_phone[-3:] if len(digits_phone) >= 3 else digits_phone.zfill(3)
    part_dob = twoic_user.date_of_birth.strftime('%d%m%y') if getattr(twoic_user, 'date_of_birth', None) else ''
    return part_phone + part_dob + '1215'


@require_GET
@role_required(Role.TWOIC)
def twoic_export_employees_csv(request):
    """Download PDF of employee number and name (password-protected). Password = last3(2IC phone) + DOB(ddmmyy) + '1215'."""
    employees = User.objects.filter(role=Role.EMPLOYEE, created_by=request.user).order_by('employee_number', 'username')
    data = [['Employee Number', 'Name']]
    for emp in employees:
        data.append([
            emp.employee_number or emp.username or '',
            (emp.get_full_name() or emp.username or '').strip() or '',
        ])

    pdf_buf = io.BytesIO()
    doc = SimpleDocTemplate(pdf_buf, pagesize=letter)
    table = Table(data, colWidths=[120, 200])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
    ]))
    doc.build([table])
    pdf_buf.seek(0)

    password = _twoic_export_password(request.user)
    reader = PdfReader(pdf_buf)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(user_password=password, algorithm="AES-256")
    out_buf = io.BytesIO()
    writer.write(out_buf)
    out_buf.seek(0)
    response = HttpResponse(out_buf.getvalue(), content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="employees.pdf"'
    return response


def _twoic_employees_queryset(request):
    """Employees created by this 2IC."""
    return User.objects.filter(role=Role.EMPLOYEE, created_by=request.user).order_by('employee_number', 'username')


@require_GET
@role_required(Role.TWOIC)
def twoic_my_employees(request):
    """List employees created by this 2IC."""
    return render(request, 'accounts/twoic/my_employees.html', {
        'employee_list': _twoic_employees_queryset(request),
    })


@require_http_methods(['GET', 'POST'])
@role_required(Role.TWOIC)
def twoic_employee_create(request):
    """2IC creates an employee: employee_number, name, phone, DoB, email, password. Login = employee_number + password."""
    if request.method == 'GET':
        return render(request, 'accounts/twoic/employee_form.html', {})

    employee_number = (request.POST.get('employee_number') or '').strip()
    first_name = (request.POST.get('first_name') or '').strip()
    last_name = (request.POST.get('last_name') or '').strip()
    phone = (request.POST.get('phone') or '').strip()
    email = (request.POST.get('email') or '').strip().lower()
    dob_str = (request.POST.get('date_of_birth') or '').strip()
    password = request.POST.get('password') or ''

    form_ctx = {
        'employee_number': employee_number,
        'first_name': first_name,
        'last_name': last_name,
        'phone': phone,
        'email': email,
        'date_of_birth': dob_str,
    }

    if not employee_number:
        messages.error(request, 'Employee number is required (used as login username).')
        return render(request, 'accounts/twoic/employee_form.html', form_ctx)
    if not email:
        messages.error(request, 'Email is required (for OTP).')
        return render(request, 'accounts/twoic/employee_form.html', form_ctx)
    ok, errs = validate_password_ims(password)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/twoic/employee_form.html', form_ctx)

    if User.objects.filter(employee_number__iexact=employee_number).exists():
        messages.error(request, f'An employee with number "{employee_number}" already exists.')
        return render(request, 'accounts/twoic/employee_form.html', form_ctx)
    if User.objects.filter(username__iexact=employee_number).exists():
        messages.error(request, f'Username "{employee_number}" is already taken.')
        return render(request, 'accounts/twoic/employee_form.html', form_ctx)
    if User.objects.filter(email__iexact=email).exists():
        messages.error(request, f'A user with email "{email}" already exists.')
        return render(request, 'accounts/twoic/employee_form.html', form_ctx)

    from datetime import datetime
    date_of_birth = None
    if dob_str:
        try:
            date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            messages.error(request, 'Invalid date of birth. Use YYYY-MM-DD.')
            return render(request, 'accounts/twoic/employee_form.html', form_ctx)

    user = User.objects.create_user(
        username=employee_number,
        email=email,
        password=password,
        role=Role.EMPLOYEE,
        first_name=first_name or '',
        last_name=last_name or '',
        phone=phone or '',
        date_of_birth=date_of_birth,
        employee_number=employee_number,
        is_staff=False,
        is_superuser=False,
        is_active=True,
        created_by=request.user,
        is_approved=False,  # superadmin must approve before employee can log in
    )
    # Force DB row: bypasses any edge case where create_user omits the flag in SQL.
    User.objects.filter(pk=user.pk).update(is_approved=False)
    user.refresh_from_db(fields=['is_approved'])
    messages.success(
        request,
        f'Employee {user.employee_number} ({user.get_full_name() or user.username}) created. '
        'They can log in after a superadmin approves the account under Users.',
    )
    return redirect('accounts:twoic_my_employees')


@require_http_methods(['GET', 'POST'])
@role_required(Role.TWOIC)
def twoic_profile(request):
    """2IC profile: change name, email, password."""
    user = request.user
    if request.method == 'GET':
        return render(request, 'accounts/twoic_profile.html', {
            'form_data': {
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'email': user.email or '',
            },
        })

    first_name = (request.POST.get('first_name') or '').strip()
    last_name = (request.POST.get('last_name') or '').strip()
    email = (request.POST.get('email') or '').strip()
    current_password = request.POST.get('current_password') or ''
    new_password = request.POST.get('new_password') or ''
    confirm_password = request.POST.get('confirm_password') or ''

    form_ctx = {'form_data': {'first_name': first_name, 'last_name': last_name, 'email': email}}

    if not email:
        messages.error(request, 'Email is required.')
        return render(request, 'accounts/twoic_profile.html', form_ctx)
    if not current_password or not new_password or not confirm_password:
        messages.error(request, 'Current password and new password are required.')
        return render(request, 'accounts/twoic_profile.html', form_ctx)
    if not user.check_password(current_password):
        messages.error(request, 'Current password is incorrect.')
        return render(request, 'accounts/twoic_profile.html', form_ctx)
    if new_password != confirm_password:
        messages.error(request, 'New passwords do not match.')
        return render(request, 'accounts/twoic_profile.html', form_ctx)
    ok, errs = validate_password_ims(new_password, user=user)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/twoic_profile.html', form_ctx)
    if User.objects.filter(email__iexact=email).exclude(pk=user.pk).exists():
        messages.error(request, 'That email is already in use.')
        return render(request, 'accounts/twoic_profile.html', form_ctx)

    user.first_name = first_name
    user.last_name = last_name
    user.email = email
    user.set_password(new_password)
    user.save(update_fields=['first_name', 'last_name', 'email', 'password'])
    update_session_auth_hash(request, user)
    log_audit_event(AuditAction.PROFILE_UPDATED, request=request, user=user, details='twoic_profile')
    messages.success(request, 'Profile updated.')
    return redirect('accounts:twoic_profile')


# ---------- Employee ----------


@require_GET
@role_required(Role.EMPLOYEE)
def employee_dashboard(request):
    """Employee dashboard: orders received from 2IC, profile."""
    from orders.models import OrderAssignment
    assignments = OrderAssignment.objects.filter(user=request.user).select_related('order').order_by('-created_at')
    total_orders = assignments.count()
    return render(request, 'accounts/dashboards/employee_dashboard.html', {
        'assignments': assignments,
        'total_orders': total_orders,
    })


@require_http_methods(['GET', 'POST'])
@role_required(Role.EMPLOYEE)
def employee_profile(request):
    """Employee profile: view/edit name, email, change password. No creation of users."""
    user = request.user
    if request.method == 'GET':
        return render(request, 'accounts/employee_profile.html', {
            'form_data': {
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'email': user.email or '',
                'employee_number': user.employee_number or user.username,
                'phone': user.phone or '',
                'date_of_birth': user.date_of_birth.isoformat() if user.date_of_birth else '',
            },
        })

    first_name = (request.POST.get('first_name') or '').strip()
    last_name = (request.POST.get('last_name') or '').strip()
    email = (request.POST.get('email') or '').strip()
    phone = (request.POST.get('phone') or '').strip()
    current_password = request.POST.get('current_password') or ''
    new_password = request.POST.get('new_password') or ''
    confirm_password = request.POST.get('confirm_password') or ''

    form_ctx = {
        'form_data': {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'phone': phone,
            'employee_number': user.employee_number or user.username,
            'date_of_birth': user.date_of_birth.isoformat() if user.date_of_birth else '',
        },
    }

    if not email:
        messages.error(request, 'Email is required.')
        return render(request, 'accounts/employee_profile.html', form_ctx)
    if not current_password or not new_password or not confirm_password:
        messages.error(request, 'Current password and new password are required.')
        return render(request, 'accounts/employee_profile.html', form_ctx)
    if not user.check_password(current_password):
        messages.error(request, 'Current password is incorrect.')
        return render(request, 'accounts/employee_profile.html', form_ctx)
    if new_password != confirm_password:
        messages.error(request, 'New passwords do not match.')
        return render(request, 'accounts/employee_profile.html', form_ctx)
    ok, errs = validate_password_ims(new_password, user=user)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/employee_profile.html', form_ctx)
    if User.objects.filter(email__iexact=email).exclude(pk=user.pk).exists():
        messages.error(request, 'That email is already in use.')
        return render(request, 'accounts/employee_profile.html', form_ctx)

    user.first_name = first_name
    user.last_name = last_name
    user.email = email
    user.phone = phone
    user.set_password(new_password)
    user.save(update_fields=['first_name', 'last_name', 'email', 'phone', 'password'])
    update_session_auth_hash(request, user)
    log_audit_event(AuditAction.PROFILE_UPDATED, request=request, user=user, details='employee_profile')
    messages.success(request, 'Profile updated.')
    return redirect('accounts:employee_profile')


# ---------- Admin: my users (Phase 3) ----------


def _admin_my_users_queryset(request):
    """All regular users (role=User), visible to any admin."""
    return User.objects.filter(role=Role.USER).order_by('username')


@require_GET
@role_required(Role.ADMIN)
def admin_my_users(request):
    """List all regular users (role=User)."""
    return render(request, 'accounts/admin/my_users.html', {
        'user_list': _admin_my_users_queryset(request),
    })


@require_http_methods(['GET', 'POST'])
@role_required(Role.ADMIN)
def admin_user_create(request):
    """Admin creates a user (role=User only); created_by=request.user."""
    form_context = {'roles': [(Role.USER, 'User')]}  # only User role

    if request.method == 'GET':
        return render(request, 'accounts/admin/user_form.html', form_context)

    username = (request.POST.get('username') or '').strip()
    email = (request.POST.get('email') or '').strip().lower()
    password = request.POST.get('password') or ''
    first_name = (request.POST.get('first_name') or '').strip()
    last_name = (request.POST.get('last_name') or '').strip()
    wing = (request.POST.get('wing') or '').strip()

    form_context.update({
        'username': username, 'email': email, 'first_name': first_name, 'last_name': last_name, 'wing': wing,
    })

    if not username:
        messages.error(request, 'Username is required.')
        return render(request, 'accounts/admin/user_form.html', form_context)
    if not email:
        messages.error(request, 'Email is required (for OTP).')
        return render(request, 'accounts/admin/user_form.html', form_context)
    ok, errs = validate_password_ims(password)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/admin/user_form.html', form_context)

    if User.objects.filter(username__iexact=username).exists():
        messages.error(request, f'A user with username "{username}" already exists.')
        return render(request, 'accounts/admin/user_form.html', form_context)
    if User.objects.filter(email__iexact=email).exists():
        messages.error(request, f'A user with email "{email}" already exists.')
        return render(request, 'accounts/admin/user_form.html', form_context)

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        role=Role.USER,
        first_name=first_name or '',
        last_name=last_name or '',
        wing=wing or '',
        is_staff=False,
        is_superuser=False,
        is_active=True,
        created_by=request.user,
        is_approved=False,  # superadmin must approve before user can log in
    )
    User.objects.filter(pk=user.pk).update(is_approved=False)
    messages.success(request, f'User {user.username} created. They can log in after superadmin approves.')
    return redirect('accounts:admin_my_users')


@require_GET
@role_required(Role.SUPERADMIN)
def superadmin_user_approve(request, user_id):
    """Approve a user so they can log in (pending employees, admin-created users, etc.)."""
    target = get_object_or_404(User, pk=user_id)
    if target.is_approved:
        messages.info(request, f'{target.username} is already approved.')
    else:
        target.is_approved = True
        target.save(update_fields=['is_approved'])
        log_audit_event('USER_APPROVED', request=request, user=target, details={'username': target.username})
        messages.success(request, f'{target.username} has been approved. They can now log in.')
    return redirect('accounts:superadmin_user_list')


@require_http_methods(['GET', 'POST'])
@role_required(Role.SUPERADMIN)
def superadmin_user_delete(request, user_id):
    """Delete a user. Confirm on GET, delete on POST. Cannot delete self."""
    target = get_object_or_404(User, pk=user_id)
    if target.pk == request.user.pk:
        messages.error(request, 'You cannot delete your own account.')
        return redirect('accounts:superadmin_user_list')
    if request.method == 'GET':
        return render(request, 'accounts/superadmin/user_confirm_delete.html', {'target_user': target})
    target.delete()
    messages.success(request, f'User {target.username} has been deleted.')
    return redirect('accounts:superadmin_user_list')


@require_http_methods(['GET', 'POST'])
@role_required(Role.SUPERADMIN)
def superadmin_user_reset_password(request, user_id):
    """Set a new password for a user; optional "force change on next login"."""
    target = get_object_or_404(User, pk=user_id)
    if request.method == 'GET':
        return render(request, 'accounts/superadmin/user_reset_password.html', {'target_user': target})

    new_password = request.POST.get('password') or ''
    force_change = request.POST.get('force_change') == 'on'

    ok, errs = validate_password_ims(new_password, user=target)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/superadmin/user_reset_password.html', {'target_user': target})

    target.set_password(new_password)
    target.force_password_change = force_change
    target.save(update_fields=['password', 'force_password_change'])
    messages.success(request, f'Password updated for {target.username}.')
    if force_change:
        messages.info(request, 'They will be required to set a new password on next login.')
    return redirect('accounts:superadmin_user_list')


# ---------- Change password (when force_password_change is set) ----------


@require_http_methods(['GET', 'POST'])
def change_password_view(request):
    """Set new password when force_password_change is set (after OTP). No current password required."""
    if not request.user.is_authenticated:
        return redirect('accounts:login')
    if not getattr(request.user, 'force_password_change', False):
        return redirect(get_dashboard_url_for_role(request.user.role))

    if request.method == 'GET':
        return render(request, 'accounts/change_password.html')

    new_password = request.POST.get('password') or ''
    confirm = request.POST.get('confirm') or ''
    ok, errs = validate_password_ims(new_password, user=request.user)
    if not ok:
        for msg in errs:
            messages.error(request, msg)
        return render(request, 'accounts/change_password.html')
    if new_password != confirm:
        messages.error(request, 'Passwords do not match.')
        return render(request, 'accounts/change_password.html')

    request.user.set_password(new_password)
    request.user.force_password_change = False
    request.user.save(update_fields=['password', 'force_password_change'])
    update_session_auth_hash(request, request.user)
    messages.success(request, 'Your password has been updated.')
    return redirect(get_dashboard_url_for_role(request.user.role))
