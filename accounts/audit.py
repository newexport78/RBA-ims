"""Audit logging and device tracking for Phase 5."""
import hashlib
from django.utils import timezone

from .models import AuditAction, AuditEvent, Device, DeviceStatus, User


def get_client_ip(request):
    """Get client IP from request (X-Forwarded-For or REMOTE_ADDR)."""
    if not request:
        return None
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def get_user_agent(request):
    """Get User-Agent string, truncated for storage."""
    if not request:
        return ''
    ua = request.META.get('HTTP_USER_AGENT') or ''
    return ua[:512]


def _device_id(user, ip, user_agent):
    """Stable id for same user + IP + UA combo."""
    raw = f'{user.pk}|{ip or ""}|{user_agent[:200]}'
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def compute_device_fingerprint(user, request):
    """Public helper: same fingerprint used by Device rows after login."""
    ip = get_client_ip(request)
    ua = get_user_agent(request)
    return _device_id(user, ip, ua)


def is_new_device_for_alert_roles(user, request):
    """
    True for 2IC/Employee when login fingerprint is new (excluding blocked rows).
    First-ever login is not treated as "new device" to avoid noisy alerts.
    """
    from .models import Device, DeviceStatus, Role

    if user.role not in (Role.TWOIC, Role.EMPLOYEE):
        return False
    qs = Device.objects.filter(user=user).exclude(status=DeviceStatus.BLOCKED)
    if not qs.exists():
        return False
    fp = compute_device_fingerprint(user, request)
    return not qs.filter(device_id=fp).exists()


def evaluate_device_login_policy(user, request):
    """
    Decide whether a login from this fingerprint is allowed.

    Returns tuple: (decision, device, is_new_device)
      - decision: 'allow' | 'pending_approval' | 'blocked'
      - device: matching/created Device row or None
      - is_new_device: True only when this call created a brand-new pending device
    Policy applies to 2IC and Employee only.
    """
    from .models import Role

    if user.role not in (Role.TWOIC, Role.EMPLOYEE):
        return ('allow', None, False)

    ip = get_client_ip(request)
    ua = get_user_agent(request)
    fp = _device_id(user, ip, ua)
    existing = Device.objects.filter(user=user, device_id=fp).first()
    if existing:
        if existing.status == DeviceStatus.BLOCKED:
            return ('blocked', existing, False)
        if existing.status == DeviceStatus.APPROVED:
            return ('allow', existing, False)
        return ('pending_approval', existing, False)

    # First-ever device for the account: auto-approve to avoid lockout on first login.
    has_any_non_blocked = Device.objects.filter(user=user).exclude(status=DeviceStatus.BLOCKED).exists()
    if not has_any_non_blocked:
        device = Device.objects.create(
            user=user,
            device_id=fp,
            user_agent=ua,
            ip_address=ip,
            status=DeviceStatus.APPROVED,
        )
        return ('allow', device, False)

    # Known account, unknown device: require superadmin approval.
    device = Device.objects.create(
        user=user,
        device_id=fp,
        user_agent=ua,
        ip_address=ip,
        status=DeviceStatus.PENDING,
    )
    return ('pending_approval', device, True)


def is_new_device_for_employee(user, request):
    """Backward-compatible wrapper for older call sites."""
    return is_new_device_for_alert_roles(user, request)


def record_device(user, request):
    """After successful login: create or update Device; set first_seen/last_seen."""
    ip = get_client_ip(request)
    ua = get_user_agent(request)
    device_id = _device_id(user, ip, ua)
    device, created = Device.objects.get_or_create(
        user=user,
        device_id=device_id,
        defaults={
            'user_agent': ua,
            'ip_address': ip,
            'status': DeviceStatus.PENDING,
        },
    )
    if not created:
        device.user_agent = ua
        device.ip_address = ip
        device.last_seen = timezone.now()
        device.save(update_fields=['user_agent', 'ip_address', 'last_seen'])
    return device


def log_audit_event(action, request=None, user=None, details=None):
    """Persist an audit event. user can be None for failed login."""
    if user is None and request and getattr(request, 'user', None) and request.user.is_authenticated:
        user = request.user
    ip = get_client_ip(request) if request else None
    ua = get_user_agent(request) if request else ''
    detail_str = ''
    if details is not None:
        if isinstance(details, dict):
            import json
            detail_str = json.dumps(details)
        else:
            detail_str = str(details)
    AuditEvent.objects.create(
        user=user,
        action=action,
        ip_address=ip,
        user_agent=ua,
        details=detail_str,
    )
