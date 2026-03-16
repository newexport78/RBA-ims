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
