"""Rate limiting for login (Phase 6). Escalating lockout: 30s → 1m → 30m → 24h → 1 month. User/Admin auto-deleted after 3 failures."""
import time

from django.conf import settings
from django.core.cache import cache

# After this many failed attempts, apply lockout (and delete User/Admin account)
LOGIN_RATELIMIT_COUNT = 3

# Escalating lockout durations (seconds): 1st lockout, 2nd, 3rd, 4th, 5th+
LOCKOUT_DURATIONS = [
    30,                    # 30 seconds
    60,                    # 1 minute
    30 * 60,               # 30 minutes
    24 * 60 * 60,          # 24 hours
    30 * 24 * 60 * 60,     # 1 month (30 days)
]
LEVEL_CACHE_TIMEOUT = 31 * 24 * 60 * 60  # 31 days so level persists

CACHE_KEY_IP_LOCK = 'rl_login_lock_ip:%s'
CACHE_KEY_IP_LOCK_UNTIL = 'rl_login_lock_until_ip:%s'
CACHE_KEY_IP_LEVEL = 'rl_login_level_ip:%s'
CACHE_KEY_IP_COUNT = 'rl_login_count_ip:%s'
CACHE_KEY_USER_LOCK = 'rl_login_lock_user:%s'
CACHE_KEY_USER_LOCK_UNTIL = 'rl_login_lock_until_user:%s'
CACHE_KEY_USER_LEVEL = 'rl_login_level_user:%s'
CACHE_KEY_USER_COUNT = 'rl_login_count_user:%s'
COUNT_CACHE_TIMEOUT = 900  # 15 min window for counting failures


def _get_ip(request):
    if not request:
        return None
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _format_remaining(seconds):
    """Human-readable remaining time."""
    if seconds <= 0:
        return 'a moment'
    if seconds < 60:
        return f'{int(seconds)} second{"s" if seconds != 1 else ""}'
    if seconds < 3600:
        m = max(1, int(round(seconds / 60)))
        return f'{m} minute{"s" if m != 1 else ""}'
    if seconds < 86400:
        h = max(1, int(round(seconds / 3600)))
        return f'{h} hour{"s" if h != 1 else ""}'
    if seconds < 2592000:  # 30 days
        d = max(1, int(round(seconds / 86400)))
        return f'{d} day{"s" if d != 1 else ""}'
    mo = max(1, int(round(seconds / 2592000)))
    return f'{mo} month{"s" if mo != 1 else ""}'


def _get_lock_message(until_key):
    """Get 'Try again in X' message from lock-until key."""
    until = cache.get(until_key)
    if until is None:
        return 'Too many failed attempts. Try again later.'
    remaining = max(0, int(until - time.time()))
    return f'Too many failed attempts. Try again in {_format_remaining(remaining)}.'


def is_login_blocked(request, username=None):
    """Return (blocked: bool, message: str). Message includes remaining time when blocked."""
    if getattr(settings, 'DISABLE_LOGIN_RATE_LIMIT', False):
        return False, ''
    ip = _get_ip(request)
    if ip:
        key_lock = CACHE_KEY_IP_LOCK % ip
        if cache.get(key_lock):
            return True, _get_lock_message(CACHE_KEY_IP_LOCK_UNTIL % ip)
    if username:
        key_user_lock = CACHE_KEY_USER_LOCK % username.lower()
        if cache.get(key_user_lock):
            return True, _get_lock_message(CACHE_KEY_USER_LOCK_UNTIL % username.lower())
    return False, ''


def _maybe_delete_account_after_failures(request, username):
    """If this is the 3rd failure for this username and account is User or Admin, delete the account. Returns True if deleted."""
    from django.contrib.auth import get_user_model
    from .models import Role
    from .audit import log_audit_event

    User = get_user_model()
    user = User.objects.filter(username__iexact=username).first()
    if not user:
        return False
    if user.role not in (Role.ADMIN, Role.USER):
        return False
    log_audit_event(
        'ACCOUNT_DELETED_FAILED_LOGINS',
        request=request,
        user=user,
        details={'reason': '3_failed_login_attempts', 'username': user.username},
    )
    user.delete()
    return True


def _apply_lockout(ip=None, username=None):
    """Apply escalating lockout for IP and/or username. Returns duration used (seconds)."""
    duration = 0
    if ip:
        key_level = CACHE_KEY_IP_LEVEL % ip
        key_lock = CACHE_KEY_IP_LOCK % ip
        key_until = CACHE_KEY_IP_LOCK_UNTIL % ip
        level = cache.get(key_level, 0)
        duration = LOCKOUT_DURATIONS[min(level, len(LOCKOUT_DURATIONS) - 1)]
        cache.set(key_lock, 1, duration)
        cache.set(key_until, int(time.time()) + duration, duration + 60)
        cache.set(key_level, min(level + 1, len(LOCKOUT_DURATIONS) - 1), LEVEL_CACHE_TIMEOUT)
    if username:
        key_level = CACHE_KEY_USER_LEVEL % username.lower()
        key_lock = CACHE_KEY_USER_LOCK % username.lower()
        key_until = CACHE_KEY_USER_LOCK_UNTIL % username.lower()
        level = cache.get(key_level, 0)
        duration = LOCKOUT_DURATIONS[min(level, len(LOCKOUT_DURATIONS) - 1)]
        cache.set(key_lock, 1, duration)
        cache.set(key_until, int(time.time()) + duration, duration + 60)
        cache.set(key_level, min(level + 1, len(LOCKOUT_DURATIONS) - 1), LEVEL_CACHE_TIMEOUT)
    return duration


def record_login_failure(request, username=None):
    """Call on each failed login. After 3 failures: escalating lockout (30s → 1m → 30m → 24h → 1 month) and User/Admin account deleted. Returns True if account was deleted."""
    if getattr(settings, 'DISABLE_LOGIN_RATE_LIMIT', False):
        return False
    account_deleted = False
    ip = _get_ip(request)
    ip_hit = username_hit = False
    if ip:
        key_count = CACHE_KEY_IP_COUNT % ip
        count = cache.get(key_count, 0) + 1
        cache.set(key_count, count, COUNT_CACHE_TIMEOUT)
        if count >= LOGIN_RATELIMIT_COUNT:
            ip_hit = True
    if username:
        key_count = CACHE_KEY_USER_COUNT % username.lower()
        count = cache.get(key_count, 0) + 1
        cache.set(key_count, count, COUNT_CACHE_TIMEOUT)
        if count >= LOGIN_RATELIMIT_COUNT:
            username_hit = True
            account_deleted = _maybe_delete_account_after_failures(request, username)
    if ip_hit or username_hit:
        _apply_lockout(ip=ip if ip_hit else None, username=username if username_hit else None)
    return account_deleted


# ---------- Employee PDF gate brute-force protection ----------

# Gate is the "Access code" screen to open an encrypted order PDF in the browser.
# Protects against repeated guessing of that code (brute force).
GATE_RATELIMIT_COUNT = 5
GATE_COUNT_CACHE_TIMEOUT = 900  # 15 minutes

# Lockout keys (ip + per-employee+order)
CACHE_KEY_GATE_IP_LOCK = 'rl_gate_lock_ip:%s'
CACHE_KEY_GATE_IP_LOCK_UNTIL = 'rl_gate_lock_until_ip:%s'
CACHE_KEY_GATE_IP_LEVEL = 'rl_gate_level_ip:%s'
CACHE_KEY_GATE_IP_COUNT = 'rl_gate_count_ip:%s'

CACHE_KEY_GATE_USER_ORDER_LOCK = 'rl_gate_lock_uo:%s:%s'
CACHE_KEY_GATE_USER_ORDER_LOCK_UNTIL = 'rl_gate_lock_until_uo:%s:%s'
CACHE_KEY_GATE_USER_ORDER_LEVEL = 'rl_gate_level_uo:%s:%s'
CACHE_KEY_GATE_USER_ORDER_COUNT = 'rl_gate_count_uo:%s:%s'


def _gate_lock_message(until_key: str) -> str:
    """Message used for gate lockouts."""
    until = cache.get(until_key)
    if until is None:
        return 'Too many invalid access code attempts. Try again later.'
    remaining = max(0, int(until - time.time()))
    return f'Too many invalid access code attempts. Try again in {_format_remaining(remaining)}.'


def is_gate_blocked(request, user, order_id):
    """
    Return (blocked: bool, message: str) for the employee PDF access-code gate.
    Locks out on repeated failures per (IP) and per (user+order).
    """
    if getattr(settings, 'DISABLE_LOGIN_RATE_LIMIT', False):
        return False, ''

    ip = _get_ip(request)
    user_pk = getattr(user, 'pk', None)

    if ip:
        lock_key = CACHE_KEY_GATE_IP_LOCK % ip
        if cache.get(lock_key):
            return True, _gate_lock_message(CACHE_KEY_GATE_IP_LOCK_UNTIL % ip)

    if user_pk is not None:
        lock_key = CACHE_KEY_GATE_USER_ORDER_LOCK % (user_pk, order_id)
        if cache.get(lock_key):
            return True, _gate_lock_message(CACHE_KEY_GATE_USER_ORDER_LOCK_UNTIL % (user_pk, order_id))

    return False, ''


def _apply_gate_lockout(ip=None, user_pk=None, order_id=None):
    """Escalating lockout for gate failures."""
    if ip:
        level_key = CACHE_KEY_GATE_IP_LEVEL % ip
        lock_key = CACHE_KEY_GATE_IP_LOCK % ip
        until_key = CACHE_KEY_GATE_IP_LOCK_UNTIL % ip
        level = cache.get(level_key, 0)
        duration = LOCKOUT_DURATIONS[min(level, len(LOCKOUT_DURATIONS) - 1)]
        cache.set(lock_key, 1, duration)
        cache.set(until_key, int(time.time()) + duration, duration + 60)
        cache.set(level_key, min(level + 1, len(LOCKOUT_DURATIONS) - 1), LEVEL_CACHE_TIMEOUT)

    if user_pk is not None and order_id is not None:
        level_key = CACHE_KEY_GATE_USER_ORDER_LEVEL % (user_pk, order_id)
        lock_key = CACHE_KEY_GATE_USER_ORDER_LOCK % (user_pk, order_id)
        until_key = CACHE_KEY_GATE_USER_ORDER_LOCK_UNTIL % (user_pk, order_id)
        level = cache.get(level_key, 0)
        duration = LOCKOUT_DURATIONS[min(level, len(LOCKOUT_DURATIONS) - 1)]
        cache.set(lock_key, 1, duration)
        cache.set(until_key, int(time.time()) + duration, duration + 60)
        cache.set(level_key, min(level + 1, len(LOCKOUT_DURATIONS) - 1), LEVEL_CACHE_TIMEOUT)


def record_gate_failure(request, user, order_id):
    """
    Call on each failed gate attempt.
    After GATE_RATELIMIT_COUNT failures, apply escalating lockout.
    """
    if getattr(settings, 'DISABLE_LOGIN_RATE_LIMIT', False):
        return False

    ip = _get_ip(request)
    user_pk = getattr(user, 'pk', None)

    ip_hit = False
    user_order_hit = False

    if ip:
        count_key = CACHE_KEY_GATE_IP_COUNT % ip
        count = cache.get(count_key, 0) + 1
        cache.set(count_key, count, GATE_COUNT_CACHE_TIMEOUT)
        if count >= GATE_RATELIMIT_COUNT:
            ip_hit = True

    if user_pk is not None:
        count_key = CACHE_KEY_GATE_USER_ORDER_COUNT % (user_pk, order_id)
        count = cache.get(count_key, 0) + 1
        cache.set(count_key, count, GATE_COUNT_CACHE_TIMEOUT)
        if count >= GATE_RATELIMIT_COUNT:
            user_order_hit = True

    if ip_hit or user_order_hit:
        _apply_gate_lockout(
            ip=ip if ip_hit else None,
            user_pk=user_pk if user_order_hit else None,
            order_id=order_id if user_order_hit else None,
        )

    return ip_hit or user_order_hit


def clear_gate_ratelimit(request, user, order_id):
    """Clear gate failure counters/locks for (user+order) and IP."""
    ip = _get_ip(request)
    user_pk = getattr(user, 'pk', None)

    keys = []
    if ip:
        keys.extend([
            CACHE_KEY_GATE_IP_LOCK % ip,
            CACHE_KEY_GATE_IP_LOCK_UNTIL % ip,
            CACHE_KEY_GATE_IP_LEVEL % ip,
            CACHE_KEY_GATE_IP_COUNT % ip,
        ])

    if user_pk is not None:
        keys.extend([
            CACHE_KEY_GATE_USER_ORDER_LOCK % (user_pk, order_id),
            CACHE_KEY_GATE_USER_ORDER_LOCK_UNTIL % (user_pk, order_id),
            CACHE_KEY_GATE_USER_ORDER_LEVEL % (user_pk, order_id),
            CACHE_KEY_GATE_USER_ORDER_COUNT % (user_pk, order_id),
        ])

    cache.delete_many(keys)
