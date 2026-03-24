import json
import os

from django.conf import settings


class CloudflareForwardedProtoMiddleware:
    """
    Cloudflare (SSL Flexible) → ALB often forwards HTTP to the task with
    X-Forwarded-Proto: http. The browser still uses https:// on your domain,
    so Django thinks the request is insecure and CSRF / cookie handling breaks.

    Cloudflare sends CF-Visitor: {"scheme":"https"}. Normalize proto for Django.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw = request.META.get("HTTP_CF_VISITOR")
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict) and data.get("scheme") == "https":
                    request.META = request.META.copy()
                    request.META["HTTP_X_FORWARDED_PROTO"] = "https"
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        return self.get_response(request)


class AlbHealthCheckHostMiddleware:
    """
    AWS ALB default health checks use Host: <target private IP>. Django then
    returns 400 DisallowedHost before /health/ runs. For /health/ only, set
    Host to a value in ALLOWED_HOSTS so ECS + target group health checks pass.

    Optional env: HEALTH_CHECK_HOST=rbac-ims.com (otherwise first non-wildcard ALLOWED_HOSTS).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if path in ('/health', '/health/'):
            host = os.environ.get('HEALTH_CHECK_HOST', '').strip()
            if not host:
                for h in getattr(settings, 'ALLOWED_HOSTS', ()):
                    hs = (h or '').strip()
                    if hs and '*' not in hs:
                        host = hs
                        break
            if host:
                request.META = request.META.copy()
                request.META['HTTP_HOST'] = host
        return self.get_response(request)


class SecurityHeadersMiddleware:
    """
    Add common security headers (HSTS, CSP, cache-control) without changing UI.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Only add strict transport security when not in DEBUG and over HTTPS.
        if not settings.DEBUG:
            response.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
            )

        # Basic CSP: allow this origin and inline resources (for existing JS/CSS).
        # This is intentionally permissive to avoid breaking current UI while
        # still providing protection against some injection vectors.
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.setdefault("Content-Security-Policy", csp)

        # Tighten caching for authenticated responses.
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            cache_control = response.get("Cache-Control", "").lower()
            if "no-store" not in cache_control:
                response["Cache-Control"] = (
                    "no-store, no-cache, must-revalidate, max-age=0"
                )
                response["Pragma"] = "no-cache"
                response["Expires"] = "0"

        # Additional helpful headers.
        response.setdefault("Referrer-Policy", "same-origin")
        response.setdefault("X-Content-Type-Options", "nosniff")

        return response

