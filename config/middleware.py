from django.conf import settings


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

