"""Custom error handlers (Phase 6/7): log errors, no sensitive detail to users."""
import logging

from django.shortcuts import render
from django.views.defaults import page_not_found as django_page_not_found

logger = logging.getLogger(__name__)


def page_not_found(request, exception):
    """404: custom template; do not leak internals."""
    return django_page_not_found(request, exception, template_name='404.html')


def server_error(request):
    """500: log error, return generic template (no sensitive detail)."""
    logger.error('Server error (500)', exc_info=True)
    return render(request, '500.html', status=500)
