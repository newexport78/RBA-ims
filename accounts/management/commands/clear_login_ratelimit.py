"""Clear login rate limit (lockout) so users can try again. Use after too many failed attempts."""
from django.core.cache import cache
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Clear login rate limit so locked-out users can try again.'

    def handle(self, *args, **options):
        cache.clear()
        self.stdout.write(self.style.SUCCESS('Login rate limit cleared. You can try logging in again.'))
