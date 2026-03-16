"""
Create the initial superadmin. Usage:
  python manage.py create_superadmin
  python manage.py create_superadmin --username sa --email sa@example.com
"""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from accounts.models import Role

User = get_user_model()


class Command(BaseCommand):
    help = 'Create the initial superadmin account (no public signup).'

    def add_arguments(self, parser):
        parser.add_argument('--username', default='superadmin', help='Username for superadmin')
        parser.add_argument('--email', required=True, help='Email for superadmin (receives OTP)')
        parser.add_argument('--password', default=None, help='Initial password (prompted if not given)')

    def handle(self, *args, **options):
        username = (options['username'] or 'superadmin').strip()
        email = (options['email'] or '').strip().lower()
        if not email:
            self.stderr.write(self.style.ERROR('Email is required (e.g. --email admin@example.com)'))
            return

        if User.objects.filter(username__iexact=username).exists():
            self.stdout.write(self.style.WARNING(f'User "{username}" already exists. Skipping.'))
            return

        password = options.get('password')
        if not password:
            from getpass import getpass
            password = getpass('Initial password for superadmin: ')
            if not password:
                self.stderr.write(self.style.ERROR('Password cannot be empty.'))
                return

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            role=Role.SUPERADMIN,
            is_staff=True,
            is_superuser=True,
            is_active=True,
        )
        self.stdout.write(self.style.SUCCESS(f'Superadmin created: {user.username} ({user.email})'))
