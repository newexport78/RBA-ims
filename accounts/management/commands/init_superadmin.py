import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from accounts.models import Role


class Command(BaseCommand):
    help = "Create initial superadmin user from environment variables if none exists."

    def handle(self, *args, **options):
        User = get_user_model()

        if User.objects.filter(role=Role.SUPERADMIN).exists():
            self.stdout.write(self.style.SUCCESS("Superadmin already exists; skipping."))
            return

        username = os.environ.get("SUPERADMIN_USERNAME", "superadmin")
        email = os.environ.get("SUPERADMIN_EMAIL", "").strip().lower()
        password = os.environ.get("SUPERADMIN_PASSWORD", "")

        if not email:
            self.stderr.write(self.style.ERROR("SUPERADMIN_EMAIL is required in environment."))
            return
        if not password:
            self.stderr.write(self.style.ERROR("SUPERADMIN_PASSWORD is required in environment."))
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
        self.stdout.write(self.style.SUCCESS(f"Superadmin created: {user.username} ({user.email})"))

