"""
Recompute Device.device_id after fingerprint normalization (e.g. ::ffff: IPv4 mapping).

Run once on server after deploying IP normalization, then users keep existing approvals.

  python manage.py rehash_device_fingerprints
"""
from django.core.management.base import BaseCommand

from accounts.audit import _device_id
from accounts.models import Device


class Command(BaseCommand):
    help = 'Recompute device_id from stored user, ip_address, and user_agent (safe to re-run).'

    def handle(self, *args, **options):
        updated = 0
        skipped = 0
        unchanged = 0
        for d in Device.objects.select_related('user').order_by('pk').iterator():
            new_id = _device_id(d.user, d.ip_address or '', d.user_agent or '')
            if new_id == d.device_id:
                unchanged += 1
                continue
            if Device.objects.filter(user_id=d.user_id, device_id=new_id).exclude(pk=d.pk).exists():
                self.stdout.write(self.style.WARNING(f'Skip pk={d.pk} user={d.user_id}: device_id collision'))
                skipped += 1
                continue
            d.device_id = new_id
            d.save(update_fields=['device_id'])
            updated += 1
        self.stdout.write(
            self.style.SUCCESS(
                f'Done. updated={updated} unchanged={unchanged} skipped_collision={skipped}'
            )
        )
