from django.conf import settings
from django.db import models


class Order(models.Model):
    """Order created by an admin: title, description, due date, PDF. Assigned to users via OrderAssignment."""
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    due_date = models.DateField(null=True, blank=True)
    pdf_file = models.FileField(upload_to='orders/%Y/%m/', blank=True)  # store with safe path
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_orders',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'orders_order'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['created_by', '-created_at']),
        ]

    def __str__(self):
        return self.title


class AssignmentStatus(models.TextChoices):
    SENT = 'sent', 'Sent'
    VIEWED = 'viewed', 'Viewed'
    IN_PROGRESS = 'in_progress', 'In progress'
    COMPLETED = 'completed', 'Completed'


class OrderAssignment(models.Model):
    """Per-user assignment of an order. Tracks viewed_at; progress (Phase 4) will update status."""
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='assignments')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='order_assignments')
    status = models.CharField(
        max_length=20,
        choices=AssignmentStatus.choices,
        default=AssignmentStatus.SENT,
    )
    viewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'orders_orderassignment'
        unique_together = [('order', 'user')]
        ordering = ['user__username']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['order', 'status']),
        ]

    def __str__(self):
        return f'{self.order.title} → {self.user.username}'


class ProgressSubmission(models.Model):
    """User's progress submission for an order: notes + optional PDF. One assignment can have many submissions."""
    assignment = models.ForeignKey(
        OrderAssignment,
        on_delete=models.CASCADE,
        related_name='progress_submissions',
    )
    notes = models.TextField(blank=True)
    file = models.FileField(upload_to='progress/%Y/%m/', blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'orders_progresssubmission'
        ordering = ['-submitted_at']

    def __str__(self):
        return f'{self.assignment.order.title} by {self.assignment.user.username} at {self.submitted_at}'

    @property
    def file_name(self):
        return self.file.name and self.file.name.split('/')[-1] or '—'


class UserDocument(models.Model):
    """Independent PDF upload by a user — not tied to any order. Like orders from admin, but user-uploaded."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='uploaded_documents',
    )
    recipient_admin = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='received_user_documents',
        help_text='Admin this document is sent to.',
    )
    file = models.FileField(upload_to='user_documents/%Y/%m/')
    notes = models.TextField(blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'orders_userdocument'
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['recipient_admin', '-uploaded_at']),
        ]

    def __str__(self):
        return f'{self.file.name} by {self.user.username} at {self.uploaded_at}'

    @property
    def file_name(self):
        return self.file.name and self.file.name.split('/')[-1] or '—'
