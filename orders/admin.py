from django.contrib import admin
from .models import Order, OrderAssignment, ProgressSubmission, UserDocument


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('title', 'created_by', 'created_at', 'due_date')
    list_filter = ('created_at',)
    search_fields = ('title',)
    raw_id_fields = ('created_by',)


@admin.register(OrderAssignment)
class OrderAssignmentAdmin(admin.ModelAdmin):
    list_display = ('order', 'user', 'status', 'viewed_at', 'created_at')
    list_filter = ('status',)
    raw_id_fields = ('order', 'user')


@admin.register(ProgressSubmission)
class ProgressSubmissionAdmin(admin.ModelAdmin):
    list_display = ('assignment', 'submitted_at', 'file', 'notes_preview')
    list_filter = ('submitted_at',)
    raw_id_fields = ('assignment',)

    def notes_preview(self, obj):
        return (obj.notes or '')[:50] + ('...' if len(obj.notes or '') > 50 else '')
    notes_preview.short_description = 'Notes'


@admin.register(UserDocument)
class UserDocumentAdmin(admin.ModelAdmin):
    list_display = ('user', 'uploaded_at', 'file', 'notes_preview')
    list_filter = ('uploaded_at',)
    raw_id_fields = ('user',)

    def notes_preview(self, obj):
        return (obj.notes or '')[:50] + ('...' if len(obj.notes or '') > 50 else '')
    notes_preview.short_description = 'Notes'
