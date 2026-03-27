from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User, OTP


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'role', 'is_active', 'is_approved', 'last_login')
    list_filter = ('role', 'is_active', 'is_approved')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('username',)
    filter_horizontal = ()
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Role', {'fields': ('role', 'is_approved', 'force_password_change')}),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        (None, {'fields': ('email', 'role')}),
    )


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'created_at', 'expires_at', 'used_at')
    list_filter = ('created_at',)
    search_fields = ('user__username',)
