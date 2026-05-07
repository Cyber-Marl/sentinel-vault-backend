"""SentinelVault — Audit Log Admin Configuration"""
from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'resource_type', 'resource_id', 'ip_address')
    list_filter = ('action', 'resource_type', 'timestamp')
    search_fields = ('user__email', 'resource_id', 'ip_address')
    readonly_fields = (
        'id', 'user', 'action', 'resource_type', 'resource_id',
        'ip_address', 'user_agent', 'timestamp', 'details',
    )
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        return False  # Audit logs are created programmatically only

    def has_change_permission(self, request, obj=None):
        return False  # Immutable — no edits allowed

    def has_delete_permission(self, request, obj=None):
        return False  # Immutable — no deletion allowed
