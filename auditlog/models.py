"""
SentinelVault — AuditLog Model (Domain 5: Audit Logging)
Immutable log of every CRUD operation in the system.
Records: User_ID, Action, Timestamp, IP_Address, and contextual details.
"""
import uuid
from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """
    Immutable audit trail entry.
    No update or delete endpoints are exposed — audit logs are append-only.
    """
    class Action(models.TextChoices):
        CREATE = 'CREATE', 'Created'
        READ = 'READ', 'Retrieved'
        UPDATE = 'UPDATE', 'Updated'
        DELETE = 'DELETE', 'Deleted'
        DOWNLOAD = 'DOWNLOAD', 'Downloaded'
        LOGIN = 'LOGIN', 'Logged In'
        LOGIN_FAILED = 'LOGIN_FAILED', 'Login Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='audit_logs',
        help_text="User who performed the action (null for failed logins)."
    )
    action = models.CharField(max_length=20, choices=Action.choices, db_index=True)
    resource_type = models.CharField(
        max_length=50,
        help_text="Type of resource (e.g., Document, Authentication)."
    )
    resource_id = models.CharField(
        max_length=100, null=True, blank=True,
        help_text="ID of the affected resource."
    )
    ip_address = models.GenericIPAddressField(
        help_text="Client IP address at the time of the action."
    )
    user_agent = models.TextField(
        blank=True, default='',
        help_text="Client User-Agent header."
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    details = models.JSONField(
        default=dict, blank=True,
        help_text="Additional context (filenames, hashes, etc.). Never store secrets."
    )

    class Meta:
        db_table = 'sentinel_audit_logs'
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp'], name='idx_audit_user_time'),
            models.Index(fields=['action', '-timestamp'], name='idx_audit_action_time'),
            models.Index(fields=['resource_type', 'resource_id'], name='idx_audit_resource'),
        ]

    def __str__(self):
        user_str = self.user.email if self.user else 'Anonymous'
        return f"[{self.timestamp}] {user_str} — {self.action} {self.resource_type}"
