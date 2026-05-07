"""SentinelVault — AuditLog Serializer (read-only)"""
from rest_framework import serializers
from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    """Read-only serializer for audit log entries. Includes nested user info."""
    user_email = serializers.EmailField(source='user.email', read_only=True, default='Anonymous')
    user_role = serializers.CharField(source='user.role', read_only=True, default='N/A')

    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'user_email', 'user_role', 'action',
            'resource_type', 'resource_id', 'ip_address',
            'user_agent', 'timestamp', 'details',
        ]
        read_only_fields = fields
