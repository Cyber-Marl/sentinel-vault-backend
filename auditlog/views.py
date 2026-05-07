"""
SentinelVault — Audit Log Views
Admin-only access to the immutable audit trail.
Supports filtering by user, action, date range.
"""
from rest_framework import generics
from django_filters import rest_framework as filters
from accounts.permissions import IsAdmin
from .models import AuditLog
from .serializers import AuditLogSerializer


class AuditLogFilter(filters.FilterSet):
    """Filter audit logs by action, user, resource type, and date range."""
    start_date = filters.DateTimeFilter(field_name='timestamp', lookup_expr='gte')
    end_date = filters.DateTimeFilter(field_name='timestamp', lookup_expr='lte')
    user_email = filters.CharFilter(field_name='user__email', lookup_expr='icontains')

    class Meta:
        model = AuditLog
        fields = ['action', 'resource_type', 'user', 'user_email', 'start_date', 'end_date']


class AuditLogListView(generics.ListAPIView):
    """
    GET /api/audit-logs/
    Admin-only. Returns paginated, filterable audit log entries.
    No create/update/delete endpoints — audit logs are immutable.
    """
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdmin]
    filterset_class = AuditLogFilter
    ordering_fields = ['timestamp', 'action']
    ordering = ['-timestamp']

    def get_queryset(self):
        return AuditLog.objects.all().select_related('user')
