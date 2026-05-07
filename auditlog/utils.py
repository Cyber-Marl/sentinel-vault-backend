"""
SentinelVault — Audit Log Utility
Centralized helper for creating audit log entries from any view.
"""
import logging
from .models import AuditLog

logger = logging.getLogger('sentinelvault')


def create_audit_log(user, action, resource_type, resource_id=None,
                     ip_address='0.0.0.0', user_agent='', details=None):
    """
    Create an immutable audit log entry.

    Args:
        user: The User instance (or None for anonymous/failed actions).
        action: One of AuditLog.Action choices.
        resource_type: String like 'Document', 'Authentication'.
        resource_id: Optional string ID of the affected resource.
        ip_address: Client IP address.
        user_agent: Client User-Agent string.
        details: Optional dict of extra context (never include secrets).
    """
    try:
        entry = AuditLog.objects.create(
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {},
        )
        logger.info(
            f"AUDIT: {action} on {resource_type}"
            f"{f' ({resource_id})' if resource_id else ''} "
            f"by {user.email if user else 'Anonymous'} "
            f"from {ip_address}"
        )
        return entry
    except Exception as e:
        logger.error(f"AUDIT_ERROR: Failed to create audit log — {e}")
        return None
