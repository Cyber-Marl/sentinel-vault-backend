"""
SentinelVault — RBAC Permission Classes
Domain 3 (Access Control) implementation using Django REST Framework's BasePermission.
"""

from rest_framework.permissions import BasePermission
from .models import Role


class IsAdmin(BasePermission):
    """
    Allows access only to users with the ADMIN role.
    Used for: user management, audit log access, system configuration.
    """
    message = "Access denied. Administrator privileges required."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == Role.ADMIN
        )


class IsManagerOrAbove(BasePermission):
    """
    Allows access to users with ADMIN or MANAGER role.
    Used for: document upload, document management operations.
    """
    message = "Access denied. Manager or Administrator privileges required."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role in (Role.ADMIN, Role.MANAGER)
        )


class IsOwnerOrAdmin(BasePermission):
    """
    Object-level permission: only the object's owner or an Admin can access it.
    The object must have an 'owner' attribute (ForeignKey to User).

    Access matrix:
        ADMIN   → Full access to all objects
        MANAGER → Access to own objects only
        VIEWER  → Access to own objects only
    """
    message = "Access denied. You can only access your own resources."

    def has_object_permission(self, request, view, obj):
        if request.user.role == Role.ADMIN:
            return True
        # Check ownership — the object must have an 'owner' field
        return hasattr(obj, 'owner') and obj.owner == request.user
