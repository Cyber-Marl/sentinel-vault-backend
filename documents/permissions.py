"""
SentinelVault — Document Permission Classes
Object-level permissions for document access control (Domain 3).
"""

from rest_framework.permissions import BasePermission
from accounts.models import Role


class IsDocumentOwnerOrAdmin(BasePermission):
    """
    Object-level permission for Documents:
        ADMIN   → Full access to all documents
        MANAGER → Read/write access to own documents only
        VIEWER  → Read-only access to own documents only
    """
    message = "Access denied. You do not have permission to access this document."

    def has_object_permission(self, request, view, obj):
        # Admins have unrestricted access
        if request.user.role == Role.ADMIN:
            return True

        # All other roles can only access their own documents
        return obj.owner == request.user


class CanUploadDocuments(BasePermission):
    """
    Only Admins and Managers can upload documents.
    Viewers have read-only access.
    """
    message = "Access denied. Only Managers and Admins can upload documents."

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role in (Role.ADMIN, Role.MANAGER)
        )


class CanDeleteDocuments(BasePermission):
    """
    Only the document owner or an Admin can delete documents.
    Managers cannot delete other users' documents.
    """
    message = "Access denied. Only the document owner or an Admin can delete this document."

    def has_object_permission(self, request, view, obj):
        if request.user.role == Role.ADMIN:
            return True
        return obj.owner == request.user
