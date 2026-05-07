"""
SentinelVault — Custom User Model
Implements Domain 3 (Access Control) with role-based authorization.
Three roles: Admin, Manager, Viewer — following the Principle of Least Privilege.
"""

import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models


class Role(models.TextChoices):
    """
    Role hierarchy for RBAC:
        ADMIN   — Full system access. Can manage users, documents, and audit logs.
        MANAGER — Can upload, view, and manage documents. Cannot manage users.
        VIEWER  — Read-only access to documents they own or are shared with.
    """
    ADMIN = 'ADMIN', 'Admin'
    MANAGER = 'MANAGER', 'Manager'
    VIEWER = 'VIEWER', 'Viewer'


class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    Uses email as the primary login identifier instead of username.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the user (UUIDv4)."
    )
    email = models.EmailField(
        unique=True,
        db_index=True,
        help_text="Email address used for authentication."
    )
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.VIEWER,
        db_index=True,
        help_text="User's role determining access level."
    )

    # Use email as the login field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    class Meta:
        db_table = 'sentinel_users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"

    @property
    def is_admin(self):
        return self.role == Role.ADMIN

    @property
    def is_manager(self):
        return self.role == Role.MANAGER

    @property
    def is_viewer(self):
        return self.role == Role.VIEWER

    @property
    def is_manager_or_above(self):
        return self.role in (Role.ADMIN, Role.MANAGER)
