"""
SentinelVault — Document Model
Stores metadata for encrypted documents including the SHA-256 integrity hash.
The actual file is stored encrypted in media/encrypted_documents/.
"""

import uuid
from django.conf import settings
from django.db import models


class Document(models.Model):
    """
    Represents an encrypted document in SentinelVault.

    Security properties:
        - encrypted_file: The file on disk is Fernet-encrypted (AES-128-CBC + HMAC-SHA256).
        - file_hash: SHA-256 hash of the ORIGINAL (unencrypted) file for integrity verification.
        - owner: Foreign key to the uploading user (access control).
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique document identifier (UUIDv4)."
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='documents',
        help_text="User who uploaded this document."
    )
    title = models.CharField(
        max_length=255,
        help_text="Human-readable document title."
    )
    description = models.TextField(
        blank=True,
        default='',
        help_text="Optional description of the document."
    )
    original_filename = models.CharField(
        max_length=255,
        help_text="Original filename as uploaded by the user."
    )
    encrypted_file = models.FileField(
        upload_to='encrypted_documents/',
        help_text="Path to the Fernet-encrypted file on disk."
    )
    file_hash = models.CharField(
        max_length=64,
        help_text="SHA-256 hex digest of the ORIGINAL (unencrypted) file."
    )
    file_size = models.PositiveIntegerField(
        help_text="Size of the original (unencrypted) file in bytes."
    )
    content_type = models.CharField(
        max_length=100,
        help_text="MIME type of the original file (e.g., application/pdf)."
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Soft-delete flag. Inactive documents are hidden from listings."
    )
    uploaded_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when the document was first uploaded."
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp of the last metadata update."
    )

    class Meta:
        db_table = 'sentinel_documents'
        verbose_name = 'Document'
        verbose_name_plural = 'Documents'
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['owner', '-uploaded_at'], name='idx_doc_owner_date'),
            models.Index(fields=['file_hash'], name='idx_doc_hash'),
        ]

    def __str__(self):
        return f"{self.title} ({self.original_filename}) — {self.owner.email}"

    @property
    def file_size_display(self):
        """Human-readable file size."""
        size = self.file_size
        for unit in ('B', 'KB', 'MB', 'GB'):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
