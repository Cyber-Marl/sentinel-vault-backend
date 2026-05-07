"""
SentinelVault — Document Serializers
Handles file upload validation, document metadata serialization,
and secure download URL generation.
"""

from django.conf import settings
from rest_framework import serializers
from .models import Document


class DocumentUploadSerializer(serializers.Serializer):
    """
    Serializer for file upload requests.
    Validates file size and content type before encryption.
    The actual file processing (encryption, hashing) happens in the view.
    """
    title = serializers.CharField(
        max_length=255,
        help_text="Document title."
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text="Optional document description."
    )
    file = serializers.FileField(
        help_text="The file to upload (max 25 MB)."
    )

    def validate_file(self, value):
        """
        Security validations:
        1. Check file size against MAX_UPLOAD_SIZE
        2. Check content type against ALLOWED_FILE_TYPES allowlist
        """
        # Validate file size
        max_size = getattr(settings, 'MAX_UPLOAD_SIZE', 25 * 1024 * 1024)
        if value.size > max_size:
            max_mb = max_size / (1024 * 1024)
            raise serializers.ValidationError(
                f"File size ({value.size / (1024 * 1024):.1f} MB) exceeds "
                f"the maximum allowed size of {max_mb:.0f} MB."
            )

        # Validate content type against allowlist
        allowed_types = getattr(settings, 'ALLOWED_FILE_TYPES', [])
        if allowed_types and value.content_type not in allowed_types:
            raise serializers.ValidationError(
                f"File type '{value.content_type}' is not allowed. "
                f"Permitted types: {', '.join(allowed_types)}"
            )

        return value


class DocumentListSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for document listings.
    Returns metadata only — no file content or download URLs.
    """
    owner_email = serializers.EmailField(source='owner.email', read_only=True)
    file_size_display = serializers.CharField(read_only=True)

    class Meta:
        model = Document
        fields = [
            'id', 'title', 'description', 'original_filename',
            'file_size', 'file_size_display', 'content_type',
            'owner_email', 'uploaded_at', 'updated_at',
        ]
        read_only_fields = fields


class DocumentDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for a single document.
    Includes the file hash for client-side integrity verification.
    """
    owner_email = serializers.EmailField(source='owner.email', read_only=True)
    owner_name = serializers.SerializerMethodField()
    file_size_display = serializers.CharField(read_only=True)
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = Document
        fields = [
            'id', 'title', 'description', 'original_filename',
            'file_size', 'file_size_display', 'content_type',
            'file_hash', 'owner_email', 'owner_name',
            'uploaded_at', 'updated_at', 'download_url',
        ]
        read_only_fields = fields

    def get_owner_name(self, obj):
        return f"{obj.owner.first_name} {obj.owner.last_name}".strip() or obj.owner.username

    def get_download_url(self, obj):
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(f'/api/documents/{obj.id}/download/')
        return None
