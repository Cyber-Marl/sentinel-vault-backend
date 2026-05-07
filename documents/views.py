"""
SentinelVault — Secure Document Views
Upload (validate->hash->encrypt->store->audit), Download (decrypt->verify->serve),
List, Detail, and soft-Delete.
"""
import logging
from django.core.files.base import ContentFile
from django.http import HttpResponse
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import Role
from .encryption import encrypt_file, decrypt_file
from .hashing import calculate_sha256, verify_integrity
from .models import Document
from .permissions import IsDocumentOwnerOrAdmin, CanUploadDocuments, CanDeleteDocuments
from .serializers import DocumentUploadSerializer, DocumentListSerializer, DocumentDetailSerializer

logger = logging.getLogger('sentinelvault')


def _get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def _create_audit(user, action, resource_id, request, details=None):
    try:
        from auditlog.utils import create_audit_log
        create_audit_log(
            user=user, action=action, resource_type='Document',
            resource_id=str(resource_id) if resource_id else None,
            ip_address=_get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details=details or {},
        )
    except Exception as e:
        logger.error(f"Failed to create audit log: {e}")


class DocumentUploadView(APIView):
    """POST /api/documents/upload/ — Validate, hash, encrypt, store, audit."""
    permission_classes = [IsAuthenticated, CanUploadDocuments]

    def post(self, request):
        serializer = DocumentUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uploaded_file = serializer.validated_data['file']
        title = serializer.validated_data['title']
        description = serializer.validated_data.get('description', '')

        raw_bytes = uploaded_file.read()
        file_hash = calculate_sha256(raw_bytes)
        encrypted_bytes = encrypt_file(raw_bytes)

        encrypted_filename = f"{file_hash[:12]}_{uploaded_file.name}.enc"
        encrypted_content = ContentFile(encrypted_bytes, name=encrypted_filename)

        document = Document.objects.create(
            owner=request.user, title=title, description=description,
            original_filename=uploaded_file.name,
            encrypted_file=encrypted_content, file_hash=file_hash,
            file_size=len(raw_bytes),
            content_type=uploaded_file.content_type or 'application/octet-stream',
        )

        _create_audit(request.user, 'CREATE', document.id, request, {
            'title': title, 'filename': uploaded_file.name,
            'size': len(raw_bytes), 'hash': file_hash,
        })

        logger.info(f"UPLOAD: {request.user.email} uploaded '{uploaded_file.name}'")

        return Response({
            'message': 'Document uploaded and encrypted successfully.',
            'document': DocumentDetailSerializer(document, context={'request': request}).data,
        }, status=status.HTTP_201_CREATED)


class DocumentListView(generics.ListAPIView):
    """GET /api/documents/ — Paginated list. Admin sees all, others see own."""
    serializer_class = DocumentListSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['content_type']
    search_fields = ['title', 'original_filename', 'description']
    ordering_fields = ['uploaded_at', 'title', 'file_size']
    ordering = ['-uploaded_at']

    def get_queryset(self):
        qs = Document.objects.filter(is_active=True)
        if self.request.user.role != Role.ADMIN:
            qs = qs.filter(owner=self.request.user)
        return qs.select_related('owner')


class DocumentDetailView(generics.RetrieveAPIView):
    """GET /api/documents/<uuid:pk>/ — Single document metadata + audit."""
    serializer_class = DocumentDetailSerializer
    permission_classes = [IsAuthenticated, IsDocumentOwnerOrAdmin]
    lookup_field = 'pk'

    def get_queryset(self):
        return Document.objects.filter(is_active=True).select_related('owner')

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        _create_audit(request.user, 'READ', kwargs.get('pk'), request)
        return response


class DocumentDownloadView(APIView):
    """GET /api/documents/<uuid:pk>/download/ — Decrypt, verify integrity, serve."""
    permission_classes = [IsAuthenticated, IsDocumentOwnerOrAdmin]

    def get(self, request, pk):
        try:
            document = Document.objects.get(pk=pk, is_active=True)
        except Document.DoesNotExist:
            return Response({'error': 'Document not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Check object-level permissions
        for perm in self.get_permissions():
            if hasattr(perm, 'has_object_permission'):
                if not perm.has_object_permission(request, self, document):
                    return Response({'error': perm.message}, status=status.HTTP_403_FORBIDDEN)

        # Read encrypted file
        try:
            document.encrypted_file.open('rb')
            encrypted_bytes = document.encrypted_file.read()
            document.encrypted_file.close()
        except FileNotFoundError:
            logger.critical(f"FILE_MISSING: Document {pk}")
            return Response({'error': 'File not found on server.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Decrypt
        try:
            decrypted_bytes = decrypt_file(encrypted_bytes)
        except Exception as e:
            logger.critical(f"DECRYPTION_ERROR: Document {pk} — {e}")
            return Response({'error': 'Decryption failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Verify integrity
        if not verify_integrity(decrypted_bytes, document.file_hash):
            logger.critical(f"INTEGRITY_VIOLATION: Document {pk} — possible tampering!")
            _create_audit(request.user, 'DOWNLOAD', pk, request, {'integrity': 'FAILED'})
            return Response({'error': 'Integrity check failed. File may be tampered.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Serve decrypted file
        response = HttpResponse(decrypted_bytes, content_type=document.content_type)
        response['Content-Disposition'] = f'attachment; filename="{document.original_filename}"'
        response['Content-Length'] = len(decrypted_bytes)
        response['X-Content-Type-Options'] = 'nosniff'

        _create_audit(request.user, 'DOWNLOAD', pk, request, {
            'filename': document.original_filename, 'integrity': 'PASSED',
        })
        logger.info(f"DOWNLOAD: {request.user.email} downloaded '{document.original_filename}'")
        return response


class DocumentDeleteView(APIView):
    """DELETE /api/documents/<uuid:pk>/ — Soft-delete, preserve encrypted file."""
    permission_classes = [IsAuthenticated, CanDeleteDocuments]

    def delete(self, request, pk):
        try:
            document = Document.objects.get(pk=pk, is_active=True)
        except Document.DoesNotExist:
            return Response({'error': 'Document not found.'}, status=status.HTTP_404_NOT_FOUND)

        for perm in self.get_permissions():
            if hasattr(perm, 'has_object_permission'):
                if not perm.has_object_permission(request, self, document):
                    return Response({'error': perm.message}, status=status.HTTP_403_FORBIDDEN)

        document.is_active = False
        document.save(update_fields=['is_active', 'updated_at'])

        _create_audit(request.user, 'DELETE', pk, request, {
            'title': document.title, 'filename': document.original_filename,
        })
        logger.info(f"DELETE: {request.user.email} soft-deleted '{document.title}' ({pk})")
        return Response({'message': 'Document deleted successfully.'}, status=status.HTTP_200_OK)
