"""SentinelVault — Documents Admin Configuration"""
from django.contrib import admin
from .models import Document


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('title', 'original_filename', 'owner', 'file_size', 'content_type', 'is_active', 'uploaded_at')
    list_filter = ('is_active', 'content_type', 'uploaded_at')
    search_fields = ('title', 'original_filename', 'owner__email', 'file_hash')
    readonly_fields = ('id', 'file_hash', 'file_size', 'uploaded_at', 'updated_at')
    ordering = ('-uploaded_at',)
    raw_id_fields = ('owner',)
