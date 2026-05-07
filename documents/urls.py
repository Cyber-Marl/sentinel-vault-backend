"""SentinelVault — Documents URL Configuration"""
from django.urls import path
from .views import (
    DocumentUploadView, DocumentListView,
    DocumentDetailView, DocumentDownloadView, DocumentDeleteView,
)

app_name = 'documents'

urlpatterns = [
    path('upload/', DocumentUploadView.as_view(), name='upload'),
    path('', DocumentListView.as_view(), name='list'),
    path('<uuid:pk>/', DocumentDetailView.as_view(), name='detail'),
    path('<uuid:pk>/download/', DocumentDownloadView.as_view(), name='download'),
    path('<uuid:pk>/delete/', DocumentDeleteView.as_view(), name='delete'),
]
