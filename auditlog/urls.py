"""SentinelVault — Audit Log URL Configuration"""
from django.urls import path
from .views import AuditLogListView

app_name = 'auditlog'

urlpatterns = [
    path('', AuditLogListView.as_view(), name='list'),
]
