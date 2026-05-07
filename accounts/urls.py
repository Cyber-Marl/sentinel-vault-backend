"""
SentinelVault — Accounts URL Configuration
"""

from django.urls import path
from .views import LoginView, SentinelTokenRefreshView, RegisterView, UserProfileView

app_name = 'accounts'

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', SentinelTokenRefreshView.as_view(), name='token-refresh'),
    path('register/', RegisterView.as_view(), name='register'),
    path('profile/', UserProfileView.as_view(), name='profile'),
]
