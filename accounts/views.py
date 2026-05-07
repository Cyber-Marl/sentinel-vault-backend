"""
SentinelVault — Authentication Views
Secure login, token refresh, and user profile endpoints.
"""

import logging

from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .serializers import (
    SentinelTokenObtainPairSerializer,
    RegisterSerializer,
    UserSerializer,
)

logger = logging.getLogger('sentinelvault')


class LoginView(TokenObtainPairView):
    """
    POST /api/auth/login/
    Authenticates a user with email + password and returns JWT access + refresh tokens.
    Also logs the authentication event to the audit trail.
    """
    serializer_class = SentinelTokenObtainPairSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            logger.info(
                f"AUTH_SUCCESS: User '{request.data.get('email')}' logged in "
                f"from {self._get_client_ip(request)}"
            )
            # Create audit log for successful login
            self._log_auth_event(request, success=True)
        else:
            logger.warning(
                f"AUTH_FAILURE: Failed login attempt for '{request.data.get('email')}' "
                f"from {self._get_client_ip(request)}"
            )
            self._log_auth_event(request, success=False)

        return response

    def _get_client_ip(self, request):
        """Extract client IP, handling reverse proxy headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '0.0.0.0')

    def _log_auth_event(self, request, success):
        """Create an audit log entry for authentication events."""
        try:
            from auditlog.utils import create_audit_log
            from auditlog.models import AuditLog

            # For failed logins, user is None
            user = None
            if success and hasattr(request, 'user') and request.user.is_authenticated:
                user = request.user
            elif success:
                # The user was authenticated by the serializer
                from django.contrib.auth import get_user_model
                User = get_user_model()
                try:
                    user = User.objects.get(email=request.data.get('email'))
                except User.DoesNotExist:
                    pass

            create_audit_log(
                user=user,
                action=AuditLog.Action.LOGIN if success else AuditLog.Action.LOGIN_FAILED,
                resource_type='Authentication',
                resource_id=None,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={
                    'email': request.data.get('email', ''),
                    'success': success,
                },
            )
        except Exception as e:
            logger.error(f"Failed to create auth audit log: {e}")


class SentinelTokenRefreshView(TokenRefreshView):
    """
    POST /api/auth/token/refresh/
    Accepts a refresh token and returns a new access token.
    """
    permission_classes = [AllowAny]


class RegisterView(generics.CreateAPIView):
    """
    POST /api/auth/register/
    Creates a new user account with the VIEWER role.
    """
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        logger.info(
            f"USER_REGISTERED: {user.email} from "
            f"{request.META.get('REMOTE_ADDR', '0.0.0.0')}"
        )

        return Response(
            {
                "message": "Account created successfully.",
                "user": UserSerializer(user).data,
            },
            status=status.HTTP_201_CREATED,
        )


class UserProfileView(generics.RetrieveAPIView):
    """
    GET /api/auth/profile/
    Returns the authenticated user's profile.
    """
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
