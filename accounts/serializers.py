"""
SentinelVault — Authentication Serializers
Handles JWT token creation with custom claims and user profile serialization.
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class SentinelTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT serializer that embeds user role and ID in the token claims.
    This allows the frontend to read the role without an extra API call.
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Custom claims embedded in the JWT payload
        token['email'] = user.email
        token['role'] = user.role
        token['full_name'] = f"{user.first_name} {user.last_name}".strip()

        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        # Include user metadata in the response body (not just the token)
        data['user'] = {
            'id': str(self.user.id),
            'email': self.user.email,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
            'role': self.user.role,
        }

        return data


class UserSerializer(serializers.ModelSerializer):
    """
    Read-only user profile serializer.
    Sensitive fields (password, last_login) are excluded.
    """

    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'role', 'is_active', 'date_joined',
        ]
        read_only_fields = fields


class RegisterSerializer(serializers.ModelSerializer):
    """
    User registration serializer with password confirmation.
    New users default to the VIEWER role (principle of least privilege).
    """
    password = serializers.CharField(
        write_only=True,
        min_length=10,
        style={'input_type': 'password'},
        help_text="Minimum 10 characters."
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
    )

    class Meta:
        model = User
        fields = [
            'email', 'username', 'first_name', 'last_name',
            'password', 'password_confirm',
        ]

    def validate(self, attrs):
        if attrs['password'] != attrs.pop('password_confirm'):
            raise serializers.ValidationError(
                {"password_confirm": "Passwords do not match."}
            )
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            password=validated_data['password'],
            # Role is explicitly set to VIEWER — never trust client input for role
        )
        return user
