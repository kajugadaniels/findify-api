import os
import re
from account.models import *
from django.db.models import Q
from datetime import timedelta
from django.utils import timezone
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

def validatePasswordComplexity(password):
    """
    Validates that the password meets the complexity requirements:
    - At least 8 characters long.
    - Contains at least one capital letter.
    - Contains at least one number.
    - Contains at least one special character.
    """
    if len(password) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise serializers.ValidationError("Password must contain at least one capital letter.")
    if not re.search(r"\d", password):
        raise serializers.ValidationError("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        raise serializers.ValidationError("Password must contain at least one special character.")
    return password

class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(
        help_text="Enter your email, phone number, or username."
    )
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        identifier = attrs.get('identifier')
        password = attrs.get('password')

        if not identifier:
            raise serializers.ValidationError("Identifier (email, phone number, or username) is required.")
        if not password:
            raise serializers.ValidationError("Password is required.")

        User = get_user_model()
        try:
            user = User.objects.get(
                Q(email__iexact=identifier) | Q(phone_number=identifier) | Q(username__iexact=identifier)
            )
        except User.DoesNotExist:
            raise serializers.ValidationError("No user found with the provided email, phone number, or username.")

        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect password. Please check your credentials.")

        refresh = RefreshToken.for_user(user)
        attrs['refresh'] = str(refresh)
        attrs['access'] = str(refresh.access_token)

        return attrs

class RegisterUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = get_user_model()
        fields = [
            'name', 
            'email', 
            'username', 
            'phone_number', 
            'image', 
            'password', 
            'confirm_password'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'required': False},
        }

    def validate_email(self, value):
        if get_user_model().objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists. Please use a different email address.")
        return value

    def validate_phone_number(self, value):
        if get_user_model().objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("A user with this phone number already exists. Please use a different phone number.")
        return value

    def validate(self, attrs):
        """
        Validates that the password and confirm_password match and that the password meets complexity requirements.
        """
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError({"password": "Password and confirm password do not match. Please re-enter them."})

        # Validate password complexity
        validatePasswordComplexity(password)
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = get_user_model().objects.create_user(
            email=validated_data.get('email'),
            name=validated_data.get('name'),
            username=validated_data.get('username'),
            phone_number=validated_data.get('phone_number'),
            image=validated_data.get('image'),
            password=validated_data.get('password')
        )
        return user

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Enter the email address associated with your account."
    )

    def validate_email(self, value):
        User = get_user_model()
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Enter your email address."
    )
    otp = serializers.CharField(
        max_length=5,
        help_text="Enter the 5-digit OTP sent to your email."
    )
    new_password = serializers.CharField(
        write_only=True,
        help_text="Enter your new password."
    )
    confirm_new_password = serializers.CharField(
        write_only=True,
        help_text="Confirm your new password."
    )

    def validate(self, attrs):
        """
        Validates OTP, new password match, and ensures the new password meets complexity requirements.
        """
        email = attrs.get('email')
        otp = attrs.get('otp')
        new_password = attrs.get('new_password')
        confirm_new_password = attrs.get('confirm_new_password')

        if new_password != confirm_new_password:
            raise serializers.ValidationError("New password and confirm password do not match.")

        # Validate new password complexity
        validatePasswordComplexity(new_password)

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("No user found with this email address.")

        if user.reset_otp != otp:
            raise serializers.ValidationError("Invalid OTP provided.")

        if user.otp_created_at:
            if timezone.now() - user.otp_created_at > timedelta(minutes=10):
                raise serializers.ValidationError("OTP has expired. Please request a new one.")
        else:
            raise serializers.ValidationError("OTP was not generated. Please request a new one.")

        attrs['user'] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data['user']
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.reset_otp = ""
        user.otp_created_at = None
        user.save()
        return user