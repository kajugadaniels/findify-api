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
            'role',
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
            role=validated_data.get('role'),
            username=validated_data.get('username'),
            phone_number=validated_data.get('phone_number'),
            image=validated_data.get('image'),
            password=validated_data.get('password')
        )
        return user

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User data.
    This will provide detailed user information (the creator of the property).
    """
    class Meta:
        model = User
        fields = ['id', 'role', 'name', 'email', 'phone_number', 'image']

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

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating the user profile.
    Allows updating name, email, username, phone_number, image, and password.
    When a new password is provided, both 'password' and 'confirm_password'
    are required and must match. Uniqueness of email, username, and phone_number is enforced.
    """
    password = serializers.CharField(
        write_only=True, required=False, style={'input_type': 'password'}
    )
    confirm_password = serializers.CharField(
        write_only=True, required=False, style={'input_type': 'password'}
    )
    
    class Meta:
        model = get_user_model()
        fields = ['name', 'email', 'username', 'phone_number', 'image', 'password', 'confirm_password']

    def validate_email(self, value):
        user = self.instance
        if get_user_model().objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use by another account.")
        return value

    def validate_phone_number(self, value):
        user = self.instance
        if get_user_model().objects.exclude(pk=user.pk).filter(phone_number=value).exists():
            raise serializers.ValidationError("This phone number is already in use by another account.")
        return value

    def validate_username(self, value):
        user = self.instance
        if get_user_model().objects.exclude(pk=user.pk).filter(username=value).exists():
            raise serializers.ValidationError("This username is already in use by another account.")
        return value

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        if password or confirm_password:
            if password != confirm_password:
                raise serializers.ValidationError({"password": "Password and confirm password do not match."})
            # Validate the password complexity if provided.
            validatePasswordComplexity(password)
        return attrs

    def update(self, instance, validated_data):
        """
        Update the user instance with the provided data.
        If a new password is provided, it is set securely.
        """
        password = validated_data.pop('password', None)
        validated_data.pop('confirm_password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance
