import random
from account.models import *
from account.serializers import *
from django.utils import timezone
from rest_framework import status
from django.utils.text import slugify
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

class LoginView(APIView):
    def post(self, request, *args, **kwargs):
        """
        Handle login using an identifier (email, phone number, or username) and password.
        Returns JWT tokens upon successful authentication.
        """
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            return Response(
                {
                    "access": serializer.validated_data['access'],
                    "refresh": serializer.validated_data['refresh']
                },
                status=status.HTTP_200_OK
            )

        return Response(
            {"detail": "Validation error", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Handle user logout by blacklisting the refresh token."""
        try:
            # Get the refresh token from the request header
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the refresh token is valid and blacklist it
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({
                "detail": "Successfully logged out."
            }, status=status.HTTP_200_OK)

        except TokenError:
            # If the token is invalid or already blacklisted
            return Response({
                "detail": "Invalid or expired token."
            }, status=status.HTTP_400_BAD_REQUEST)

class RegisterView(APIView):
    def post(self, request, *args, **kwargs):
        """
        Handle user registration. If the username is not provided,
        generate a unique username from the user's name. Upon successful registration,
        send a welcome email to the user's registered email address.
        """
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data.copy()
            # Generate unique username if not provided
            if not data.get('username'):
                base_username = slugify(data.get('name')) if data.get('name') else "user"
                username = base_username
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}-{random.randint(1000, 9999)}"
                data['username'] = username
            else:
                base_username = data['username']
                username = base_username
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}{random.randint(1000, 9999)}"
                data['username'] = username

            # Create the user with the updated, unique username.
            user = serializer.create(data)

            # Send welcome email upon successful registration.
            subject = "Welcome to Findify!"
            message = f"Hi {user.name or 'there'}, welcome to Findify. We're thrilled to have you on board."
            from_email = None  # Uses DEFAULT_FROM_EMAIL from settings if set.
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list)

            return Response({
                "detail": "User registered successfully.",
                "user": {
                    "id": user.id,
                    "name": user.name,
                    "email": user.email,
                    "username": user.username,
                    "phone_number": user.phone_number,
                }
            }, status=status.HTTP_201_CREATED)

        return Response({
            "detail": "Registration failed. Please check the errors for details.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)