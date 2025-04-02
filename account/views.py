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

class VerifyTokenView(APIView):
    """
    Endpoint to verify the access token and retrieve user details.
    """

    def get(self, request, *args, **kwargs):
        """
        This will check if the access token is valid and return user details.
        """
        try:
            # Retrieve the token from the Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return Response({"detail": "Authorization header missing."}, status=status.HTTP_400_BAD_REQUEST)

            token = auth_header.split(' ')[1]  # Extract token from 'Bearer <token>'

            # Validate the token
            access_token = AccessToken(token)  # This will check if token is valid and not expired

            # If token is valid, retrieve user
            user = User.objects.get(id=access_token['user_id'])
            user_data = UserSerializer(user).data

            return Response({
                "detail": "Token is valid",
                "user": user_data
            }, status=status.HTTP_200_OK)

        except InvalidToken as e:
            # Token is invalid or expired
            return Response({
                "detail": "Invalid or expired token.",
                "error": str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)
        except TokenError as e:
            # Handle any other token errors
            return Response({
                "detail": "Token error.",
                "error": str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            # If no user is found for the token
            return Response({
                "detail": "User associated with this token not found."
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "detail": "An unexpected error occurred.",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProfileUpdateView(APIView):
    """
    Update the authenticated user's profile details.
    Supports both complete (PUT) and partial (PATCH) updates.
    Only accessible to authenticated users.
    """
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = UserProfileUpdateSerializer(instance=request.user, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "detail": "Profile updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            "detail": "Profile update failed.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):
        serializer = UserProfileUpdateSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "detail": "Profile updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            "detail": "Profile update failed.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestView(APIView):
    """
    Initiate the password reset process by sending a 5-digit OTP to the user's email address.
    """
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            User = get_user_model()
            user = User.objects.get(email=email)
            # Generate a 5-digit OTP
            otp = str(random.randint(10000, 99999))
            user.reset_otp = otp
            user.otp_created_at = timezone.now()
            user.save()

            subject = "Password Reset OTP"
            message = f"Your OTP for password reset is: {otp}"
            from_email = None  # Uses DEFAULT_FROM_EMAIL from settings if set
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list)

            return Response({"detail": "OTP sent to your email address."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    """
    Confirm the password reset by validating the OTP and setting the new password.
    After successfully resetting the password, sends a confirmation email to the user.
    """
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Send confirmation email after successful password reset.
            subject = "Password Changed Successfully"
            message = f"Hi {user.name or 'there'}, your password has been changed successfully. If you did not perform this action, please contact support immediately."
            from_email = None  # Uses DEFAULT_FROM_EMAIL from settings if set.
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list)
            return Response({"detail": "Password reset successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)