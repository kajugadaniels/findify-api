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
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

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
        send a welcome email to the user's registered email address and log the user in
        by generating JWT tokens (access and refresh).
        """
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data.copy()
            # Generate unique username if not provided.
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

            # Automatically generate JWT tokens for the new user.
            refresh = RefreshToken.for_user(user)

            return Response({
                "detail": "User registered successfully.",
                "user": {
                    "id": user.id,
                    "role": user.role,
                    "name": user.name,
                    "email": user.email,
                    "username": user.username,
                    "phone_number": user.phone_number,
                },
                "access": str(refresh.access_token),
                "refresh": str(refresh)
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
            user_data = UserSerializer(user, context={'request': request}).data

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

class UpdatePasswordView(APIView):
    """
    This view handles password change for the logged-in user.
    After successfully changing the password, the user will be logged out (by blacklisting the refresh token, if provided).
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user  # Get the currently authenticated user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        confirm_new_password = request.data.get("confirm_new_password")
        refresh_token = request.data.get("refresh_token")  # Optionally send the refresh token

        if not old_password or not new_password or not confirm_new_password:
            return Response(
                {"detail": "Old password, new password, and confirmation are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if old password is correct
        if not user.check_password(old_password):
            return Response(
                {"detail": "Old password is incorrect."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Ensure new password and confirmation match
        if new_password != confirm_new_password:
            return Response(
                {"detail": "New password and confirm new password do not match."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update the password
        user.set_password(new_password)
        user.save()

        # If a refresh token was provided, blacklist it to force logout.
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except (TokenError, InvalidToken) as e:
                # Log error if needed, but continue.
                pass

        return Response(
            {"detail": "Password updated successfully. Please log in again."},
            status=status.HTTP_200_OK
        )

class PasswordResetRequestView(APIView):
    """
    Initiate the password reset process by sending a 5-digit OTP to the user's email address.
    Provides detailed error messages on failure.
    """
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            User = get_user_model()
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                # This should normally be caught in the serializer, but we double-check.
                return Response({"detail": "No user found with the provided email address."}, status=status.HTTP_404_NOT_FOUND)
            
            # Generate a 5-digit OTP
            otp = str(random.randint(10000, 99999))
            user.reset_otp = otp
            user.otp_created_at = timezone.now()
            user.save()

            subject = "Password Reset OTP"
            message = f"Your OTP for password reset is: {otp}"
            from_email = None  # Uses DEFAULT_FROM_EMAIL from settings if set.
            recipient_list = [user.email]

            try:
                send_mail(subject, message, from_email, recipient_list)
            except Exception as e:
                return Response({
                    "detail": "Failed to send OTP email.",
                    "error": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"detail": "OTP sent to your email address."}, status=status.HTTP_200_OK)
        else:
            # Construct a detailed error message.
            error_messages = []
            for field, messages in serializer.errors.items():
                error_messages.append(f"{field}: {', '.join(messages)}")
            error_detail = " ".join(error_messages)
            return Response({"detail": error_detail}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    """
    Confirm the password reset by validating the OTP and setting the new password.
    After successfully resetting the password, sends a confirmation email to the user.
    Provides detailed error messages on failure.
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
            try:
                send_mail(subject, message, from_email, recipient_list)
            except Exception as e:
                return Response({
                    "detail": "Password reset succeeded but failed to send confirmation email.",
                    "error": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({"detail": "Password reset successfully."}, status=status.HTTP_200_OK)
        else:
            # Build detailed error messages.
            error_messages = []
            for field, messages in serializer.errors.items():
                error_messages.append(f"{field}: {', '.join(messages)}")
            error_detail = " ".join(error_messages)
            return Response({"detail": error_detail}, status=status.HTTP_400_BAD_REQUEST)
