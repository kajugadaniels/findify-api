from personal.models import *
from rest_framework import status
from personal.serializers import *
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied

class PersonalProfileUpdateView(APIView):
    """
    Retrieve or update the Personal profile of a user based on user.id.
    Only authenticated users can access this endpoint.
    If a Personal profile does not exist, it will be created automatically.
    """
    permission_classes = [IsAuthenticated]

    def get_object(self, user_id):
        # Ensure the logged in user is accessing their own profile.
        if self.request.user.id != user_id:
            raise PermissionDenied("You do not have permission to access this profile.")
        
        personal = Personal.objects.filter(user__id=user_id).first()
        if not personal:
            # Auto-create a Personal profile with default values.
            # Ensure your Personal model allows these fields to be blank or provide defaults.
            personal = Personal.objects.create(
                user=self.request.user,
                id_number="",  # Default empty; update with a valid id_number later.
                bio="",
                country="",   # Or a default country code if applicable.
                district="",
                sector="",
                cell="",
                village=""
            )
        return personal

    def get(self, request, user_id, *args, **kwargs):
        personal_instance = self.get_object(user_id)
        serializer = PersonalSerializer(personal_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, user_id, *args, **kwargs):
        personal_instance = self.get_object(user_id)
        serializer = PersonalSerializer(personal_instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, user_id, *args, **kwargs):
        personal_instance = self.get_object(user_id)
        serializer = PersonalSerializer(personal_instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
