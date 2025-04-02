from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from personal.models import Personal
from personal.serializers import *
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from account.models import *

class PersonalProfileUpdateView(APIView):
    """
    View to update personal profile using user ID.
    Only authenticated users can access.
    """
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id, *args, **kwargs):
        user = get_object_or_404(User, pk=user_id, role='Personal')
        personal_profile, created = Personal.objects.get_or_create(user=user)
        serializer = PersonalSerializer(instance=personal_profile, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "detail": "Personal profile updated successfully.",
                "personal_profile": serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            "detail": "Update failed.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, user_id, *args, **kwargs):
        user = get_object_or_404(User, pk=user_id, role='Personal')
        personal_profile, created = Personal.objects.get_or_create(user=user)
        serializer = PersonalSerializer(instance=personal_profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "detail": "Personal profile updated successfully.",
                "personal_profile": serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            "detail": "Update failed.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
