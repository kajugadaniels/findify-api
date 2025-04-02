from personal.models import *
from rest_framework import status
from personal.serializers import *
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated

class PersonalProfileUpdateView(APIView):
    """
    Retrieve or update the Personal profile of a user based on user.id.
    Only authenticated users can access this endpoint.
    """
    permission_classes = [IsAuthenticated]

    def get_object(self, user_id):
        return get_object_or_404(Personal, user__id=user_id)

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
