from vendor.models import *
from vendor.serializers import *
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied

class VendorProfileUpdateView(APIView):
    """
    Retrieve or update the Vendor profile of a user based on user.id.
    Only authenticated users can access this endpoint.
    If a Vendor profile does not exist, it will be auto-created.
    """
    permission_classes = [IsAuthenticated]

    def get_object(self, user_id):
        # Ensure that a user can only update his/her own profile.
        if self.request.user.id != user_id:
            raise PermissionDenied("You do not have permission to access this profile.")

        vendor = Vendor.objects.filter(user__id=user_id).first()
        if not vendor:
            # Auto-create a Vendor profile with default values.
            vendor = Vendor.objects.create(
                user=self.request.user,
                company_name="",
                tin_number="",
                business_type="",
                email="",
                phone="",
                website="",
                address="",
                country="",
                district="",
                sector="",
                cell="",
                village=""
            )
        return vendor

    def get(self, request, user_id, *args, **kwargs):
        vendor_instance = self.get_object(user_id)
        serializer = VendorSerializer(vendor_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, user_id, *args, **kwargs):
        vendor_instance = self.get_object(user_id)
        serializer = VendorSerializer(vendor_instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, user_id, *args, **kwargs):
        vendor_instance = self.get_object(user_id)
        serializer = VendorSerializer(vendor_instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
