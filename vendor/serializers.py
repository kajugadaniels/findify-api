from vendor.models import *
from rest_framework import serializers

class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = ['id', 'company_name', 'tin_number', 'business_type', 'email', 'phone', 'website', 'address', 'country', 'district', 'sector', 'cell', 'village', 'is_verified', 'created_at', 'updated_at']
        read_only_fields = ['is_verified', 'created_at', 'updated_at']
