from personal.models import *
from rest_framework import serializers

class PersonalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Personal
        fields = ['id', 'id_number', 'bio', 'country', 'district', 'sector', 'cell', 'village', 'date_of_birth', 'gender', 'profile_completed', 'created_at', 'updated_at']
        read_only_fields = ['profile_completed', 'created_at', 'updated_at']
