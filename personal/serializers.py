from personal.models import *
from account.serializers import *
from rest_framework import serializers

class PersonalSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Personal
        fields = ['id', 'user', 'id_number', 'bio', 'country', 'district', 'sector', 'cell', 'village', 'date_of_birth', 'gender', 'profile_completed', 'created_at', 'updated_at']
        read_only_fields = ['profile_completed', 'created_at', 'updated_at']
