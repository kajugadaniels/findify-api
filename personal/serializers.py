from rest_framework import serializers
from personal.models import Personal

class PersonalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Personal
        fields = ['id', 'id_number', 'bio', 'country', 'district', 'sector', 'cell', 'village', 'date_of_birth', 'gender', 'profile_completed']
        read_only_fields = ['id', 'profile_completed']
