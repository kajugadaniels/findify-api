from rest_framework import serializers
from personal.models import *

class PersonalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Personal
        fields = '__all__'
        read_only_fields = ['user', 'created_at', 'updated_at']
