import os
import re
from account.models import *
from django.db.models import Q
from datetime import timedelta
from django.utils import timezone
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

def validatePasswordComplexity(password):
    """
    Validates that the password meets the complexity requirements:
    - At least 8 characters long.
    - Contains at least one capital letter.
    - Contains at least one number.
    - Contains at least one special character.
    """
    if len(password) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise serializers.ValidationError("Password must contain at least one capital letter.")
    if not re.search(r"\d", password):
        raise serializers.ValidationError("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        raise serializers.ValidationError("Password must contain at least one special character.")
    return password