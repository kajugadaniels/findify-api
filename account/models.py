import os
from account.managers import *
from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from imagekit.processors import ResizeToFill
from imagekit.models import ProcessedImageField
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, Permission

def user_image_path(instance, filename):
    base_filename, file_extension = os.path.splitext(filename)
    return f'users/user_{slugify(instance.name)}_{instance.phone_number}_{instance.email}{file_extension}'

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('Personal', 'Personal'),
        ('Vendor', 'Vendor'),
        ('Wholesaler', 'Wholesaler'),
    )

    name = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(unique=True, null=True, blank=True)
    username = models.CharField(unique=True, max_length=255, null=True, blank=True)
    phone_number = models.CharField(unique=True, max_length=20, null=True, blank=True)
    image = ProcessedImageField(
        upload_to=user_image_path,
        processors=[ResizeToFill(1270, 1270)],
        format='JPEG',
        options={'quality': 90},
        null=True,
        blank=True
    )
    role = models.CharField(max_length=30, choices=ROLE_CHOICES, null=True, blank=True)
    password = models.CharField(max_length=255, null=True, blank=True)
    reset_otp = models.CharField(max_length=7, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone_number']

    # Custom related names to prevent clashes with auth models
    groups = models.ManyToManyField(
        'auth.Group', 
        related_name='account_user_set',
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission, 
        related_name='account_user_permissions',
        blank=True
    )

    def generate_username(self):
        """Generate a unique username based on the name"""
        base_username = slugify(self.name) if self.name else "user"
        return f"{base_username}"

    def save(self, *args, **kwargs):
        # Auto generate username only on creation if not provided.
        if not self.pk and not self.username:
            self.username = self.generate_username()
        super(User, self).save(*args, **kwargs)

    def __str__(self):
        return f"{self.name}"
