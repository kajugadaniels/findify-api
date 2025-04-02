from django.db import models
from django.conf import settings

class Vendor(models.Model):
    BUSINESS_TYPE_CHOICES = (
        ('Retailer', 'Retailer'),
        ('Wholesaler', 'Wholesaler'),
        ('Distributor', 'Distributor'),
        ('Manufacturer', 'Manufacturer'),
    )

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='vendor_profile')
    company_name = models.CharField(max_length=255, null=True, blank=True)
    tin_number = models.CharField(max_length=100, unique=True, null=True, blank=True)
    business_type = models.CharField(max_length=50, choices=BUSINESS_TYPE_CHOICES, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    website = models.URLField(null=True, blank=True)

    address = models.TextField()
    country = models.CharField(max_length=100, null=True, blank=True)
    district = models.CharField(max_length=100, null=True, blank=True)
    sector = models.CharField(max_length=100, null=True, blank=True)
    cell = models.CharField(max_length=100, null=True, blank=True)
    village = models.CharField(max_length=100, null=True, blank=True)

    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.company_name} ({self.tin_number})"
