from vendor.views import *
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

app_name = 'vendor'

urlpatterns = [
    path('update/<int:user_id>/', VendorProfileUpdateView.as_view(), name='vendorProfileUpdate'),
]  + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
