from account.views import *
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

app_name = 'auth'

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
    path('verify_token/', VerifyTokenView.as_view(), name='verifyToken'),
    path('profile/update/', ProfileUpdateView.as_view(), name='ProfileUpdate'),
    path('password-reset-request/', PasswordResetRequestView.as_view(), name='passwordResetRequest'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='passwordResetConfirm'),
]  + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
