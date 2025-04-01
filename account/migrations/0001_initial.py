# Generated by Django 5.0.7 on 2025-04-01 22:19

import account.models
import django.utils.timezone
import imagekit.models.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('email', models.EmailField(blank=True, max_length=254, null=True, unique=True)),
                ('username', models.CharField(blank=True, max_length=255, null=True, unique=True)),
                ('phone_number', models.CharField(blank=True, max_length=20, null=True, unique=True)),
                ('image', imagekit.models.fields.ProcessedImageField(blank=True, null=True, upload_to=account.models.user_image_path)),
                ('role', models.CharField(blank=True, choices=[('Personal', 'Personal'), ('Vendor', 'Vendor'), ('Wholesaler', 'Wholesaler')], max_length=30, null=True)),
                ('password', models.CharField(blank=True, max_length=255, null=True)),
                ('reset_otp', models.CharField(blank=True, max_length=7, null=True)),
                ('otp_created_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, related_name='account_user_set', to='auth.group')),
                ('user_permissions', models.ManyToManyField(blank=True, related_name='account_user_permissions', to='auth.permission')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
