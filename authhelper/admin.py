from django.contrib import admin
from authhelper.models import UserEmail, UserEmailValidation

# Register your models here.

admin.site.register(UserEmail)
admin.site.register(UserEmailValidation)
