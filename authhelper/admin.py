from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from authhelper.models import UserEmail, UserEmailValidation, UserProfile

# Register your models here.


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'


class CustomUserAdmin(UserAdmin):
    inlines = (UserProfileInline, )

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)


class UserEmailAdmin(admin.ModelAdmin):
    model = UserEmail
    list_display = ('user', 'email', 'primary', 'verified')
    list_filter = ('primary', 'verified')
    search_fields = ['user__username', 'email']


admin.site.unregister(User)
admin.site.register(UserEmail, UserEmailAdmin)
admin.site.register(UserEmailValidation)
admin.site.register(User, CustomUserAdmin)
