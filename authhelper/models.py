from django.db import models
from django.db.models import Q
from django.contrib.auth.models import User

# Create your models here.


class UserEmail(models.Model):
    EMAIL_TYPE_CHOICES = (
        ('office', 'Office'),
        ('home', 'Home'),
        ('mobile', 'Mobile'),
        ('emergency', 'Emergency')
    )
    user = models.ForeignKey(
        User, related_name='emails', on_delete=models.CASCADE)
    email = models.EmailField()
    primary = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
    email_type = models.CharField(
        max_length=10, default='office', choices=EMAIL_TYPE_CHOICES)
    added_to_listmonk = models.BooleanField(default=False)
    listmonk_id = models.IntegerField(null=True)
    listmonk_uuid = models.UUIDField(null=True)

    def save(self, *args, **kwargs):
        if self.primary:
            qs = type(self).objects.filter(Q(primary=True) & Q(user=self.user))
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            qs.update(primary=False)

        super(UserEmail, self).save(*args, **kwargs)

    def __str__(self):
        return self.user.username


class UserEmailValidation(models.Model):
    useremail = models.OneToOneField(UserEmail, on_delete=models.CASCADE)
    validation_key = models.CharField(max_length=400)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.useremail.user.username


class ResetPasswordToken(models.Model):
    user = models.ForeignKey(
        User, related_name='reset_password_tokens', on_delete=models.CASCADE
    )
    token = models.CharField(max_length=400)
    created_on = models.DateTimeField(auto_now_add=True)


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Comma seprated string if multiple
    special_scopes = models.CharField(
        default='', max_length=400,
        help_text='If multiple scope it must separated by comma')
    created_from_email_list = models.BooleanField(default=False)
    credential_email_sent = models.BooleanField(default=False)
    invited_to_baza = models.BooleanField(default=False)

    def get_special_scopes(self):
        return self.special_scopes.split(',')

    def __str__(self):
        return self.user.username


class UserPassword(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    password = models.CharField(max_length=10, default='')
