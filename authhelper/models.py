from django.db import models
from django.db.models import Q
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

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

    def get_special_scopes(self):
        return self.special_scopes.split(',')

    def __str__(self):
        return self.user.username


@receiver(post_save, sender=UserEmail)
def update_user_email(sender, **kwargs):
    useremail = kwargs['instance']
    if useremail.verified and useremail.primary:
        useremail.user.email = useremail.email
        useremail.user.save()


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(
            user=instance,
            special_scopes='baza-beta'
        )
