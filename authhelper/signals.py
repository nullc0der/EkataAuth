from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User

from authhelper.models import UserEmail, UserProfile

from authhelper.tasks import task_add_useremail_to_listmonk_subscribers


@receiver(post_save, sender=UserEmail)
def update_user_email(sender, **kwargs):
    useremail = kwargs['instance']
    if useremail.verified and useremail.primary:
        useremail.user.email = useremail.email
        useremail.user.save()
        if not useremail.added_to_listmonk:
            task_add_useremail_to_listmonk_subscribers.delay(useremail.id)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(
            user=instance
        )
