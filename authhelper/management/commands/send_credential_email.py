from django.core.management.base import BaseCommand
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.utils.crypto import get_random_string

from authhelper.models import UserProfile, ResetPasswordToken


class Command(BaseCommand):
    help = 'This command will send user credential email'
    ' to the users created with email id list'

    def handle(self, *args, **options):
        email_template = loader.get_template('credentialemail.html')
        userprofiles = UserProfile.objects.filter(
            created_from_email_list=True,
            credential_email_sent=False
        )
        emails_to_send = userprofiles.count()
        emails_sent = 0
        self.stdout.write(
            self.style.SUCCESS(
                '{} Emails to send'.format(
                    emails_to_send))
        )
        for userprofile in userprofiles:
            userprofile.user.set_unusable_password()
            userprofile.user.save()
            token = get_random_string(length=48)
            reset_password_url = 'https://ekata.social/' + \
                'resetpassword/{}/?new=true'.format(token)
            ResetPasswordToken.objects.create(
                user=userprofile.user,
                token=token
            )
            msg = EmailMultiAlternatives(
                subject='Welcome to the new Ekata Social',
                body='Please find the attached url to set password and login.',
                from_email='system@ekata.social',
                to=[userprofile.user.email])
            msg.attach_alternative(email_template.render({
                'username': userprofile.user.username,
                'reset_password_url': reset_password_url,
                'base_template': 'base_email_template_ekata_social.html'
            }), 'text/html')
            msg.send()
            if hasattr(userprofile.user, 'userpassword'):
                userprofile.user.userpassword.delete()
            emails_sent += 1
            userprofile.credential_email_sent = True
            userprofile.save()
            self.stdout.write(
                self.style.SUCCESS(
                    '[{}/{}] Credential email sent '
                    'successfully for user {}'.format(
                        emails_sent,
                        emails_to_send,
                        userprofile.user.username))
            )
