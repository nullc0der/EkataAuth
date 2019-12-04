from django.core.management.base import BaseCommand
from django.core.mail import EmailMultiAlternatives
from django.template import loader

from authhelper.models import UserPassword


class Command(BaseCommand):
    help = 'This command will send user credential email'
    ' to the users created with email id list'

    def handle(self, *args, **options):
        email_template = loader.get_template('credentialemail.html')
        for userpassword in UserPassword.objects.all():
            msg = EmailMultiAlternatives(
                subject='Welcome to new ekata social',
                body='Here is your credential to login.'
                ' username: {} password: {}'.format(
                    userpassword.user.username, userpassword.password),
                from_email='system@ekata.social',
                to=[userpassword.user.email])
            msg.attach_alternative(email_template.render({
                'username': userpassword.user.username,
                'password': userpassword.password,
                'base_template': 'base_email_template_ekata_social.html'
            }), 'text/html')
            msg.send()
            userpassword.delete()
            self.stdout.write(
                self.style.SUCCESS(
                    'Credential email sent successfully for user {}'.format(
                        userpassword.user.username))
            )
