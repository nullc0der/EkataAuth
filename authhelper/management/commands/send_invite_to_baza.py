from django.core.management.base import BaseCommand, CommandParser
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.contrib.auth.models import User

from authhelper.models import UserProfile


class Command(BaseCommand):
    help = 'This command will send invitation email to ekata users to baza'

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument('--send-test', action='store_true',
                            help="Send email to admin for test")

    def send_email(self, email_id: str, username: str) -> None:
        template = loader.get_template('bazainvite.html')
        msg = EmailMultiAlternatives(
            'You are invited to Baza.Foundation',
            'Check html message',
            'system-noreply@baza.foundation',
            [email_id]
        )
        msg.attach_alternative(
            template.render({
                'base_template': 'base_email_template_baza_foundation.html',
                'username': username
            }),
            "text/html"
        )
        msg.send()

    def get_username_and_emails(self, send_test: bool = False) -> None:
        if send_test:
            return [
                {
                    'email_id': 'prasantakakati@ekata.io',
                    'username': 'prasanta'
                },
                {
                    'email_id': 'andrew@ekata.io',
                    'username': 'puffmushroom'
                }
            ]
        username_and_emails = []
        userprofiles = UserProfile.objects.filter(
            created_from_email_list=True,
            invited_to_baza=False
        )
        for userprofile in userprofiles:
            user = userprofile.user
            if user.username != 'paulhyatt'\
                    and user.email != 'carol.chalke546@yahoo.com':
                username_and_emails.append({
                    'email_id': user.email,
                    'username': user.username
                })
        return username_and_emails

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Getting username and emails"))
        username_and_emails = self.get_username_and_emails(
            send_test=options["send_test"])
        for username_and_email in username_and_emails:
            self.stdout.write(self.style.SUCCESS(
                f"Sending email to {username_and_email['email_id']}"))
            self.send_email(
                email_id=username_and_email['email_id'],
                username=username_and_email['username'])
            if not options['send_test']:
                user = User.objects.get(
                    username=username_and_email['username'])
                user.userprofile.invited_to_baza = True
                user.userprofile.save()
