import json

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

from authhelper.models import UserEmail


class Command(BaseCommand):
    help = "This command will migrate user emails from old ekata dumps"

    def add_arguments(self, parser):
        parser.add_argument('data_file', type=str)

    def handle(self, *args, **options):
        f = open(options['data_file'], 'r')
        datas = json.load(f)
        for data in datas:
            fields = data['fields']
            try:
                user = User.objects.get(username=fields['user'][0])
                useremails = user.emails.all()
                user_has_primary_email = useremails.filter(
                    primary=True).count()
                useremail = UserEmail(
                    user=user, email=fields['email'],
                    verified=fields['verified'])
                useremail.primary = fields['primary'] \
                    if not user_has_primary_email else False
                useremail.save()
                self.stdout.write(
                    self.style.SUCCESS('Email %s added for user %s' %
                                       (fields['email'], fields['user'])))
            except User.DoesNotExist:
                self.stdout.write(
                    self.style.SUCCESS(
                        'User %s can\'t be found, skipped!!' %
                        fields['user'][0]))
