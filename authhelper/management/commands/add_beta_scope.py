import json

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = "This command will add beta scopes to the users" + \
        " migrated from old ekata beta dumps"

    def add_arguments(self, parser):
        parser.add_argument('data_file', type=str)

    def handle(self, *args, **options):
        f = open(options['data_file'], 'r')
        datas = json.load(f)
        for data in datas:
            fields = data['fields']
            try:
                user = User.objects.get(username=fields['username'])
                userprofile = user.userprofile
                scopes = userprofile.get_special_scopes()
                scopes.append('ekata-beta')
                userprofile.special_scopes = ','.join(scopes)
                userprofile.save()
            except User.DoesNotExist:
                self.stdout.write(
                    self.style.SUCCESS(
                        'User %s can\'t be found, skipped!!' %
                        fields['user'][0]))
