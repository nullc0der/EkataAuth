import json

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = "This command will migrate users from old ekata dumps"

    def add_arguments(self, parser):
        parser.add_argument('data_file', type=str)

    def handle(self, *args, **options):
        f = open(options['data_file'], 'r')
        datas = json.load(f)
        for data in datas:
            fields = data['fields']
            try:
                User.objects.get(username=fields['username'])
                self.stdout.write(
                    self.style.SUCCESS('user %s exist' %
                                       (fields['username'])))
            except User.DoesNotExist:
                User.objects.create(
                    username=fields['username'],
                    password=fields['password'],
                    email=fields['email'],
                    first_name=fields['first_name'],
                    last_name=fields['last_name'],
                    is_staff=fields['is_staff'],
                    is_active=fields['is_active'],
                    is_superuser=fields['is_superuser']
                )
