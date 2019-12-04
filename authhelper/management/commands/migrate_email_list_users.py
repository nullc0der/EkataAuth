import json

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string

from authhelper.models import UserEmail, UserPassword


class Command(BaseCommand):
    help = 'This command will create users from the email ids list'

    def add_arguments(self, parser):
        parser.add_argument('data_file', type=str)

    def check_username_exist(self, username):
        try:
            User.objects.get(username=username)
            return True
        except User.DoesNotExist:
            return False

    def get_username(self, data):
        username = data['first_name'] + data['last_name']
        if not username:
            username = data['email_id'].split('@')[0]
        while self.check_username_exist(username):
            username = username + get_random_string(length=6)
        return username

    def handle(self, *args, **options):
        f = open(options['data_file'], 'r')
        datas = json.load(f)
        f.close()
        for data in datas:
            if User.objects.filter(email=data['email_id']).exists():
                self.stdout.write(
                    self.style.NOTICE(
                        'Skipped creating user for email id'
                        ' {}, user exist'.format(data['email_id'])))
            else:
                password_string = get_random_string(length=8)
                user = User.objects.create_user(
                    username=self.get_username(data), password=password_string)
                user.userprofile.created_from_email_list = True
                user.userprofile.save()
                UserEmail.objects.create(
                    user=user, email=data['email_id'], primary=True,
                    verified=True)
                UserPassword.objects.create(
                    user=user, password=password_string)
                self.stdout.write(
                    self.style.SUCCESS(
                        'Created user for emailid {}'.format(data['email_id']))
                )
