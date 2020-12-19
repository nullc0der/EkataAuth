import os
import json

from django.conf import settings
from django.core.management.base import BaseCommand

from authhelper.models import UserEmail


class Command(BaseCommand):
    help = 'This command will generate a list of all users who used' + \
        ' disposable email domains'

    def handle(self, *args, **options):
        accounts_with_disposable_domains = {}
        for useremail in UserEmail.objects.all():
            email_domain = useremail.email.split('@')[1]
            domain_list_to_open = settings.BASE_DIR + \
                '/authhelper/datas/disposable_email_domains/' + \
                'disposable_email_domains_{}.json'.format(email_domain[0])
            if os.path.exists(domain_list_to_open):
                with open(domain_list_to_open) as f:
                    domains = json.loads(f.read())
                    if email_domain in domains:
                        account = accounts_with_disposable_domains.get(
                            useremail.user.username, {})
                        account[useremail.email] = {
                            'id': useremail.id,
                            'verified': useremail.verified,
                            'primary': useremail.primary
                        }
                        accounts_with_disposable_domains[
                            useremail.user.username] = account
        self.stdout.write(
            self.style.SUCCESS(accounts_with_disposable_domains)
        )
