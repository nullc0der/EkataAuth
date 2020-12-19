import os
import json

from django.conf import settings
from django.core.management.base import BaseCommand

from authhelper.models import UserEmail


class Command(BaseCommand):
    help = 'This command will remove the accounts who used disposable' + \
        ' emails as primary, it will also remove secondary emails'

    def handle(self, *args, **options):
        deleted_users_list = []
        deleted_secondary_emails_list = []
        for useremail in UserEmail.objects.all():
            email_domain = useremail.email.split('@')[1]
            domain_list_to_open = settings.BASE_DIR + \
                '/authhelper/datas/disposable_email_domains/' + \
                'disposable_email_domains_{}.json'.format(email_domain[0])
            if os.path.exists(domain_list_to_open):
                with open(domain_list_to_open) as f:
                    domains = json.loads(f.read())
                    if email_domain in domains:
                        if useremail.primary:
                            deleted_users_list.append(useremail.user.username)
                            useremail.user.delete()
                        else:
                            deleted_secondary_emails_list.append(
                                "{}:{}".format(
                                    useremail.email, useremail.user.username))
                            useremail.delete()
        self.stdout.write(
            self.style.SUCCESS("Deleted Users: " + deleted_users_list)
        )
        self.stdout.write(
            self.style.SUCCESS("Deleted secondary emails: " +
                               deleted_secondary_emails_list)
        )
