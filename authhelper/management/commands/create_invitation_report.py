import csv
from typing import Any, Optional

from django.core.management import BaseCommand

from authhelper.models import UserProfile


class Command(BaseCommand):
    help = 'This command will create csv report for'
    ' the ekata to baza invitation sent emails'

    def handle(self, *args: Any, **options: Any) -> Optional[str]:
        username_and_emails = []
        userprofiles = UserProfile.objects.filter(
            created_from_email_list=True,
            invited_to_baza=True
        )
        for userprofile in userprofiles:
            user = userprofile.user
            username_and_emails.append({
                'email_id': user.email,
                'username': user.username
            })
        with open('invitation.csv', 'w') as csvfile:
            csvwriter = csv.writer(
                csvfile, delimiter=',', quotechar='|',
                quoting=csv.QUOTE_MINIMAL)
            csvwriter.writerow(['email_id', 'username'])
            for sent_to_emailid in username_and_emails:
                csvwriter.writerow(
                    [sent_to_emailid['email_id'], sent_to_emailid['username']])
