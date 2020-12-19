import os
import json

from django.conf import settings

from rest_framework.exceptions import ValidationError


class EmailDomainValidator:
    """
    This validator is used to check whether an email id is using
    disposable email domain
    """
    message = "Enter a valid email address"

    def __init__(self, message=None):
        self.message = message or self.message

    def __call__(self, value):
        email_id_splitted = value.split('@')
        if len(email_id_splitted) > 1:
            email_domain = email_id_splitted[1]
            domain_list_to_open = settings.BASE_DIR + \
                '/authhelper/datas/disposable_email_domains/' + \
                'disposable_email_domains_{}.json'.format(email_domain[0])
            if os.path.exists(domain_list_to_open):
                with open(domain_list_to_open) as f:
                    domains = json.loads(f.read())
                    if email_domain in domains:
                        raise ValidationError(self.message)
