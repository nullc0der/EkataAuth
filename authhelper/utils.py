import os
import json
from itertools import groupby
from operator import itemgetter

import requests
from requests_oauthlib import OAuth1
from requests.auth import HTTPBasicAuth

from django.core.mail import EmailMultiAlternatives
from django.utils.crypto import get_random_string
from django.template import loader
from django.conf import settings
from django.utils.timezone import now

from oauth2_provider.models import get_access_token_model

from authhelper.models import (
    UserEmail, UserEmailValidation, ResetPasswordToken)


BASE_EMAIL_TEMPLATE = {
    'ekata.social': 'base_email_template_ekata_social.html',
    'baza.foundation': 'base_email_template_baza_foundation.html',
    'localhost:5100': 'base_email_template_ekata_social.html'
}


def send_validation_email(
        email_id, initiator_use_ssl, initiator_site, initiator_email):
    useremail = UserEmail.objects.get(email=email_id)
    validation_key = get_random_string(length=48)
    validation_url = '%s://%s/validateemail/%s/' % (
        'https' if initiator_use_ssl else 'http',
        initiator_site, validation_key, )
    email_template = loader.get_template('validateemail.html')
    msg = EmailMultiAlternatives(
        'Validate your email for %s' % initiator_site,
        'Go to this url to validate %s' % validation_url,
        initiator_email,
        [useremail.email])
    msg.attach_alternative(email_template.render({
        'username': useremail.email,
        'initiator_site': initiator_site,
        'validation_url': validation_url,
        'base_template': BASE_EMAIL_TEMPLATE[initiator_site]
    }), "text/html")
    msg.send()
    try:
        useremailvalidation = UserEmailValidation.objects.get(
            useremail=useremail)
        useremailvalidation.validation_key = validation_key
        useremailvalidation.created_on = now()
        useremailvalidation.save()
    except UserEmailValidation.DoesNotExist:
        UserEmailValidation.objects.create(
            useremail=useremail,
            validation_key=validation_key
        )


def send_password_reset_email(
        email_id, initiator_use_ssl, initiator_site, initiator_email):
    useremail = UserEmail.objects.get(email=email_id)
    token = get_random_string(length=48)
    reset_password_url = '%s://%s/resetpassword/%s/' % (
        'https' if initiator_use_ssl else 'http',
        initiator_site, token,
    )
    email_template = loader.get_template('forgotpassword.html')
    msg = EmailMultiAlternatives(
        'Forgot password',
        'Go to this url to reset %s' % reset_password_url,
        initiator_email,
        [useremail.email])
    msg.attach_alternative(email_template.render({
        'email': useremail.email,
        'reset_link': reset_password_url,
        'base_template': BASE_EMAIL_TEMPLATE[initiator_site]
    }), "text/html")
    msg.send()
    ResetPasswordToken.objects.create(
        user=useremail.user,
        token=token
    )


def get_token_user_email_data(access_token):
    AccessToken = get_access_token_model()
    try:
        data = {}
        user = AccessToken.objects.get(token=access_token).user
        data['user'] = user
        data['access_token_exist'] = True
        if user.email == '':
            data['email_exist'] = False
        else:
            data['email_exist'] = True
            if len(user.emails.all()):
                primary_email = user.emails.get(primary=True)
                data['user_email_object_exist'] = True
                data['useremail'] = primary_email
            else:
                data['user_email_object_exist'] = False
        return data
    except AccessToken.DoesNotExist:
        return {
            'access_token_exist': False
        }


def get_twitter_request_token(initiator_site, callback_uri):
    auth = OAuth1(
        callback_uri=callback_uri,
        client_key=getattr(settings, 'SOCIAL_AUTH_TWITTER_' +
                           settings.SOCIAL_KEY_SETTING_NAME[initiator_site]),
        client_secret=getattr(
            settings, 'SOCIAL_AUTH_TWITTER_'
            + settings.SOCIAL_SECRET_SETTING_NAME[initiator_site])
    )
    res = requests.post(
        'https://api.twitter.com/oauth/request_token', auth=auth)
    return res


def get_twitter_user_auth_token(initiator_site, oauth_token, oauth_verifier):
    auth = OAuth1(
        client_key=getattr(settings, 'SOCIAL_AUTH_TWITTER_' +
                           settings.SOCIAL_KEY_SETTING_NAME[initiator_site]),
        client_secret=getattr(
            settings, 'SOCIAL_AUTH_TWITTER_'
            + settings.SOCIAL_SECRET_SETTING_NAME[initiator_site]),
        resource_owner_key=oauth_token
    )
    data = {
        'oauth_verifier': oauth_verifier
    }
    res = requests.post(
        'https://api.twitter.com/oauth/access_token?oauth_verifier',
        data=data,
        auth=auth
    )
    return res


def send_added_email_notification(username):
    url = settings.INTERNAL_WEBHOOK_URL + '/profile/webhook/addedemail/'
    data = {
        'username': username,
        'key': settings.INTERNAL_WEBHOOK_KEY
    }
    requests.post(url, data=data)


def send_added_social_notification(username):
    url = settings.INTERNAL_WEBHOOK_URL + '/profile/webhook/addedsocial/'
    data = {
        'username': username,
        'key': settings.INTERNAL_WEBHOOK_KEY
    }
    requests.post(url, data=data)


def save_disposable_email_domain_list() -> bool:
    disposable_email_domains_dir = settings.BASE_DIR + \
        '/authhelper/datas/disposable_email_domains'
    if not os.path.isdir(disposable_email_domains_dir):
        os.makedirs(disposable_email_domains_dir)
    res = requests.get(
        'https://raw.githubusercontent.com/ivolo/' +
        'disposable-email-domains/master/index.json')
    if res.status_code == 200:
        splitted_domains = groupby(res.json(), key=itemgetter(0))
        for char, domains in splitted_domains:
            f = open(
                '{}/disposable_email_domains_{}.json'.format(
                    os.path.join(
                        settings.BASE_DIR,
                        'authhelper/datas/disposable_email_domains'
                    ),
                    char
                ),
                'w+'
            )
            f.write(json.dumps(list(domains)))
        return True
    return False


def add_useremail_to_listmonk_subscribers(useremail_id: int) -> str:
    useremail = UserEmail.objects.get(id=useremail_id)
    additional_data = {
        "user_id": useremail.user.id,
        "username": useremail.user.username,
        "email_type": useremail.email_type
    }
    full_name = useremail.user.get_full_name()
    res = requests.post(
        f"{settings.LISTMONK_SERVER_URL}/api/subscribers",
        json={
            "name": full_name if full_name else useremail.user.username,
            "email": useremail.email,
            "status": "enabled",
            "lists": settings.LISTMONK_SUBSCRIBERS_LIST,
            "attribs": additional_data,
            "preconfirm_subscription": True
        },
        auth=HTTPBasicAuth(
            settings.LISTMONK_API_USERNAME,
            settings.LISTMONK_API_PASSWORD)
    )
    if res.status_code == 200:
        response_data = res.json().get("data", {})
        useremail.added_to_listmonk = True
        useremail.listmonk_id = response_data.get("id", None)
        useremail.listmonk_uuid = response_data.get("uuid", None)
        useremail.save()
        return f"Added useremail_id:{useremail_id}"
    return f"Failed to add useremail_id:{useremail_id}, status code:{res.status_code}"
