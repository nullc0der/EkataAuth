import requests
from requests_oauthlib import OAuth1

from django.core.mail import EmailMultiAlternatives
from django.utils.crypto import get_random_string
from django.template import loader
from django.conf import settings

from oauth2_provider.models import get_access_token_model

from authhelper.models import (
    UserEmail, UserEmailValidation, ResetPasswordToken)


def send_validation_email(email_id,
                          initiator_use_ssl, initiator_site, initiator_email):
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
        'validation_url': validation_url
    }), "text/html")
    msg.send()
    try:
        useremailvalidation = UserEmailValidation.objects.get(
            useremail=useremail)
        useremailvalidation.validation_key = validation_key
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
        'reset_link': reset_password_url
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


def get_twitter_request_token(callback_uri):
    auth = OAuth1(
        callback_uri=callback_uri,
        client_key=settings.SOCIAL_AUTH_TWITTER_KEY,
        client_secret=settings.SOCIAL_AUTH_TWITTER_SECRET
    )
    res = requests.post(
        'https://api.twitter.com/oauth/request_token', auth=auth)
    return res


def get_twitter_user_auth_token(oauth_token, oauth_verifier):
    auth = OAuth1(
        client_key=settings.SOCIAL_AUTH_TWITTER_KEY,
        client_secret=settings.SOCIAL_AUTH_TWITTER_SECRET,
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
