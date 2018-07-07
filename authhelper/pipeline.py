from social_core.exceptions import AuthException

from authhelper.models import UserEmail


def check_email_exists(backend, details, uid, user=None, *args, **kwargs):
    email = details.get('email', '')
    provider = backend.name
    social = backend.strategy.storage.user.get_social_auth(provider, uid)
    email_exists = UserEmail.objects.filter(email=email).exists()
    if not user and not social and email_exists:
        raise AuthException(backend, 'email_associated:%s' % email)
