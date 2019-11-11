from django.conf import settings
from social_core.backends.facebook import (
    FacebookAppOAuth2, FacebookOAuth2)
from social_core.backends.google import GoogleOAuth2
from social_core.backends.twitter import TwitterOAuth


class EkataAuthFacebookAppOAuth2(FacebookAppOAuth2):
    def get_key_and_secret(self):
        request = self.strategy.request
        return self.setting(
            settings.SOCIAL_KEY_PREFIXES[
                request.POST['initiator_site']]),\
            self.setting(
                settings.SOCIAL_SECRET_PREFIXES[
                    request.POST['initiator_site']])


class EkataAuthFacebookOAuth2(FacebookOAuth2):
    def get_key_and_secret(self):
        request = self.strategy.request
        return self.setting(
            settings.SOCIAL_KEY_PREFIXES[
                request.POST['initiator_site']]),\
            self.setting(
                settings.SOCIAL_SECRET_PREFIXES[
                    request.POST['initiator_site']])


class EkataAuthGoogleOAuth2(GoogleOAuth2):
    def get_key_and_secret(self):
        request = self.strategy.request
        return self.setting(
            settings.SOCIAL_KEY_PREFIXES[
                request.POST['initiator_site']]),\
            self.setting(
                settings.SOCIAL_SECRET_PREFIXES[
                    request.POST['initiator_site']])


class EkataAuthTwitterOAuth(TwitterOAuth):
    def get_key_and_secret(self):
        request = self.strategy.request
        return self.setting(
            settings.SOCIAL_KEY_PREFIXES[
                request.POST['initiator_site']]),\
            self.setting(
                settings.SOCIAL_SECRET_PREFIXES[
                    request.POST['initiator_site']])
