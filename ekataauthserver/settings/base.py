"""
Django settings for bazaback project.

Generated by 'django-admin startproject' using Django 2.0.5.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""

import os
from django.core.exceptions import ImproperlyConfigured

from celery.schedules import crontab


def get_env_var(name):
    try:
        return os.environ[name]
    except KeyError:
        raise ImproperlyConfigured(
            'Set the environment variable %s' % name
        )


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_env_var('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles'
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'oauth2_provider',
    'social_django',
    'rest_framework_social_oauth2',
    'mjml'
]

EKATA_AUTH_APPS = [
    'authhelper'
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + EKATA_AUTH_APPS

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ekataauthserver.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ekataauthserver.wsgi.application'


# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Authentication
AUTHENTICATION_BACKENDS = (
    'authhelper.backends.EkataAuthFacebookAppOAuth2',
    'authhelper.backends.EkataAuthFacebookOAuth2',
    'authhelper.backends.EkataAuthGoogleOAuth2',
    'authhelper.backends.EkataAuthTwitterOAuth',
    'django.contrib.auth.backends.ModelBackend',
)


# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/

STATIC_URL = '/static/'


# Media files

MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
    )
}

# CELERY
CELERY_BROKER_URL = 'redis://' + get_env_var('REDIS_HOST') + ':6379/0'
CELERY_RESULT_BACKEND = 'redis://' + get_env_var('REDIS_HOST') + ':6379/0'
CELERY_TIMEZONE = 'UTC'
CELERY_BEAT_SCHEDULE = {
    'clear-expired-access-tokens': {
        'task': 'authhelper.tasks.clear_expired_access_tokens',
        'schedule': crontab(minute=0, hour=0)
    }
}

# EMAIL_SERVER
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = get_env_var('DJANGO_EMAIL_HOST')
EMAIL_PORT = 587
EMAIL_HOST_USER = get_env_var('DJANGO_EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = get_env_var('DJANGO_EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True


# Oauth Toolkit
OAUTH2_PROVIDER = {
    'SCOPES': {
        'read': 'Read scope',
        'write': 'Write scope',
        'introspection': 'Introspect token scope',
        'ekata-core': 'Ekata core services access',
        'ekata': 'Ekata resource access',
        'baza': 'Baza resource access',
        'ekata-beta': 'Ekata beta resource access',
        'baza-beta': 'Baza beta resource access'
    },
    'DEFAULT_SCOPES': ['read', 'write', 'ekata-core']
}

# Social Auth
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'authhelper.pipeline.check_email_exists',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
)
SOCIAL_AUTH_FACEBOOK_LOCALHOST_KEY = get_env_var(
    'SOCIAL_AUTH_FACEBOOK_LOCALHOST_KEY')
SOCIAL_AUTH_FACEBOOK_LOCALHOST_SECRET = get_env_var(
    'SOCIAL_AUTH_FACEBOOK_LOCALHOST_SECRET')
SOCIAL_AUTH_FACEBOOK_BAZA_FOUNDATION_KEY = get_env_var(
    'SOCIAL_AUTH_FACEBOOK_BAZA_FOUNDATION_KEY')
SOCIAL_AUTH_FACEBOOK_BAZA_FOUNDATION_SECRET = get_env_var(
    'SOCIAL_AUTH_FACEBOOK_BAZA_FOUNDATION_SECRET')
SOCIAL_AUTH_FACEBOOK_EKATA_SOCIAL_KEY = get_env_var(
    'SOCIAL_AUTH_FACEBOOK_EKATA_SOCIAL_KEY')
SOCIAL_AUTH_FACEBOOK_EKATA_SOCIAL_SECRET = get_env_var(
    'SOCIAL_AUTH_FACEBOOK_EKATA_SOCIAL_SECRET')
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']
SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {
    'fields': 'id, name, email'
}
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = get_env_var(
    'SOCIAL_AUTH_GOOGLE_OAUTH2_KEY')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = get_env_var(
    'SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET')
SOCIAL_AUTH_TWITTER_KEY = get_env_var(
    'SOCIAL_AUTH_TWITTER_KEY')
SOCIAL_AUTH_TWITTER_SECRET = get_env_var(
    'SOCIAL_AUTH_TWITTER_SECRET')
# SOCIAL_AUTH_GOOGLE_OAUTH2_EKATA_SOCIAL_KEY = get_env_var(
#     'SOCIAL_AUTH_GOOGLE_OAUTH2_EKATA_SOCIAL_KEY')
# SOCIAL_AUTH_GOOGLE_OAUTH2_EKATA_SOCIAL_SECRET = get_env_var(
#     'SOCIAL_AUTH_GOOGLE_OAUTH2_EKATA_SOCIAL_SECRET')
# SOCIAL_AUTH_GOOGLE_OAUTH2_BAZA_FOUNDATION_KEY = get_env_var(
#     'SOCIAL_AUTH_GOOGLE_OAUTH2_BAZA_FOUNDATION_KEY')
# SOCIAL_AUTH_GOOGLE_OAUTH2_BAZA_FOUNDATION_SECRET = get_env_var(
#     'SOCIAL_AUTH_GOOGLE_OAUTH2_BAZA_FOUNDATION_SECRET')
# SOCIAL_AUTH_GOOGLE_OAUTH2_LOCALHOST_KEY = get_env_var(
#     'SOCIAL_AUTH_GOOGLE_OAUTH2_LOCALHOST_KEY')
# SOCIAL_AUTH_GOOGLE_OAUTH2_LOCALHOST_SECRET = get_env_var(
#     'SOCIAL_AUTH_GOOGLE_OAUTH2_LOCALHOST_SECRET')
# SOCIAL_AUTH_TWITTER_LOCALHOST_KEY = get_env_var(
#     'SOCIAL_AUTH_TWITTER_LOCALHOST_KEY')
# SOCIAL_AUTH_TWITTER_LOCALHOST_SECRET = get_env_var(
#     'SOCIAL_AUTH_TWITTER_LOCALHOST_SECRET')
# SOCIAL_AUTH_TWITTER_BAZA_FOUNDATION_KEY = get_env_var(
#     'SOCIAL_AUTH_TWITTER_BAZA_FOUNDATION_KEY')
# SOCIAL_AUTH_TWITTER_BAZA_FOUNDATION_SECRET = get_env_var(
#     'SOCIAL_AUTH_TWITTER_BAZA_FOUNDATION_SECRET')
# SOCIAL_AUTH_TWITTER_EKATA_SOCIAL_KEY = get_env_var(
#     'SOCIAL_AUTH_TWITTER_EKATA_SOCIAL_KEY')
# SOCIAL_AUTH_TWITTER_EKATA_SOCIAL_SECRET = get_env_var(
#     'SOCIAL_AUTH_TWITTER_EKATA_SOCIAL_SECRET')
INTERNAL_WEBHOOK_URL = get_env_var('INTERNAL_WEBHOOK_URL')
INTERNAL_WEBHOOK_KEY = get_env_var('INTERNAL_WEBHOOK_KEY')
SOCIAL_KEY_PREFIXES = {
    'localhost:5100': 'LOCALHOST_KEY',
    'baza.foundation': 'BAZA_FOUNDATION_KEY',
    'beta.baza.foundation': 'BAZA_FOUNDATION_KEY',
    'ekata.social': 'EKATA_SOCIAL_KEY',
    'development.ekata.social': 'EKATA_SOCIAL_KEY'
}

SOCIAL_SECRET_PREFIXES = {
    'localhost:5100': 'LOCALHOST_SECRET',
    'baza.foundation': 'BAZA_FOUNDATION_SECRET',
    'beta.baza.foundation': 'BAZA_FOUNDATION_SECRET',
    'ekata.social': 'EKATA_SOCIAL_SECRET',
    'development.ekata.social': 'EKATA_SOCIAL_SECRET'
}
