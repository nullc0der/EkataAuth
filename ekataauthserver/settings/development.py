from .base import *

DEBUG = True

# INSTALLED_APPS += [
#     'corsheaders',
# ]

# MIDDLEWARE.insert(2, 'corsheaders.middleware.CorsMiddleware')

# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# CORS_ORIGIN_WHITELIST = [
#     'localhost:5100'
# ]
