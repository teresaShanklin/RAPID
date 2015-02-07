"""
Django settings for RAPID project.

For more information on this file, see
https://docs.djangoproject.com/en/1.7/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.7/ref/settings/
"""

import os
from RAPID.configurations import PostgresConfig
from RAPID.configurations import RapidEmailConfig

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.7/howto/deployment/checklist/

# List of admin emails for receiving errors
# ADMINS = (('NAME', 'email@address.com'),)


# SECURITY WARNING: keep the secret key used in production secret!
# That means DO NOT use this one...You have been warned
SECRET_KEY = 'tuluiw*b9rlp^)_i#12*p-vncpd*=q#ydsr8^a_t8rht33x2@4'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
TEMPLATE_DEBUG = True

# Uncomment SECURE_PROXY and set secure cookies to true once HTTPS is enabled in Production
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False

# Enable HTTPS for wsgi
# os.environ['wsgi.url_scheme'] = 'https'

ALLOWED_HOSTS = []  # [x.x.x.x, host.com]
AUTH_USER_MODEL = 'gateway.RapidUser'

# Application definition
INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'widget_tweaks',
    'gateway',
    'pivoteer',
    'monitor_domain',
    'monitor_ip',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'RAPID.urls'
WSGI_APPLICATION = 'RAPID.wsgi.application'

# Database Settings
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': PostgresConfig.db_name,
        'USER': PostgresConfig.username,
        'PASSWORD': PostgresConfig.password,
        'HOST': PostgresConfig.host,
        'PORT': PostgresConfig.port,
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.7/topics/i18n/
TIME_ZONE = 'UTC'
LANGUAGE_CODE = 'en-us'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.7/howto/static-files/
# STATIC_ROOT = None  # Ex) "/var/www/rapid/static/"
STATIC_URL = '/static/'

# Media Files
# MEDIA_ROOT = None  # Ex) "/var/www/rapid/media/"
MEDIA_URL = '/media/'

# Email Settings
EMAIL_USE_TLS = RapidEmailConfig.tls
EMAIL_HOST = RapidEmailConfig.host
EMAIL_HOST_USER = RapidEmailConfig.user
EMAIL_HOST_PASSWORD = RapidEmailConfig.password
EMAIL_PORT = RapidEmailConfig.port

# Basic Logging Configuration
# https://docs.djangoproject.com/en/1.7/topics/logging/
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'RAPID.log',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}