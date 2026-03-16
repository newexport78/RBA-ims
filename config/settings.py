"""
Django settings for IMS. Config separation: dev vs production via env.
"""
import os
from pathlib import Path

import environ

env = environ.Env(
    DEBUG=(bool, True),
    SECRET_KEY=(str, 'dev-secret-key-change-in-production'),
    ALLOWED_HOSTS=(list, ['localhost', '127.0.0.1']),
    DATABASE_URL=(str, ''),
    SENDGRID_API_KEY=(str, ''),
    DEFAULT_FROM_EMAIL=(str, 'noreply@ims.local'),
    OTP_EXPIRY_MINUTES=(int, 10),
    SESSION_COOKIE_AGE=(int, 3600),
    SESSION_SAVE_EVERY_REQUEST=(bool, True),
)

BASE_DIR = Path(__file__).resolve().parent.parent
environ.Env.read_env(BASE_DIR / '.env')

SECRET_KEY = env('SECRET_KEY')
DEBUG = env('DEBUG')
ALLOWED_HOSTS = env('ALLOWED_HOSTS')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'orders',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'accounts.middleware.SessionTimeoutMiddleware',
    'accounts.middleware.RoleRedirectMiddleware',
]

ROOT_URLCONF = 'config.urls'
WSGI_APPLICATION = 'config.wsgi.application'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
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

DATABASES = {}
_db_url = (env('DATABASE_URL') or os.environ.get('DATABASE_URL') or '').strip()
if _db_url:
    import dj_database_url
    DATABASES['default'] = dj_database_url.parse(_db_url, conn_max_age=600)
else:
    DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'ims_ratelimit_cache',
    }
}

AUTH_USER_MODEL = 'accounts.User'
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'accounts:login_redirect'
LOGOUT_REDIRECT_URL = 'accounts:login'

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static'] if (BASE_DIR / 'static').exists() else []
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Session
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = env('SESSION_COOKIE_AGE')
SESSION_SAVE_EVERY_REQUEST = env('SESSION_SAVE_EVERY_REQUEST')
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = not DEBUG

# Email (OTP) via SendGrid HTTP API
OTP_EXPIRY_MINUTES = env('OTP_EXPIRY_MINUTES')
SENDGRID_API_KEY = env('SENDGRID_API_KEY')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')

# Error logging (Phase 6): log to console; optionally to file if logs/ exists
_log_dir = BASE_DIR / 'logs'
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'config': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}
if _log_dir.exists():
    LOGGING['handlers']['file'] = {
        'class': 'logging.FileHandler',
        'filename': _log_dir / 'django.log',
    }
    LOGGING['root']['handlers'] = ['console', 'file']
    LOGGING['loggers']['config']['handlers'] = ['console', 'file']
