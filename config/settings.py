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
    # Amazon SES (OTP email on AWS). Set USE_SES=true and verify sender/domain in SES console.
    USE_SES=(bool, False),
    AWS_SES_REGION_NAME=(str, ''),
    DEFAULT_FROM_EMAIL=(str, 'noreply@ims.local'),
    OTP_EXPIRY_MINUTES=(int, 10),
    SESSION_COOKIE_AGE=(int, 3600),
    SESSION_SAVE_EVERY_REQUEST=(bool, True),
    REDIS_URL=(str, ''),
    AWS_STORAGE_BUCKET_NAME=(str, ''),
    AWS_S3_REGION_NAME=(str, ''),
    AWS_ACCESS_KEY_ID=(str, ''),
    AWS_SECRET_ACCESS_KEY=(str, ''),
    AWS_S3_CUSTOM_DOMAIN=(str, ''),
    OTP_SEND_ASYNC=(bool, False),
    # Emergency: set true in ECS env to bypass Redis login lockout (24h etc.). Remove after recovery.
    DISABLE_LOGIN_RATE_LIMIT=(bool, False),
)

BASE_DIR = Path(__file__).resolve().parent.parent
environ.Env.read_env(BASE_DIR / '.env')

SECRET_KEY = env('SECRET_KEY')
DEBUG = env('DEBUG')
ALLOWED_HOSTS = env('ALLOWED_HOSTS')

# HTTPS POST (login, forms) fails with "CSRF verification failed" if the Origin is not trusted.
# Set CSRF_TRUSTED_ORIGINS explicitly, or we derive https:// and http:// entries from ALLOWED_HOSTS.
_csrf_trusted = [x.strip() for x in env.list('CSRF_TRUSTED_ORIGINS', default=[]) if x and str(x).strip()]
if _csrf_trusted:
    CSRF_TRUSTED_ORIGINS = _csrf_trusted
else:
    CSRF_TRUSTED_ORIGINS = []
    for _host in ALLOWED_HOSTS:
        _h = (_host or '').strip().lower().strip('.')
        if not _h or '*' in _h:
            continue
        CSRF_TRUSTED_ORIGINS.extend((f'https://{_h}', f'http://{_h}'))

DISABLE_LOGIN_RATE_LIMIT = env.bool('DISABLE_LOGIN_RATE_LIMIT', default=False)


# Behind ALB / Cloudflare: use X-Forwarded-Host as Host (disable with USE_X_FORWARDED_HOST=false).
USE_X_FORWARDED_HOST = env.bool('USE_X_FORWARDED_HOST', default=(not DEBUG))

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
    'config.middleware.AlbHealthCheckHostMiddleware',
    'config.middleware.CloudflareForwardedProtoMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'config.middleware.SecurityHeadersMiddleware',
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

# Default: DB-backed sessions. When REDIS_URL is set below, this is switched to cache backend.
SESSION_ENGINE = "django.contrib.sessions.backends.db"

# Optional: Redis (recommended for high traffic). If REDIS_URL is set, use it for:
# - cache (rate limits, throttles, general caching)
# - sessions (avoids DB session table bottleneck)
_redis_url = (env('REDIS_URL') or os.environ.get('REDIS_URL') or '').strip()
if _redis_url:
    _redis_options = {"CLIENT_CLASS": "django_redis.client.DefaultClient"}
    # ElastiCache TLS (rediss://) often needs relaxed cert verify inside the VPC.
    if _redis_url.lower().startswith("rediss://"):
        import ssl

        _redis_options["CONNECTION_POOL_KWARGS"] = {"ssl_cert_reqs": ssl.CERT_NONE}
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": _redis_url,
            "OPTIONS": _redis_options,
            "TIMEOUT": 300,
        }
    }
    SESSION_ENGINE = "django.contrib.sessions.backends.cache"
    SESSION_CACHE_ALIAS = "default"

AUTH_USER_MODEL = 'accounts.User'
AUTHENTICATION_BACKENDS = ['accounts.backends.ApprovedUserBackend']
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'accounts:login_redirect'
LOGOUT_REDIRECT_URL = 'accounts:login'

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Password hashing (applies to all roles: superadmin/2IC/employee/users)
# Uses Argon2 (strong modern hash). Existing passwords remain valid and will
# be upgraded to Argon2 on next login/password change.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static'] if (BASE_DIR / 'static').exists() else []
STATIC_ROOT = BASE_DIR / 'staticfiles'
if not DEBUG:
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'
    WHITENOISE_USE_FINDERS = True

MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Optional: S3 media storage (recommended for production and large scale).
# If AWS_STORAGE_BUCKET_NAME is set, use S3 for uploaded media (order PDFs, user docs).
_bucket = (env('AWS_STORAGE_BUCKET_NAME') or os.environ.get('AWS_STORAGE_BUCKET_NAME') or '').strip()
if _bucket:
    INSTALLED_APPS += ["storages"]
    AWS_STORAGE_BUCKET_NAME = _bucket
    # Avoid invalid endpoint errors like `https://s3..amazon` when the region env is missing/blank.
    # Your bucket is in `ap-south-1` per AWS S3 console screenshot.
    AWS_S3_REGION_NAME = (
        env('AWS_S3_REGION_NAME')
        or os.environ.get('AWS_S3_REGION_NAME')
        or 'ap-south-1'
    ).strip() or 'ap-south-1'
    AWS_S3_CUSTOM_DOMAIN = env('AWS_S3_CUSTOM_DOMAIN') or os.environ.get('AWS_S3_CUSTOM_DOMAIN') or ''
    AWS_S3_OBJECT_PARAMETERS = {"CacheControl": "max-age=86400"}
    AWS_DEFAULT_ACL = None
    AWS_QUERYSTRING_AUTH = True  # signed URLs (access-controlled)
    AWS_S3_FILE_OVERWRITE = False
    AWS_S3_SIGNATURE_VERSION = "s3v4"
    DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

    # Media URL: prefer CloudFront/custom domain if provided
    if AWS_S3_CUSTOM_DOMAIN:
        MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/"
    else:
        MEDIA_URL = f"https://{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/"

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Session cookies (SESSION_ENGINE set above; Redis block may override to cache backend)
SESSION_COOKIE_AGE = env('SESSION_COOKIE_AGE')
SESSION_SAVE_EVERY_REQUEST = env('SESSION_SAVE_EVERY_REQUEST')
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

# SSL/security (safe defaults; only enforced in production)
# Default: redirect to HTTPS when DEBUG is off. Set SECURE_SSL_REDIRECT=false on an HTTP-only ALB so /health/ returns 200.
SECURE_SSL_REDIRECT = env.bool('SECURE_SSL_REDIRECT', default=(not DEBUG))
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Secure cookies are not sent/stored on plain HTTP. If SECURE_SSL_REDIRECT is false (HTTP-only ALB),
# default to non-secure session/CSRF cookies so login → OTP flow keeps the session.
SESSION_COOKIE_SECURE = env.bool(
    "SESSION_COOKIE_SECURE",
    default=(not DEBUG and SECURE_SSL_REDIRECT),
)
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=SESSION_COOKIE_SECURE)

# Extra hardening (safe, no UI impact)
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"

# Email (OTP): DEBUG → console; USE_SES → Amazon SES; else SendGrid if SENDGRID_API_KEY set
OTP_EXPIRY_MINUTES = env('OTP_EXPIRY_MINUTES')
SENDGRID_API_KEY = env('SENDGRID_API_KEY')
USE_SES = env.bool('USE_SES', default=False)
_s3_region = (env('AWS_S3_REGION_NAME') or '').strip()
AWS_SES_REGION_NAME = (env('AWS_SES_REGION_NAME') or '').strip() or _s3_region or 'ap-south-1'
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')

# Local development: print emails (OTP) to console (no SES/SendGrid)
if DEBUG:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

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
        # OTP / SES diagnostics in CloudWatch (ECS)
        'accounts.services': {
            'handlers': ['console'],
            'level': 'INFO',
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
    LOGGING['loggers']['accounts.services']['handlers'] = ['console', 'file']
