import json
import os
import ipaddress
import re
from urllib.parse import urlparse
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
# The launcher supplies this file path; values are never printed or committed.
configuration = os.environ.get('PORTAL_CONFIG_FILE')
if configuration:
    from portal.configuration import read_config
    for key, value in read_config(Path(configuration)).items():
        if key.startswith('PORTAL_'):
            os.environ.setdefault(key, str(value))

RUNTIME = Path(os.environ.get('PORTAL_RUNTIME_DIR', str(Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local' / 'state'))) / 'ReleasePortalDemo' / 'runtime')))
RUNTIME.mkdir(parents=True, exist_ok=True)

LOCAL = os.environ.get('PORTAL_MODE', 'local') == 'local'
AUTH_MODE = os.environ.get('PORTAL_AUTH_MODE', 'github')
PRIVATE_INGRESS_CONFIRMED = os.environ.get('PORTAL_PRIVATE_INGRESS_CONFIRMED') == '1'
INGRESS_MODE = os.environ.get('PORTAL_INGRESS_MODE', 'private')
PUBLIC = INGRESS_MODE == 'public'
if INGRESS_MODE not in ['private', 'public']:
    raise ImproperlyConfigured('Invalid portal ingress mode.')
if PUBLIC and (LOCAL or os.environ.get('PORTAL_PUBLIC_INGRESS_APPROVED') != '1' or PRIVATE_INGRESS_CONFIRMED):
    raise ImproperlyConfigured('Public shared hosting requires explicit approval and no false private-ingress assertion.')
TRUSTED_PROXY_NETWORKS = []
if PUBLIC:
    if os.environ.get('PORTAL_TRUST_PROXY') != '1':
        raise ImproperlyConfigured('Public hosting requires the approved HTTPS proxy.')
    try:
        TRUSTED_PROXY_NETWORKS = [ipaddress.ip_network(value.strip()) for value in os.environ.get('PORTAL_TRUSTED_PROXY_CIDRS', '').split(',') if value.strip()]
    except ValueError:
        raise ImproperlyConfigured('Invalid trusted proxy networks.') from None
    if not TRUSTED_PROXY_NETWORKS or any(network.prefixlen == 0 for network in TRUSTED_PROXY_NETWORKS):
        raise ImproperlyConfigured('Explicit trusted proxy networks are required.')
if AUTH_MODE not in ['github', 'invited_password', 'corporate']:
    raise ImproperlyConfigured('Invalid PORTAL_AUTH_MODE.')
if not LOCAL and AUTH_MODE != 'github':
    raise ImproperlyConfigured('The direct-delivery pilot requires GitHub authentication.')
if not LOCAL and not PUBLIC and not PRIVATE_INGRESS_CONFIRMED:
    raise ImproperlyConfigured('Shared hosting requires confirmed VPN/private ingress. This setting does not configure or verify the network.')
DEBUG = False
SECRET_KEY = os.environ.get('PORTAL_SECRET_KEY', '')
if not SECRET_KEY:
    if not LOCAL:
        raise ImproperlyConfigured('PORTAL_SECRET_KEY is required for pilot hosting.')
    import secrets
    key_file = RUNTIME / 'django-key'
    if not key_file.exists():
        key_file.write_text(secrets.token_urlsafe(64))
    SECRET_KEY = key_file.read_text().strip()
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'testserver'] if LOCAL else os.environ.get('PORTAL_HOSTS', '').split(',')
if not LOCAL and (not all(ALLOWED_HOSTS) or '*' in ALLOWED_HOSTS):
    raise ImproperlyConfigured('Explicit PORTAL_HOSTS are required.')
if PUBLIC and (len(ALLOWED_HOSTS) != 1 or not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)+', ALLOWED_HOSTS[0])):
    raise ImproperlyConfigured('Public hosting requires one exact DNS hostname.')
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'portal']
MIDDLEWARE = ['portal.middleware.IngressMiddleware', 'django.middleware.security.SecurityMiddleware', 'whitenoise.middleware.WhiteNoiseMiddleware',
              'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.common.CommonMiddleware',
              'django.middleware.csrf.CsrfViewMiddleware', 'django.contrib.auth.middleware.AuthenticationMiddleware',
              'portal.middleware.CorrelationMiddleware']
ROOT_URLCONF = 'config.urls'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [], 'APP_DIRS': True}]
WSGI_APPLICATION = 'config.wsgi.application'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': RUNTIME / 'portal.sqlite3', 'OPTIONS': {'timeout': 20}}}
if os.environ.get('PORTAL_DB_HOST'):
    DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql', 'HOST': os.environ['PORTAL_DB_HOST'],
        'NAME': os.environ.get('PORTAL_DB_NAME', 'release_portal'), 'USER': os.environ.get('PORTAL_DB_USER', 'release_portal'),
        'PASSWORD': os.environ.get('PORTAL_DB_PASSWORD', ''), 'PORT': os.environ.get('PORTAL_DB_PORT', '5432'),
        'OPTIONS': {'sslmode': os.environ.get('PORTAL_DB_SSLMODE', 'verify-full')}}}
    if os.environ.get('PORTAL_DB_SSLROOTCERT'):
        DATABASES['default']['OPTIONS']['sslrootcert'] = os.environ['PORTAL_DB_SSLROOTCERT']
if not LOCAL and os.environ.get('PORTAL_DB_SSLMODE', 'verify-full') != 'verify-full':
    raise ImproperlyConfigured('Shared pilot database connections require verify-full TLS.')
if not LOCAL and DATABASES['default']['ENGINE'].endswith('sqlite3'):
    raise ImproperlyConfigured('Shared pilot mode requires PostgreSQL.')
AUTH_PASSWORD_VALIDATORS = [{'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'}]
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = not LOCAL
CSRF_COOKIE_SECURE = not LOCAL
SESSION_COOKIE_AGE = 8 * 60 * 60
SECURE_SSL_REDIRECT = not LOCAL
if os.environ.get('PORTAL_TRUST_PROXY') == '1':
    # Opt-in only: ingress must strip and replace this header.
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 86400 if not LOCAL else 0
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
USE_TZ = True
TIME_ZONE = 'UTC'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
STATIC_URL = '/assets/'
STATIC_ROOT = BASE_DIR.parent / 'dist' / 'client' / 'assets'
WHITENOISE_ROOT = BASE_DIR.parent / 'dist' / 'client'
OIDC_METADATA = os.environ.get('PORTAL_OIDC_METADATA', '')
OIDC_CLIENT_ID = os.environ.get('PORTAL_OIDC_CLIENT_ID', '')
OIDC_CLIENT_SECRET = os.environ.get('PORTAL_OIDC_CLIENT_SECRET', '')
OIDC_REDIRECT_URI = os.environ.get('PORTAL_OIDC_REDIRECT_URI', '')
if OIDC_METADATA and not OIDC_METADATA.startswith('https://'):
    raise ImproperlyConfigured('Corporate OIDC discovery requires HTTPS.')
if OIDC_REDIRECT_URI and not OIDC_REDIRECT_URI.startswith('https://'):
    raise ImproperlyConfigured('Corporate OIDC callback requires HTTPS.')
if AUTH_MODE == 'corporate' and not all([OIDC_METADATA, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI]):
    raise ImproperlyConfigured('Corporate OIDC configuration is required when corporate authentication is selected.')
JENKINS_URL = os.environ.get('PORTAL_JENKINS_URL', '')
JENKINS_JOB = os.environ.get('PORTAL_JENKINS_JOB', 'Demo-Application-CI')
JENKINS_USER = os.environ.get('PORTAL_JENKINS_USER', '')
JENKINS_TOKEN = os.environ.get('PORTAL_JENKINS_TOKEN', '')
if JENKINS_URL and not JENKINS_URL.startswith('https://') and not (LOCAL and JENKINS_URL.startswith('http://127.0.0.1:8080')):
    raise ImproperlyConfigured('Jenkins requires HTTPS outside local mode.')
LOGGING = {'version': 1, 'disable_existing_loggers': False, 'handlers': {'console': {'class': 'logging.StreamHandler'}},
           'loggers': {'portal': {'handlers': ['console'], 'level': 'INFO', 'propagate': False}}}
LOGGING['handlers']['discard'] = {'class': 'logging.NullHandler'}
for logger in ['django.request', 'django.security', 'django.server', 'waitress', 'botocore', 'boto3']:
    LOGGING['loggers'][logger] = {'handlers': ['discard'], 'propagate': False}
GITHUB_CLIENT_ID = os.environ.get('PORTAL_GITHUB_CLIENT_ID', '')
GITHUB_CLIENT_SECRET = os.environ.get('PORTAL_GITHUB_CLIENT_SECRET', '')
GITHUB_REDIRECT_URI = os.environ.get('PORTAL_GITHUB_REDIRECT_URI', '')
GITHUB_ORGANIZATIONS = os.environ.get('PORTAL_GITHUB_ORGS', 'macANTONIO213').split(',')
GITHUB_REVIEWER_IDS = set(os.environ.get('PORTAL_GITHUB_REVIEWER_IDS', '').split(',')) - {''}
GITHUB_ALLOWED_USER_IDS = set(os.environ.get('PORTAL_GITHUB_ALLOWED_USER_IDS', '').split(',')) - {''}
if PUBLIC and (len(GITHUB_ALLOWED_USER_IDS) < 2 or not GITHUB_REVIEWER_IDS or not GITHUB_REVIEWER_IDS <= GITHUB_ALLOWED_USER_IDS):
    raise ImproperlyConfigured('Public hosting requires approved GitHub user IDs and independent reviewer IDs.')
if any(not value.isdigit() for value in GITHUB_ALLOWED_USER_IDS):
    raise ImproperlyConfigured('GitHub allowed user IDs must be numeric.')
if any(not value.isdigit() for value in GITHUB_REVIEWER_IDS):
    raise ImproperlyConfigured('GitHub reviewer IDs must be numeric, comma-separated values.')
if not LOCAL and not all([GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_REDIRECT_URI]):
    raise ImproperlyConfigured('A registered GitHub App is required for shared hosting.')
if GITHUB_REDIRECT_URI and not GITHUB_REDIRECT_URI.startswith('https://'):
    raise ImproperlyConfigured('GitHub callback must use the approved HTTPS endpoint.')
if PUBLIC and GITHUB_REDIRECT_URI != 'https://' + ALLOWED_HOSTS[0] + '/auth/callback':
    raise ImproperlyConfigured('Public GitHub callback must exactly match the approved hostname.')
BUILD_IMAGE = os.environ.get('PORTAL_BUILD_IMAGE', '')
BUILD_NETWORK = os.environ.get('PORTAL_BUILD_NETWORK', '')
BUILD_RUNTIME = os.environ.get('PORTAL_BUILD_RUNTIME', '')
BUILD_EGRESS_CONFIRMED = os.environ.get('PORTAL_BUILD_EGRESS_CONFIRMED') == '1'
ARTIFACT_ROOT = Path(os.environ.get('PORTAL_ARTIFACT_ROOT') or str(RUNTIME / 'artifacts'))
if not ARTIFACT_ROOT.is_absolute():
    raise ImproperlyConfigured('PORTAL_ARTIFACT_ROOT must be an absolute private storage path.')
ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
AWS_DEPLOYMENT_ENABLED = os.environ.get('PORTAL_AWS_DEPLOYMENT_ENABLED') == '1'
DEPLOYMENT_TEMPLATE_APPROVED = os.environ.get('PORTAL_DEPLOYMENT_TEMPLATE_APPROVED') == '1'
if PUBLIC and (AWS_DEPLOYMENT_ENABLED or DEPLOYMENT_TEMPLATE_APPROVED or BUILD_IMAGE or BUILD_RUNTIME or BUILD_EGRESS_CONFIRMED):
    raise ImproperlyConfigured('Public hosting approval does not enable repository execution or application deployment.')
# Public source copy has no executable deployment target.
if AWS_DEPLOYMENT_ENABLED or DEPLOYMENT_TEMPLATE_APPROVED:
    raise ImproperlyConfigured('Demo deployment adapter is disabled until a new target is reviewed.')
# Values below are non-operational test fixtures, not an AWS assignment.
AWS_TARGET = {'account': '111122223333', 'region': 'ap-southeast-1',
    'instance': 'i-00000000000000000', 'bucket': 'demo-source-111122223333',
    'key': 'app.tar.gz', 'application_url': 'https://application.example.invalid'}
