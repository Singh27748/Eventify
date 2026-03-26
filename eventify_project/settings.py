"""
Django settings for eventify_project project.
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file(BASE_DIR / ".env")


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'jsYK_qHnMb7IHSSefFLxZ43N4l0zNtXpXTYAzfpNsJkPiL3d4cpPyIjIw2aaBn-R3XU'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core.apps.CoreConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'core.middleware.PanelTransportEncryptionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'core.middleware.ProfileCompletionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'core.middleware.SessionSecurityMiddleware',
    'core.middleware.SecurityHeadersMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'eventify_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'eventify_project.wsgi.application'


# Database
# Default is SQLite. Set USE_MYSQL=1 to switch to MySQL.
def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


USE_MYSQL = env_bool("USE_MYSQL", False)

if USE_MYSQL:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "NAME": os.getenv("MYSQL_DATABASE", "mydb"),
            "USER": os.getenv("MYSQL_USER", "root"),
            "PASSWORD": os.getenv("MYSQL_PASSWORD", ""),
            "HOST": os.getenv("MYSQL_HOST", "127.0.0.1"),
            "PORT": os.getenv("MYSQL_PORT", "3306"),
            "CONN_MAX_AGE": int(os.getenv("MYSQL_CONN_MAX_AGE", "60")),
            "OPTIONS": {
                "charset": "utf8mb4",
                "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
            },
        }
    }
else:
    default_sqlite_name = (
        "eventify_db.sqlite3"
        if (BASE_DIR / "eventify_db.sqlite3").exists()
        else "db.sqlite3"
    )
    sqlite_db_name = os.getenv("SQLITE_DB_NAME", default_sqlite_name).strip() or default_sqlite_name
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / sqlite_db_name,
        }
    }


# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 10},
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'core.password_validators.StrongPasswordPolicyValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.0/howto/static-files/

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

LOGIN_URL = "auth_page"
SESSION_INACTIVITY_TIMEOUT = int(os.getenv("SESSION_INACTIVITY_TIMEOUT", "1800") or "1800")
LOGIN_LOCKOUT_ATTEMPTS = int(os.getenv("LOGIN_LOCKOUT_ATTEMPTS", "5") or "5")
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "10") or "10")
DJANGO_ADMIN_URL = (
    (os.getenv("DJANGO_ADMIN_URL", "secure-admin-portal") or "secure-admin-portal").strip("/")
    + "/"
)
DEFAULT_ADMIN_EMAIL = (os.getenv("DEFAULT_ADMIN_EMAIL", "asing27748@gmail.com") or "asing27748@gmail.com").strip().lower()

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
CSRF_COOKIE_SECURE = env_bool("CSRF_COOKIE_SECURE", False)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "ignore_broken_pipe": {
            "()": "eventify_project.logging_filters.IgnoreBrokenPipeFilter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "filters": ["ignore_broken_pipe"],
        },
    },
    "loggers": {
        "django.server": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# Email Configuration for OTP
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "asing27748@gmail.com"
EMAIL_HOST_PASSWORD = "ybbsgmaapaamvivx"
DEFAULT_FROM_EMAIL = "Eventify <asing27748@gmail.com>"

# OAuth configuration
GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
GOOGLE_OAUTH_REDIRECT_URI = os.getenv("GOOGLE_OAUTH_REDIRECT_URI", "").strip()
GITHUB_OAUTH_CLIENT_ID = os.getenv("GITHUB_OAUTH_CLIENT_ID", "").strip()
GITHUB_OAUTH_CLIENT_SECRET = os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "").strip()
GITHUB_OAUTH_REDIRECT_URI = os.getenv("GITHUB_OAUTH_REDIRECT_URI", "").strip()

# Razorpay configuration
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "").strip()
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
RAZORPAY_CURRENCY = os.getenv("RAZORPAY_CURRENCY", "INR").strip() or "INR"

# AI support assistant configuration
AI_SUPPORT_PROVIDER = (os.getenv("AI_SUPPORT_PROVIDER", "ollama") or "ollama").strip().lower()
AI_SUPPORT_OLLAMA_BASE_URL = (
    os.getenv("AI_SUPPORT_OLLAMA_BASE_URL", "http://127.0.0.1:11434/api")
    or "http://127.0.0.1:11434/api"
).rstrip("/")
AI_SUPPORT_CHAT_MODEL = os.getenv("AI_SUPPORT_CHAT_MODEL", "llama3.1:8b").strip() or "llama3.1:8b"
AI_SUPPORT_TIMEOUT_SECONDS = int(os.getenv("AI_SUPPORT_TIMEOUT_SECONDS", "15") or "15")
