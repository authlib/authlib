SECRET_KEY = "django-secret"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]

SESSION_ENGINE = "django.contrib.sessions.backends.cache"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "unique-snowflake",
    }
}

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "tests.django.test_oauth1",
    "tests.django.test_oauth2",
]

USE_TZ = True
