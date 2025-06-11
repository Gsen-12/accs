from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
ALLOWED_HOSTS = ['*']
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "accs",
        "USER": "root",
        "PASSWORD": "123456",
        "HOST": "127.0.0.1",
        "PORT": "3306",
        "CHARSET": "utf8mb4",
    },
}
