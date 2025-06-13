import json
import os
from datetime import timedelta
from pathlib import Path
from .base import *

# 允许最大100MB内存文件上传
DATA_UPLOAD_MAX_MEMORY_SIZE = 104857600  # 100MB
# 允许最大100MB非内存文件上传
FILE_UPLOAD_MAX_MEMORY_SIZE = 104857600

CORS_ALLOWED_ORIGINS = ['http://192.168.101.57:5666',
                        "http://127.0.0.1:5666",
                        'http://192.168.101.69:3000',
                        'http://192.168.101.32'
                        ]

# 允许携带cookie
CORS_ALLOW_CREDENTIALS = True

WSGI_APPLICATION = 'CorrectionPlatformBackend.wsgi.application'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'accs.authentication.CustomJWTAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
        'rest_framework.permissions.IsAuthenticated',
    ]
}

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

CACHES = {
    'default': {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://@127.0.0.1:6379/1",
        "KEY_PREFIX": "cache",  # 追加前缀双重保险
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    },
    "token": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://@127.0.0.1:6379/2",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            # "PASSWORD": "123456"
            "SOCKET_CONNECT_TIMEOUT": 5,
            "SOCKET_TIMEOUT": 5,
        },
        "KEY_PREFIX": "jwt_"
    },
    "invitation": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://@127.0.0.1:6379/3",
        "OPTIONS": {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }

    },
    "file": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://@127.0.0.1:6379/4",
        "OPTIONS": {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }

    },
    "answer": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://@127.0.0.1:6379/5",
        "OPTIONS": {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            "DECODE_RESPONSES": True
        }

    },
    "analyze": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://@127.0.0.1:6379/6",
        "OPTIONS": {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            "DECODE_RESPONSES": True
        }

    },
    'verify': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/7',
        'OPTIONS': {'CLIENT_CLASS': 'django_redis.client.DefaultClient'},
    },
}

ROLE_IDS = {
    'tea': 0,
    'stu': 1
}

MIDDLEWARE.insert(0, 'corsheaders.middleware.CorsMiddleware')

AUTHENTICATION_BACKENDS = (
    'accs.views.custom_system.MyCustomBackend',
    'django.contrib.auth.backends.ModelBackend',
)

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),  # 默认值
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{asctime}] {levelname} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'accs/role_audit.log'),
            'when': 'midnight',
            'backupCount': 30,
            'formatter': 'verbose'
        },
    },
    'loggers': {
        'role_audit': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    }
}

MIDDLEWARE.insert(0, 'corsheaders.middleware.CorsMiddleware')

TEMP_AVATAR_DIR = 'tmp/avatars'
FINAL_AVATAR_DIR = 'avatars'
# 回滚有效期24小时
AVATAR_ROLLBACK_TTL = 86400
# 临时存储目录
TEMP_FILE_DIR = 'tmp/files'
# 正式存储目录
FINAL_FILE_DIR = 'files'
# 文件回滚有效期(24小时)
FILE_ROLLBACK_TTL = 86400
# 100MB文件大小限制
MAX_FILE_SIZE = 104857600
# 允许的文件类型
ALLOWED_FILE_TYPES = ['pdf', 'docx', 'xlsx', "py"]

config = json.loads(open(Path.joinpath(BASE_DIR, '.config.json'), 'r', encoding='utf-8').read())

server_url = config["server_url"]
login_name = config["login_name"]
pwd = config["pwd"]
admin_repo_id = config["repo_id"]
DIFY_API_KEY = config["DIFY_API_KEY"]
DIFY_API_KEY_Answer = config["DIFY_API_KEY_Answer"]
