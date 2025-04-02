import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.

class Roles(models.Model):
    role_id = models.IntegerField(primary_key=True)
    user_id = models.IntegerField(null=False)


class BlacklistedToken(models.Model):
    token = models.CharField(max_length=500, unique=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def add(cls, token):
        # 将 Token 字符串存入黑名单
        refresh = RefreshToken(token)
        cls.objects.create(token=str(refresh))


class UUIDTools(object):
    @staticmethod
    def uuid4_hex():
        return uuid.uuid4().hex