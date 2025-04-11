import uuid

from MySQLdb.constants.FIELD_TYPE import VARCHAR
from django.contrib.auth.models import AbstractUser, User
from django.core.validators import FileExtensionValidator
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.

class Roles(models.Model):
    role_id = models.IntegerField(primary_key=True)
    role_name = models.CharField(max_length=200, null=False)



class BlacklistedToken(models.Model):
    token = models.CharField(max_length=255, unique=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def add(cls, token):
        # 将 Token 字符串存入黑名单
        refresh = RefreshToken(token)
        cls.objects.create(token=str(refresh))

class UserFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/%Y/%m/%d/')
    uploaded_at = models.DateTimeField(auto_now_add=True)  # 自动记录上传时间

class UserInfo(models.Model):
    userId = models.IntegerField(primary_key=True)
    desc = models.TextField(max_length=500, null=True)
    homePath = models.CharField(max_length=100, null=True)
    avatar = models.CharField(max_length=100, null=True)
    realName = models.CharField(max_length=100, null=True)
    role_id = models.IntegerField(null=False)
