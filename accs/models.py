import uuid

from django.contrib.auth.models import AbstractUser, User
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.

class Roles(models.Model):
    role_id = models.AutoField(primary_key=True)  # 改为自增字段
    role_name = models.CharField(max_length=200, unique=True)
    permissions = models.ManyToManyField(
        'auth.Permission',
        blank=True,
        verbose_name='权限集合',
        related_name='role_set'
    )

    def changes(self, old_instance):
        diff = {}
        for field in self._meta.fields:
            new_val = getattr(self, field.name)
            old_val = getattr(old_instance, field.name)
            if new_val != old_val:
                diff[field.verbose_name] = (old_val, new_val)
        return diff

    class Meta:
        verbose_name = "角色"
        verbose_name_plural = "角色"

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
    # userId = models.OneToOneField(
    #     User,
    #     on_delete=models.CASCADE,  # 必须设置级联删除
    #     primary_key=True,
    #     related_name='userinfo'
    # )
    userId = models.IntegerField(primary_key=True)
    desc = models.TextField(max_length=500, null=True)
    homePath = models.CharField(max_length=100, null=True)
    avatar = models.CharField(max_length=100, null=True)
    realName = models.CharField(max_length=100, null=True)
    role_id = models.IntegerField(null=False)
