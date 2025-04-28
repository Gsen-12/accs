from django.contrib.auth.models import AbstractUser, User
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken

from CorrectionPlatformBackend import settings


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
    # 新增字段
    is_temporary = models.BooleanField(default=True)
    original_name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    seafile_file_id = models.CharField(max_length=100, unique=True)  # 新增Seafile文件ID
    file_hash = models.CharField(max_length=64)  # SHA256哈希值

    def get_seafile_url(self):
        """生成文件访问链接"""
        return f"{settings.SEAFILE_API_URL}/files/{self.seafile_file_id}/download"

    def get_final_path(self):
        return f"{settings.FINAL_FILE_DIR}/{self.original_name}"

class Class(models.Model):
    class_id = models.AutoField(primary_key=True)
    class_name = models.CharField(max_length=100, unique=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='created_classes'
    )
    students = models.ManyToManyField(
        User,
        related_name='student_classes',
        limit_choices_to={'userinfo__role_id': 1}  # 仅允许关联学生
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "班级"
        verbose_name_plural = "班级"
        unique_together = ('class_name', 'created_by')  # 同教师下班级名不可重复

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
    avatar = models.CharField(max_length=255, null=True, default='avatars/default.png')
    realName = models.CharField(max_length=100, null=True)
    role_id = models.IntegerField(null=False)
    GENDER_CHOICES = ((0, '女'), (1, '男'), (2, '保密'))
    gender = models.SmallIntegerField(choices=GENDER_CHOICES, default=0)
    classes = models.ManyToManyField(
        Class,
        through='ClassMembership',  # 关键点1：明确指定中间模型
        through_fields=('user_info', 'classroom'),  # 关键点2：声明关联字段
        related_name='members'
    )
class ClassMembership(models.Model):
    # 关键点3：正确的外键命名和关联
    user_info = models.ForeignKey(
        UserInfo,
        on_delete=models.CASCADE,
        related_name='class_relations'  # 自定义反向关联名
    )
    classroom = models.ForeignKey(
        Class,
        on_delete=models.CASCADE,
        related_name='student_relations'  # 自定义反向关联名
    )
    join_date = models.DateField(auto_now_add=True)

    class Meta:
        # 确保唯一性约束
        unique_together = ('user_info', 'classroom')