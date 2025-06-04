from django.contrib.auth.models import AbstractUser, User
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken
from CorrectionPlatformBackend import settings


# Create your models here.

class Roles(models.Model):
    ADMIN_ROLE_ID = 3
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


class Group(models.Model):
    GroupId = models.IntegerField(primary_key=True)
    school = models.CharField(max_length=255, null=True)
    specialty = models.CharField(max_length=255, null=True)
    college = models.CharField(max_length=255, null=True)
    study_groups = models.CharField(max_length=100, verbose_name="班级名称")


class GroupAssignment(models.Model):
    userId = models.CharField(max_length=255)
    study_groups = models.CharField(max_length=255)
    specialty = models.CharField(max_length=255, null=True)
    college = models.CharField(max_length=255, null=True)


class StuAssignment(models.Model):
    stuId = models.CharField(max_length=100, null=True)
    username = models.CharField(max_length=255)
    groupname = models.CharField(max_length=255)


class UserInfo(models.Model):
    # userId = models.OneToOneField(
    #     User,
    #     on_delete=models.CASCADE,  # 必须设置级联删除
    #     pspecialtyrimary_key=True,
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
    pub_repo_id = models.CharField(max_length=255,null=True,default='ad406967-dd0d-4d5c-949c-cdd62d21b9fe')
    pri_repo_id = models.CharField(max_length=255,null=True)


class AnalysisResult(models.Model):
    vulnerabilities = models.IntegerField()  # IntegerField：精确数字
    errors = models.IntegerField()
    code_smells = models.IntegerField()
    accepted_issues = models.IntegerField()
    duplicates = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)  # DateTimeField：时间，扫描时auto_now_add=True自动添加时间
    type = models.JSONField(default=list, blank=True)  # JSONField：JSON格式
    severity = models.CharField(max_length=50)  # CharField：短文本

    class Meta:
        db_table = 'code'
        # 指定数据库表名


class IPConfig(models.Model):
    """
    单独表，用于存储系统当前 Dify 服务 IP，所有用户均可操作。
    """
    ip_address = models.CharField(max_length=45)
    updated_at = models.DateTimeField(auto_now=True)  # auto_now=True，保存时自动设置时间

    class Meta:
        db_table = 'dify_ip_config'
        verbose_name = 'Dify IP 配置'
        verbose_name_plural = 'Dify IP 配置'
        ordering = ['-updated_at']


class DepartmentMajor(models.Model):
    department = models.CharField("院系", max_length=100)
    major = models.CharField("专业", max_length=100)
    created_at = models.DateTimeField("创建时间", auto_now_add=True)

    class Meta:
        db_table = 'department_major'
        verbose_name = '院系-专业'
        verbose_name_plural = '院系-专业'
        unique_together = ('department', 'major')  # 保证院系+专业不重复

    def __str__(self):
        return f"{self.department} - {self.major}"


class Student(models.Model):
    student_id = models.CharField("学号", max_length=50, unique=True, db_index=True)
    name = models.CharField("姓名", max_length=50)
    class_name = models.CharField("班级", max_length=50)
    department_major = models.ForeignKey(
        DepartmentMajor,
        on_delete=models.PROTECT,
        verbose_name="院系-专业",
        related_name="students"
    )
    created_at = models.DateTimeField("创建时间", auto_now_add=True)
    updated_at = models.DateTimeField("更新时间", auto_now=True)

    class Meta:
        db_table = 'student'
        verbose_name = '学生'
        verbose_name_plural = '学生'
        ordering = ['student_id']

    def __str__(self):
        return f"{self.student_id} - {self.name}"
