from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.db import models, transaction, IntegrityError

User = get_user_model()


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
        db_table = 'roles'
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

    class Meta:
        db_table = 'blacklistedtoken'
        verbose_name = "token黑名单"
        verbose_name_plural = "token黑名单"


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


class Class(models.Model):
    class_name = models.CharField(max_length=100, verbose_name="班级名称")  # , unique=True
    department_major = models.ForeignKey(
        DepartmentMajor,
        on_delete=models.CASCADE,
        verbose_name="所属院系专业"
    )
    created_at = models.DateTimeField("创建时间", auto_now_add=True)
    updated_at = models.DateTimeField("更新时间", auto_now=True)

    class Meta:
        db_table = 'class'
        verbose_name = '班级'
        unique_together = ('class_name', 'department_major')  # 确保班级与院系专业的唯一性

    def __str__(self):
        return f"{self.class_name} ({self.department_major.department} - {self.department_major.major})"


class Student(models.Model):
    # id = models.AutoField(primary_key=True)
    student_id = models.CharField(
        "学号",
        max_length=50,
        db_index=True,

    )
    name = models.CharField("姓名", max_length=50)
    class_info = models.ForeignKey(
        Class,  # 这里通过外键关联到 Class 表
        on_delete=models.PROTECT,  # 禁止删除班级
        verbose_name="班级",
        related_name="students",  # 可以通过 related_name 来反向查询学生
    )
    created_at = models.DateTimeField("创建时间", auto_now_add=True)
    updated_at = models.DateTimeField("更新时间", auto_now=True)

    class Meta:
        db_table = 'student'
        verbose_name = '学生'
        verbose_name_plural = '学生'
        ordering = ['student_id']
        unique_together = ('student_id', 'class_info')  # 确保同一学号在同一班级下唯一

    def __str__(self):
        return f"{self.student_id} - {self.name}"


class UserInfo(models.Model):
    userId = models.IntegerField(primary_key=True)
    student = models.OneToOneField(
        'Student',
        db_column='stu_id',  # 数据库中对应的列名为 stu_id
        on_delete=models.PROTECT,
        verbose_name="学号",
        related_name='user_info',  # 通过 student.user_info 可以反查到关联的 UserInfo
        null=True,
        blank=True,
        unique = True
    )
    class_id = models.ForeignKey(
        Class,  # 这里通过外键关联到 Class 表
        on_delete=models.PROTECT,  # 禁止删除班级
        verbose_name="班级",
        related_name="user_info",  # 可以通过 related_name 来反向查询学生
        null=True,
    )
    desc = models.TextField(max_length=500, null=True)
    homePath = models.CharField(max_length=100, null=True)
    avatar = models.CharField(max_length=255, null=True, default='avatars/default.png')
    realName = models.CharField(max_length=100, null=True)
    role_id = models.IntegerField(null=False)
    GENDER_CHOICES = ((0, '女'), (1, '男'), (2, '保密'))
    gender = models.SmallIntegerField(choices=GENDER_CHOICES, default=0)
    pub_repo_id = models.CharField(max_length=255, null=True, default='ad406967-dd0d-4d5c-949c-cdd62d21b9fe')
    pri_repo_id = models.CharField(max_length=255, null=True)
    AUDIT_CHOICES = ((0, '待审核'), (1, '已通过'), (2, '已拒绝'))
    audit = models.SmallIntegerField(choices=AUDIT_CHOICES, null=True)

    class Meta:
        db_table = 'user_info'
        verbose_name = '用户扩展信息'
        verbose_name_plural = '用户扩展信息'

    def __str__(self):
        return f"{self.userId} ({self.student_id if self.student else '无学号'})"


class SubmissionTemplate(models.Model):
    """
    教师创建的提交模板，用于学生针对某次作业进行提交。
    每次以同一标题新建时，自动计算版本号：同一教师、同一标题的 max(version) +1。
    """
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(User, related_name='created_templates', on_delete=models.CASCADE)
    version = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    due_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'sub-temp'
        unique_together = ('title', 'created_by', 'version')
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.pk:
            last = SubmissionTemplate.objects.filter(
                title=self.title,
                created_by=self.created_by
            ).order_by('-version').first()
            self.version = (last.version if last else 0) + 1
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.title} (v{self.version} by {self.created_by})"


class StudentSubmission(models.Model):
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    template = models.ForeignKey(SubmissionTemplate, on_delete=models.CASCADE)
    version = models.IntegerField()
    file_name = models.CharField(max_length=500)
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'stu-file'
        verbose_name = '学生文件'
        verbose_name_plural = '学生文件'


class AnalysisResult(models.Model):
    vulnerabilities = models.IntegerField()  # IntegerField：精确数字
    errors = models.IntegerField()
    code_smells = models.IntegerField()
    accepted_issues = models.IntegerField()
    duplicates = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)  # DateTimeField：时间，扫描时auto_now_add=True自动添加时间
    type = models.JSONField(default=list, blank=True)  # JSONField：JSON格式
    severity = models.CharField(max_length=50)  # CharField：短文本
    template = models.ForeignKey(SubmissionTemplate, on_delete=models.CASCADE)  # 关联模板
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # 关联用户
    correct_code = models.JSONField(default=list, blank=True)  # 存储正确代码
    description = models.JSONField(default=list, blank=True)  # 存储描述信息

    class Meta:
        db_table = 'answer'
        verbose_name = '分析结果'
        verbose_name_plural = '分析结果'

    def __str__(self):
        return f"Analysis Result for {self.template.title} (v{self.template.version}) by {self.user}"
