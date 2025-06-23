from django.core.validators import FileExtensionValidator
from django.contrib.auth.models import User, Permission
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from accs.models import Roles, UserInfo, DepartmentMajor, StudentSubmission, SubmissionTemplate
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from PIL import Image
from .models import AnalysisResult


def validate_image_content(value):
    """
    深度验证图像文件内容（安全增强）
    功能：
    1. 验证文件头合法性
    2. 检测图像文件损坏
    3. 限制最大尺寸
    """
    try:
        # --- 验证1：文件头检查 ---
        value.seek(0)
        header = value.read(4)
        if not header.startswith((b'\xff\xd8\xff', b'\x89PNG')):
            raise ValidationError("非标准JPEG/PNG文件头")
        value.seek(0)

        # --- 验证2：Pillow格式验证 ---
        img = Image.open(value)
        img.verify()  # 检测文件完整性

        # --- 验证3：尺寸限制 ---
        value.seek(0)
        img = Image.open(value)
        if max(img.size) > 5000:  # 限制最大边长
            raise ValidationError("图片尺寸超过5000px限制")
        value.seek(0)

        return value
    except IOError as e:
        raise ValidationError(f"图像文件损坏: {str(e)}")
    except Exception as e:
        raise ValidationError(f"非法图像内容: {str(e)}")
    finally:
        if hasattr(value, 'seekable') and value.seekable():
            value.seek(0)  # 确保文件指针重置


class UserInfoSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(
        write_only=True,
        required=False,
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png']),
            validate_image_content  # 直接引用验证函数
        ]
    )

    class Meta:
        model = UserInfo
        fields = ['userId', 'desc', 'homePath', 'avatar', 'realName', 'role_id', 'gender', 'pri_repo_id', 'pub_repo_id']

    def create(self, validated_data):
        userinfo = UserInfo.objects.create(**validated_data, userId=self.context.get("userId"))
        return userinfo

    def get(self):
        return self.data.items()


class UserSerializer(serializers.ModelSerializer):
    userId = serializers.IntegerField(read_only=True)
    desc = serializers.CharField(read_only=True)
    homePath = serializers.CharField(read_only=True)
    avatar = serializers.CharField(required=False)
    realName = serializers.CharField(read_only=True)
    role_id = serializers.IntegerField(read_only=True)
    token = serializers.CharField(read_only=True)
    gender = serializers.IntegerField(read_only=True)
    email = serializers.EmailField(required=True)
    pri_repo_id = serializers.CharField(required=False)
    pub_repo_id = serializers.CharField(required=False)
    class Meta:
        model = User
        fields = [
            'id', 'username', 'password', 'email', 'userId', 'desc', 'homePath', 'avatar', 'realName', 'role_id',

            'token', 'gender', 'pri_repo_id', 'pub_repo_id'

        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'required': False},
            'role_id': {'required': False},
        }

    # def get_role_id(self, obj):
    #     try:
    #         return Roles.objects.get(user_id=obj.id).role_id  # 动态获取角色ID[5](@ref)
    #     except Roles.DoesNotExist:
    #         return None

    def get_id(self):
        return self.context.get("id")

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data, id=self.context.get("id"))
        return user

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("该邮箱已被注册")
        return value

    def validate_real_name(self, value):
        if User.objects.filter(real_name=value).exists():
            raise serializers.ValidationError("该真实姓名已被使用")
        return value


class RolesSerializer(serializers.ModelSerializer):
    permissions = serializers.SlugRelatedField(
        many=True,
        slug_field='codename',
        queryset=Permission.objects.all()
    )

    class Meta:
        model = Roles
        fields = ['role_id', 'role_name', 'permissions']
        extra_kwargs = {
            'role_name': {'validators': []}  # 禁用唯一性验证
        }

    def validate_role_name(self, value):
        if Roles.objects.filter(role_name=value).exists():
            raise serializers.ValidationError("角色名称已存在")
        return value


class UserRoleUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserInfo
        fields = ['role_id']  # 只包含需要更新的字段
        extra_kwargs = {
            'role_id': {'required': True}
        }

    def validate_role_id(self, value):
        """验证角色是否有效"""
        if not Roles.objects.filter(role_id=value).exists():
            raise serializers.ValidationError("指定的角色不存在")
        return value


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super(MyTokenObtainPairSerializer, cls).get_token(user)
        # 添加额外信息
        token['username'] = user.username
        return token

    # def generate_access_token(cls, user):
    #     access_token = default_token_generator.make_token(user)
    #     return access_token


class AvatarUploadSerializer(serializers.Serializer):
    avatar = serializers.ImageField(
        allow_empty_file=False,
        max_length=100,
        help_text="支持格式：JPEG/PNG，最大5MB",
        validators=[
            FileExtensionValidator(allowed_extensions=["jpg", "jpeg", "png"]),
            # 新增内容类型验证
            lambda value: ValidationError("仅支持JPEG/PNG")
            if value.content_type not in ["image/jpeg", "image/png"]
            else None
        ]
    )

    def validate_avatar(self, value):
        # 文件验证（2MB限制，支持JPG/PNG）
        if value.size > 2 * 1024 * 1024:
            raise ValidationError("头像大小不能超过2MB")
        if value.content_type not in ['image/jpeg', 'image/png']:
            raise ValidationError("仅支持JPEG/PNG格式")
        return value


class DepartmentMajorSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(
        format="%Y-%m-%d %H:%M:%S",  # 年-月-日 时:分:秒
        read_only=True  # 因为这是 auto_now_add，所以只读
    )

    class Meta:
        model = DepartmentMajor
        fields = ['id', 'department', 'major', 'created_at']
        read_only_fields = ['id', 'created_at']


class AnalysisSerializer(serializers.ModelSerializer):
    # 覆盖 timestamp 字段，指定输出日期时间格式
    timestamp = serializers.DateTimeField(
        format="%Y-%m-%d %H:%M:%S",  # 年-月-日 时:分:秒
        read_only=True  # 因为这是 auto_now_add，所以只读
    )

    class Meta:
        model = AnalysisResult
        fields = [
            'vulnerabilities',
            'errors',
            'code_smells',
            'accepted_issues',
            'duplicates',
            'timestamp',
            'type',
            'severity',
            # 如果有 user 字段也要列出来
        ]


class SubmissionTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubmissionTemplate
        fields = ['id', 'title', 'description', 'due_date', 'created_by', 'created_at']
        read_only_fields = ['id', 'created_by', 'created_at']


class StudentSubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentSubmission
        fields = ['id', 'template', 'student', 'file_path', 'version', 'submitted_at']
        read_only_fields = ['id', 'submitted_at']

