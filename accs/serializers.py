import os

from rest_framework import serializers
from django.contrib.auth.models import User, Permission
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from accs.models import Roles, UserFile, UserInfo

class UserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserInfo
        fields = ['userId', 'desc','homePath','avatar', 'realName', 'role_id']

    def create(self, validated_data):
        userinfo = UserInfo.objects.create(**validated_data, userId=self.context.get("userId"))
        return userinfo

    def get(self):
        return self.data.items()

class UserSerializer(serializers.ModelSerializer):
    userId = serializers.IntegerField(read_only=True)
    desc = serializers.CharField(read_only=True)
    homePath = serializers.CharField(read_only=True)
    avatar = serializers.CharField(read_only=True)
    realName = serializers.CharField(read_only=True)
    role_id = serializers.IntegerField(read_only=True)
    token = serializers.CharField(read_only=True)

    email = serializers.EmailField(required=True)
    class Meta:
        model = User
        fields = [
            'id', 'username', 'password', 'email', 'userId','desc','homePath','avatar','realName','role_id', 'token'
        ]
        extra_kwargs = {'password': {'write_only': True}}

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


class FileUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserFile
        fields = ['file']
        extra_kwargs = {
            'file': {'write_only': True}
        }


