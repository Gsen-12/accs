from django.contrib.auth.tokens import default_token_generator
from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from accs.models import Roles, UserFile


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class RolesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Roles
        fields = ['role_id', 'user_id']

    def create(self, validated_data):
        role = Roles.objects.create(**validated_data)
        return role


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
