import datetime
import json
import os
import tempfile

from django.contrib.auth import authenticate, get_user_model
from django.db.models import Q
from django.http import JsonResponse
from django_redis import get_redis_connection
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated
from seafileapi import SeafileAPI

from CorrectionPlatformBackend import settings
from CorrectionPlatformBackend.settings import repo_id, login_name, server_url, pwd
from accs.models import Roles, UserInfo, UserFile, Class
from accs.permissions import IsSuperAdmin
from accs.serializers import UserSerializer, UserInfoSerializer, RolesSerializer, \
     validate_image_content, ClassCreateSerializer, AssignStudentSerializer, ClassSerializer
from rest_framework.parsers import MultiPartParser, FormParser
import requests
from accs.utils.middleware import UUIDTools

User = get_user_model()


def csrf_failure(request, reason=""):
    return JsonResponse({"error": "CSRF验证失败"}, status=403)



class RegisterView(APIView):
    permission_classes = [AllowAny]

    @staticmethod
    def post(request):
        if not {'username', 'password', 'role_id','gender'}.issubset(request.data):
            return Response({"message": "缺少必填字段"}, status=400)
        if len(request.data['password']) < 8:
            return Response({"password": "密码长度需至少8位"}, status=400)
        uuid = UUIDTools().uuid4_hex()
        user_serializer = UserSerializer(data=request.data, context={'id': uuid})
        if user_serializer.is_valid():
            if request.data.get('role_id') is not None:
                user_serializer.save()
                userinfo_serializer = UserInfoSerializer(
                    data=request.data,
                    context={'userId': user_serializer.get_id()},
                    partial=True
                )
                if userinfo_serializer.is_valid():
                    userinfo_serializer.save()
                    return Response({
                        "code": 201,
                        "data": {
                            "user_id": user_serializer.get_id(),
                            "role_id": request.data['role_id']
                        },
                        "message": "注册成功"
                    }, status=status.HTTP_201_CREATED)

            else:
                return Response(
                    {"code": 400, "message": "角色ID不能为空", "data": None},
                    status=status.HTTP_400_BAD_REQUEST
                )

        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    @staticmethod
    def post(request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        # role = UserInfo.objects.get(user_id=user.id)
        if not user:
            return Response({
                "code": 401,
                "message": "用户名或密码错误",
                "result": None
            }, status=status.HTTP_200_OK)  # Vben通常接受200带错误码

        try:
            # 生成双令牌
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            # 存储到Redis
            redis_conn = get_redis_connection("token")
            user_id = user.id

            # 转换时间单位为整数秒
            access_expire = int(datetime.timedelta(minutes=30).total_seconds())
            refresh_expire = int(datetime.timedelta(days=7).total_seconds())

            # 使用正确参数顺序：name, time, value
            redis_conn.setex(
                name=f"access_{user_id}",
                time=access_expire,
                value=access_token.encode('utf-8')
            )
            redis_conn.setex(
                name=f"refresh_{user_id}",
                time=refresh_expire,
                value=refresh_token.encode('utf-8')
            )

            return Response({
                'code': 200,
                'message': '登录成功',
                'data': {
                    'accessToken': access_token
                }

            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": f"令牌生成失败: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            if not request.auth:
                return Response({"error": "未登录"}, status=400)

            print(type(request))

            user_id = request.user.id
            redis_conn = get_redis_connection("token")
            redis_conn.delete(f"access_{user_id}", f"refresh_{user_id}")

            return Response({"message": "成功登出"}, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)


class MyCustomBackend(TokenObtainPairView):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None


class ClassViewSet(viewsets.ModelViewSet):
    queryset = Class.objects.all()
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return ClassCreateSerializer
        return ClassSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=False, methods=['get'])
    def my_classes(self, request):
        """获取当前教师创建的班级"""
        classes = Class.objects.filter(created_by=request.user)
        serializer = self.get_serializer(classes, many=True)
        return Response(serializer.data)


class ClassAssignmentView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = AssignStudentSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)

        classroom = serializer.validated_data['class_id']
        student_ids = serializer.validated_data['student_ids']

        # 验证教师权限
        if classroom.created_by != request.user:
            return Response({
                "code": 403,
                "message": "无权操作其他教师的班级"
            }, status=403)

        # 批量关联学生
        students = User.objects.filter(id__in=student_ids)
        classroom.students.add(*students)

        return Response({
            "code": 200,
            "message": f"成功添加{len(students)}名学生"
        })

class CurrentUserView(RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """直接返回当前用户对象"""
        user = self.request.user
        user_info = UserInfo.objects.get(Q(userId=self.request.user.id))
        user.realName = user_info.realName
        user.avatar = user_info.avatar
        user.desc = user_info.desc
        user.homePath = user_info.homePath
        user.gender = user_info.gender
        user.role_id = user_info.role_id
        user.repo_id = user_info.repo_id
        user.token = self.request.headers.get('authorization').replace("Bearer ", "")
        return user  # 通过JWT自动解析用户身份

class UserModificationView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    def post(self, request):
        user = request.user
        user_info = UserInfo.objects.get(userId = user.id)
        redis_conn = get_redis_connection("default")
        user_serializer = UserSerializer
        seafile_file_uploaded = False

        try:
            if user_info.avatar == request.data['avatar'] \
                    and user_info.realName == request.data['realName'] \
                    and user_info.gender == request.data['gender']:
                    return Response({
                        "code": 406,
                        "data": {
                            "username": user.username,
                            "realName": user_info.realName,
                            "avatar": user_info.avatar,
                            "gender": user_info.gender
                        },
                        "message": "没有任何修改请检查!"
                    })
            if 'avatar' in request.FILES:
                seafile_api = SeafileAPI(login_name,pwd,server_url)
                avatar_file = request.FILES['avatar']
                try:
                    validate_image_content(avatar_file)  # 自定义验证函数
                except ValidationError as e:
                    return Response({
                        "code": 415,
                        "error": f"文件验证失败: {e.detail[0]}"
                    }, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

                ext = request.FILES.get("avatar").name.split(".")[-1]
                seafile_path = f"/ava/{user.id}_tmp_ava_upload.{ext}"
                path = f"/ava/{user.id}_ava_upload.{ext}"
                temp_filename = f'{user.id}_temp_ava_upload.{ext}'
                final_filename = f'{user.id}_ava_upload.{ext}'
                cache_key = f"{user.id}_tmp_ava_upload"

                try:
                    if not redis_conn.exists(cache_key):
                        return Response({"code": 404, "message": "无待确认的头像"}, status=404)
                    seafile_api.auth()

                    repo = seafile_api.get_repo(repo_id)

                    file_path = os.path.join("/ava",final_filename)

                    temp_path = os.path.join("/ava", temp_filename)
                    if final_filename in [x["name"] for x in repo.list_dir("/ava")]:
                        repo.delete_file(path)
                    repo.rename_file(seafile_path,final_filename)
                    seafile_file_uploaded = True
                    user_info = UserInfo.objects.get(userId=user.id)
                    user_info.avatar = f'{server_url}/files/{repo_id}{final_filename}'
                    user_info.save()

                    return Response({
                        "code": 200,
                        "avayar_url":user_info.avatar,
                        "message":"头像更新成功"
                    })
                except Exception as e:
                    return Response({
                        "code": 500,
                        "error":f"上传失败:{str(e)}"
                    },status=500)
            user_info_fields = ['realName', 'desc', 'homePath', 'avatar', 'gender']
            for field in user_info_fields:
                if field in request.data:
                    setattr(user_info, field, request.data[field])
            user.save()
            user_info.save()

            return Response({
                "username": user.username,
                "realName": user_info.realName,
                "code": 200,
                "data": {"avatar": str(user_info.avatar),
                         "gender": user_info.gender
                         },
                "message": "信息更新成功"
            })
        except Exception as e:
            return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # TODO: email 检测重复, 检测修改后的内容是否符合规范,完成后取消下方注释,头像修改逻辑,完成后,直接拿到地址,赋给下方avatar

class TempAvatarUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self,request):
        user = request.user
        avatar_file = request.FILES.get('avatar')
        ext = request.FILES.get('avatar').name.split('.')[-1]
        filename = f"{user.id}_tmp_ava_upload.{ext}"
        seafile_path = f"/ava/{user.id}_tmp_ava_upload.{ext}"  # Seafile中的存储路径
        try:
            seafile_api = SeafileAPI(login_name, pwd, server_url)
            seafile_api.auth()  # 认证

            # 获取仓库对象
            repo = seafile_api.get_repo(repo_id)

            # 创建临时目录保存文件（确保文件名正确）
            temp_dir = tempfile.mkdtemp()
            temp_file_path = os.path.join(temp_dir, filename)

            with open(temp_file_path, 'wb') as temp_file:
                for chunk in avatar_file.chunks():
                    temp_file.write(chunk)

            # 上传到Seafile
            if filename in [x["name"] for x in repo.list_dir("/ava")]:
                repo.delete_file(seafile_path)
            repo.upload_file("/ava", temp_file_path)
            seafile_file_uploaded = True

        # 构造文件访问URL
            avatar_url = f"{server_url.rstrip('/')}/avatar/{repo_id}{seafile_path}"

            # 用户头像信息
            user_info = UserInfo.objects.get(userId=user.id)
            old_avatar = user_info.avatar
            user_info.avatar = avatar_url
            user_info.save()

        # 缓存头像路径
            redis_conn = get_redis_connection("default")
            redis_conn.setex(
                name=f"{user.id}_tmp_ava_upload",
                time=3600,  # 1小时回滚有效期
                value=json.dumps(avatar_url)
            )

            return Response({
                "code": 200,
                "message": "头像上传成功"
            })
        except Exception as e:
            return Response({
                "code": 500,
                "error": f"上传失败：{str(e)}"
            }, status=500)

class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        if not user.check_password(old_password):  # 验证原密码
            return Response({"code": 400, "message": "原密码错误"}, status=400)

        if len(new_password) < 8:
            return Response({"code": 400, "message": "新密码长度需至少8位"}, status=400)

        user.set_password(new_password)  # 安全更新密码
        user.save()

        # 使旧令牌失效（根据你的Redis实现）
        redis_conn = get_redis_connection("token")
        redis_conn.delete(f"access_{user.id}", f"refresh_{user.id}")

        return Response({"code": 200, "message": "密码修改成功"})

class AdminRoleView(APIView):
    permission_classes = [IsSuperAdmin]

    # 获取所有角色
    def get(self, request):
        roles = Roles.objects.all()
        serializer = RolesSerializer(roles, many=True)
        return Response({
            "code": 200,
            "data": serializer.data,
            "message": "success"
        })

    # 创建角色
    def post(self, request):
        serializer = RolesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "code": 201,
                "data": serializer.data,
                "message": "角色创建成功"
            }, status=status.HTTP_201_CREATED)
        return Response({
            "code": 400,
            "errors": serializer.errors,
            "message": "验证失败"
        }, status=400)


class AdminRoleModificationView(APIView):
    permission_classes = [IsSuperAdmin]

    # 修改角色
    def post(self, request):
        try:
            role_id = request.data.get('role_id')
            role = Roles.objects.get(role_id=role_id)
            serializer = RolesSerializer(role, data=request.data)
            if not role_id:
                return Response({"code": 400,
                                 "message": "缺少角色ID"
                                 }, status=400)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "code": 200,
                    "data": serializer.data,
                    "message": "角色更新成功"
                })
            return Response({
                "code": 400,
                "errors": serializer.errors,
                "message": "验证失败"
            }, status=400)
        except Roles.DoesNotExist:
            return Response({
                "code": 404,
                "message": "角色不存在"
            }, status=404)

class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
