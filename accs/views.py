import datetime
import shutil
import uuid
from pathlib import Path

from django.contrib.auth import authenticate, get_user_model
from django.core.files.storage import default_storage
from django.db.models import Q
from django.http import JsonResponse
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

from accs.models import Roles, UserInfo
from accs.permissions import IsSuperAdmin
from accs.serializers import UserSerializer, FileUploadSerializer, UserInfoSerializer, RolesSerializer, \
    AvatarUploadSerializer
from rest_framework.parsers import MultiPartParser, FormParser

from accs.utils.middleware import UUIDTools

User = get_user_model()


def csrf_failure(request, reason=""):
    return JsonResponse({"error": "CSRF验证失败"}, status=403)


# Create your views here.


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
                    # return Response(user_serializer.data, status=status.HTTP_201_CREATED)

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
        # userinfo_serializer = UserInfoSerializer(data=request.data)
        user = authenticate(username=username, password=password)
        # role = UserInfo.objects.get(user_id=user.id)
        if not user:
            return Response({
                "code": 401,
                "message": "用户名或密码错误",
                "result": None
            }, status=status.HTTP_200_OK)  # Vben通常接受200带错误码
            # return Response({'code': 401, 'msg': '认证失败'})
            # return Response({"error": "无效的凭证"}, status=status.HTTP_401_UNAUTHORIZED)

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
            # return Response({"error": f"令牌生成失败: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # refresh_token = request.data.get('refresh')
            # access_token = request.auth
            #

            if not request.auth:
                return Response({"error": "未登录"}, status=400)
            # # 加入黑名单
            # add_to_blacklist(access_token)
            # add_to_blacklist(RefreshToken(refresh_token))

            print(type(request))

            # 清理Redis存储
            user_id = request.user.id
            redis_conn = get_redis_connection("token")
            redis_conn.delete(f"access_{user_id}", f"refresh_{user_id}")

            return Response({"message": "成功登出"}, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)


# MyCustomBackend
class MyCustomBackend(TokenObtainPairView):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None


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
        user.token = self.request.headers.get('authorization').replace("Bearer ", "")
        return user  # 通过JWT自动解析用户身份


class UserModificationView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def post(self, request):
        user = request.user  # 直接获取当前登录用户
        user_info = UserInfo.objects.get(userId = user.id)

        if 'email' in request.data:
            if User.objects.exclude(pk = user.id).filter(email=request.data['email']).exists():
                return Response({"code": 400, "message": "邮箱已被使用"}, status=400)
            user.email = request.data['email']

        if'username' in request.data:
            if User.objects.exclude(pk = user.id).filter(username=request.data['username']).exists():
                return Response({"code": 400, "message": "用户名已存在"}, status=400)
            user.username = request.data['username']

            # 更新UserInfo扩展信息
            user_info_fields = ['realName', 'desc', 'homePath', 'avatar','gender']
            for field in user_info_fields:
                if field in request.data:
                    setattr(user_info, field, request.data[field])
            user.save()
            user_info.save()

            return Response({
                "code": 200,
                "data": {
                    "username": user.username,
                    "realName": user_info.realName,
                    "avatar": user_info.avatar,
                    "gender": user_info.gender
                },
                "message": "信息更新成功"
            })


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
    #permission_classes = [IsAuthenticated]
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]  # 支持multipart表单数据

    # max_upload_size = 104857600  # 100MB
    # def handle_exception(self, exc):
    #     if isinstance(exc, serializers.ValidationError):
    #         return Response(
    #             {"error": "文件验证失败", "detail": exc.detail},
    #             status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    #         )
    #     return super().handle_exception(exc)
    def post(self, request):
        serializer = FileUploadSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid():
            # 自动关联当前登录用户
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AvatarUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self,request):
        serializer = AvatarUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)
        user = request.user
        ext = request.FILES.get('avatar').name.split('.')[-1]
        filename = f"{uuid.uuid4().hex[:8]}_{user.id}.{ext}"
        upload_path = f"tmp/avatars/{filename}"
        try:
            print( request.FILES['avatar'])
            default_storage.save(upload_path, request.FILES['avatar'])

            user_info = UserInfo.objects.get(userId=user.id)
            old_avatar = user_info.avatar
            user_info.avatar = upload_path
            user_info.save()

            # 缓存旧头像路径（用于回滚）
            redis_conn = get_redis_connection("default")
            redis_conn.setex(
                name=f"avatar_rollback_{user.id}",
                time=3600,  # 1小时回滚有效期
                value=old_avatar.encode('utf-8')
            )

            return Response({
                "code": 200,
                "data": {"avatar_url": f"/media/{upload_path}"},
                "message": "头像上传成功"
            })
        except Exception as e:
            return Response({
                "code": 500,
                "error": f"上传失败：{str(e)}"
            }, status=500)


class AvatarRollbackView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        redis_conn = get_redis_connection("default")

        if old_avatar := redis_conn.get(f"avatar_rollback_{user.id}"):
            # 执行数据库回滚
            UserInfo.objects.filter(userId=user.id).update(avatar=old_avatar.decode())
            return Response({"code": 200, "message": "头像回滚成功"})

        return Response({"code": 404, "message": "无可用回滚版本"}, status=404)