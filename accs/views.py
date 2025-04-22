import datetime
import os
import time
import uuid

from django.contrib.auth import authenticate, get_user_model
from django.core.files.storage import default_storage
from django.db.models import Q
from django.http import JsonResponse
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

from CorrectionPlatformBackend import settings
from accs.models import Roles, UserInfo, UserFile
from accs.permissions import IsSuperAdmin
from accs.serializers import UserSerializer, FileUploadSerializer, UserInfoSerializer, RolesSerializer, \
    AvatarUploadSerializer, validate_image_content
from rest_framework.parsers import MultiPartParser, FormParser

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

class AvatarChangeView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # 允许文件上传[8](@ref)

    def post(self, request):
        user = request.user
        user_info = UserInfo.objects.get(userId=user.id)
        redis_conn = get_redis_connection("default")
        temp_path = None
        response_data = {"code": 200, "message": "信息更新成功"}
        try:
            if 'avatar' in request.FILES:
                uploaded_file = request.FILES['avatar']

                try:
                    validate_image_content(uploaded_file)  # 调用自定义验证
                except ValidationError as e:
                    return Response({
                        "code": 415,
                        "error": f"文件验证失败: {e.detail[0]}"
                    }, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
                # 生成唯一临时路径（示例：tmp/avatars/temp_89ab3c_123.jpg）
                ext = uploaded_file.name.split('.')[-1]
                temp_filename = f"temp_{uuid.uuid4().hex[:6]}_{user.id}.{ext}"
                temp_path = default_storage.save(
                    os.path.join(settings.TEMP_AVATAR_DIR, temp_filename),
                    uploaded_file
                )

                # 缓存临时文件信息（有效期1小时）
                redis_conn.hmset(
                    f"avatar_temp_{user.id}",
                    {
                        'temp_path': temp_path,
                        'final_path': f"{settings.FINAL_AVATAR_DIR}/{user.id}_{int(time.time())}.{ext}",
                        'expire': str(int(time.time()) + 3600)
                    }
                )
                response_data["preview_url"] = f"/media/{temp_path}"  # 关键点3：动态添加字段
                response_data["message"] = "基本信息已更新，头像修改待确认"

                user.save()
                user_info.save()

                return Response(response_data)

        except Exception as e:
            if temp_path and default_storage.exists(temp_path):
                default_storage.delete(temp_path)
            return Response({
                "code": 500,
                "error": f"服务器错误: {str(e)}"
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

    def post(self, request):
        """分阶段上传文件到临时目录"""
        try:
            uploaded_file = request.FILES['file']

            # 文件验证
            if uploaded_file.size > settings.MAX_FILE_SIZE:
                return Response({"error": "文件大小超过100MB限制"}, status=413)

            ext = uploaded_file.name.split('.')[-1].lower()
            if ext not in settings.ALLOWED_FILE_TYPES:
                return Response({"error": "不支持的文件类型"}, status=415)

            # 生成临时存储路径
            temp_filename = f"temp_{uuid.uuid4().hex[:8]}_{request.user.id}.{ext}"
            temp_path = default_storage.save(
                os.path.join(settings.TEMP_FILE_DIR, temp_filename),
                uploaded_file
            )

            # Redis缓存文件信息
            redis_conn = get_redis_connection("default")
            redis_key = f"file_temp_{request.user.id}"
            redis_conn.hmset(redis_key, {
                'temp_path': temp_path,
                'original_name': uploaded_file.name,
                'expire': str(int(time.time()) + 3600)  # 1小时有效期
            })

            return Response({
                "code": 200,
                "preview_url": f"/media/{temp_path}",
                "message": "文件已暂存，请确认提交"
            })

        except KeyError:
            return Response({"error": "未接收到文件"}, status=400)

class FileConfirmView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """将临时文件转为正式存储"""
        temp_path=None
        user = request.user
        redis_conn = get_redis_connection("default")
        cache_key = f"file_temp_{user.id}"

        if not redis_conn.exists(cache_key):
            return Response({"code": 404, "message": "无待确认的文件"}, status=404)

        cache_data = redis_conn.hgetall(cache_key)
        try:
            temp_path = cache_data[b'temp_path'].decode()
            original_name = cache_data[b'original_name'].decode()

            # 创建正式存储路径（网页1）
            final_filename = f"{uuid.uuid4().hex[:8]}_{original_name}"
            final_path = os.path.join(settings.FINAL_FILE_DIR, final_filename)

            # 移动文件（网页4）
            with default_storage.open(temp_path) as src_file:
                saved_path = default_storage.save(final_path, src_file)

            # 创建数据库记录
            UserFile.objects.create(
                user=user,
                file=saved_path,
                is_temporary=False,
                original_name=original_name
            )

            # 清理缓存和临时文件
            redis_conn.delete(cache_key)
            default_storage.delete(temp_path)

            return Response({
                "code": 200,
                "file_url": f"/media/{saved_path}",
                "message": "文件已正式保存"
            })

        except Exception as e:
            if temp_path and default_storage.exists(temp_path):
                default_storage.delete(temp_path)
            return Response({
                "code": 500,
                "error": f"文件确认失败：{str(e)}"
            }, status=500)

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


class AvatarConfirmView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        redis_conn = get_redis_connection("default")
        cache_key = f"avatar_temp_{user.id}"

        # 验证缓存有效性
        if not redis_conn.exists(cache_key):
            return Response({"code": 404, "message": "无待确认的头像"}, status=404)

        cache_data = redis_conn.hgetall(cache_key)
        temp_path = cache_data[b'temp_path'].decode()
        final_path = cache_data[b'final_path'].decode()

        try:
            # 移动文件到正式目录
            with default_storage.open(temp_path) as src_file:
                default_storage.save(final_path, src_file)

            # 更新数据库记录
            user_info = UserInfo.objects.get(userId=user.id)
            old_avatar = user_info.avatar
            user_info.avatar = final_path
            user_info.save()

            # 清理缓存和临时文件
            redis_conn.delete(cache_key)
            default_storage.delete(temp_path)

            # 保存旧头像回滚点（参考网页6缓存策略）
            if old_avatar.startswith(settings.FINAL_AVATAR_DIR):
                redis_conn.setex(
                    f"avatar_rollback_{user.id}",
                    settings.AVATAR_ROLLBACK_TTL,
                    old_avatar
                )

            return Response({
                "code": 200,
                "avatar_url": f"/media/{final_path}",
                "message": "头像更新成功"
            })

        except Exception as e:
            # 事务回滚（参考网页5错误处理）
            default_storage.delete(final_path)
            return Response({
                "code": 500,
                "error": f"确认失败：{str(e)}"
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