import datetime
import json
import os
import tempfile
import uuid
from linecache import cache

from django.contrib.auth import authenticate, get_user_model
from django.db.models import Q
from django.http import JsonResponse
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated
from seafileapi import SeafileAPI
import re
from rest_framework.decorators import api_view
from .models import AnalysisResult, IPConfig
from .serializers import AnalysisSerializer
from rest_framework.permissions import AllowAny
from .services import DifyService, get_reliable_local_ip, DifyAnswer
from CorrectionPlatformBackend.settings import repo_id, login_name, server_url, pwd
from accs.models import Roles, UserInfo, Group, GroupAssignment
from accs.permissions import IsSuperAdmin, IsTeacher
from accs.serializers import UserSerializer, UserInfoSerializer, RolesSerializer, \
    validate_image_content, GroupSerializer
from rest_framework.parsers import MultiPartParser, FormParser
from accs.utils.middleware import UUIDTools

User = get_user_model()


def csrf_failure(request, reason=""):
    return JsonResponse({"error": "CSRF验证失败"}, status=403)


class RegisterView(APIView):
    permission_classes = [AllowAny]

    @staticmethod
    def post(request):
        if not {'username', 'password', 'role_id', 'gender'}.issubset(request.data):
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
            return None
        except Exception as e:
            return None


class CreateGroupView(APIView):
    permission_classes = [IsSuperAdmin]

    @staticmethod
    def post(request):
        if not {'study_groups'}.issubset(request.data):
            return Response({"message": "缺少必填字段"}, status=400)
        uuid = UUIDTools().uuid4_hex()
        group_serializer = GroupSerializer(
            data=request.data,
            context={'request': request, 'GroupId': uuid}
        )
        if group_serializer.is_valid():
            group_serializer.save()
            return Response({
                "code": 201,
                "data": {
                    "GroupId": group_serializer.get_id(),
                    "study_groups": request.data['study_groups']
                },
                "message": "班级创建成功"
            }, status=status.HTTP_201_CREATED)
        return Response(group_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AssignGroupView(APIView):
    permissions_classes = [IsTeacher]

    @staticmethod
    def post(request):
        if not {'user_id', 'group_id'}.issubset(request.data):
            return Response({"message": "缺少必填字段"}, status=400)
        user_id = request.data.get('user_id')
        group_id = request.data.get('group_id')
        if request.user.userinfo.role_id == 2:
            return Response({"code": 404, "message": "用户为老师"}, status=404)
        # if request.user.userinfo.role_id == 3:

        try:
            user = User.objects.get(id=user_id)
            if request.user.userinfo.role_id == 2:
                return Response({"code": 404, "message": "用户为老师"}, status=404)
            group = Group.objects.get(GroupId=group_id)
        except User.DoesNotExist:
            return Response({"code": 404, "message": "用户不存在"}, status=404)
        except Group.DoesNotExist:

            return Response({"code": 404, "message": "班级不存在"}, status=404)
        try:
            assignment, created = GroupAssignment.objects.get_or_create(
                userId=user_id,
                groupId=group_id,
                defaults={'userId': user_id, 'groupId': group_id}
            )
            if not created:
                return Response({"code": 409, "message": "用户已在该班级中"}, status=409)

            return Response({
                "code": 200,
                "data": {
                    "user_id": user_id,
                    "group_id": group_id
                },
                "message": "加入班级成功"
            }, status=200)
        except Exception as e:
            return Response({"code": 500, "error": str(e)}, status=500)


class InvitationCodeview(APIView):
    permissions_classes = [IsTeacher]

    @staticmethod
    def post(request):
        group_id = request.data.get('group_id')
        group = Group.objects.get(GroupId=group_id)
        try:
            invitation_code = uuid.uuid4().hex[:8]
            redis_conn = get_redis_connection("invitation")
            redis_conn.setex(
                name=group_id,
                time=3600,  # 1小时回滚有效期
                value=json.dumps(invitation_code)
            )
            return Response({
                "code": 200,
                "error": f"获取邀请码成功",
                'data': {invitation_code}
            }, status=200)
        except Exception as e:
            return Response({
                "code": 500,
                "error": f"获取邀请码失败：{str(e)}"
            }, status=500)


class JoinGroupView(APIView):
    permissions_classes = [IsAuthenticated]

    @staticmethod
    def post(request):
        if not {'group_id', 'invitation_code'}.issubset(request.data):
            return Response({"message": "缺少必填字段"}, status=400)
        redis_conn = get_redis_connection('invitation')
        stored_code = redis_conn.get(request.data['group_id'])

        if not stored_code:
            return Response({
                'code': 404,
                'message': '邀请码已过期'
            }, status=404)
        if request.data['invitation_code'] != json.loads(stored_code):
            return Response({
                "code": 403,
                "message": "邀请码无效"
            }, status=403)

        try:
            # 检查当前用户是否已有班级关联记录
            # 使用当前登录用户的ID过滤GroupAssignment表记录
            existing_assignments = GroupAssignment.objects.filter(userId=request.user.id)

            if existing_assignments.exists():
                return Response({
                    'code': 409,
                    'message': '您已加入其他班级或已在本班级中，确认要覆盖吗？',
                    'existing_groups': [
                        str(ass.groupId) for ass in existing_assignments  # 遍历查询集提取班级ID
                    ]
                }, status=409)
            assignment, created = GroupAssignment.objects.get_or_create(
                userId=request.user.id,
                groupId=request.data['group_id'],
                defaults={
                    'userId': request.user.id,
                    'groupId': request.data['group_id'],
                }
            )
            if not created:
                return Response({
                    'code': 406,
                    'message': '已在本班级中'
                }, status=406)
            return Response({
                'code': 200,
                'data': {
                    'group_id': request.data['group_id'],
                }
            }, status=200)
        except Exception as e:
            return Response({"code": 500, "error": str(e)}, status=500)


class JoinConfirmView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # 需要接收确认参数和班级ID
        if not {'group_id', 'confirm'}.issubset(request.data):
            return Response({"code": 400, "message": "缺少必要参数"}, status=400)

        if request.data['confirm'] == 'true':
            # 删除原有班级关联
            GroupAssignment.objects.filter(userId=request.user.id).delete()

            # 创建新关联
            GroupAssignment.objects.create(
                userId=request.user.id,
                groupId=request.data['group_id']
            )
            return Response({'code': 200, 'message': '班级覆盖成功'})

        if request.data['confirm'] == 'false':
            return Response({'code': 406, 'message': '取消覆盖操作'}, status=406)


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
        user_info = UserInfo.objects.get(userId=user.id)
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
                seafile_api = SeafileAPI(login_name, pwd, server_url)
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

                    if final_filename in [x["name"] for x in repo.list_dir("/ava")]:
                        repo.delete_file(path)
                    repo.rename_file(seafile_path, final_filename)
                    user_info = UserInfo.objects.get(userId=user.id)
                    user_info.avatar = f'{server_url}/files/{repo_id}{final_filename}'
                    user_info.save()

                    return Response({
                        "code": 200,
                        "avayar_url": user_info.avatar,
                        "message": "头像更新成功"
                    })
                except Exception as e:
                    return Response({
                        "code": 500,
                        "error": f"上传失败:{str(e)}"
                    }, status=500)
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


class TempAvatarUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
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

            # 构造文件访问URL
            avatar_url = f"{server_url.rstrip('/')}/avatar/{repo_id}{seafile_path}"

            # 用户头像信息
            user_info = UserInfo.objects.get(userId=user.id)
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

    def post(self, request):
        user = request.user
        user_file = request.FILES.get('file')
        ext = request.FILES.get('file').name.split('.')[-1]
        filename = f"{user.id}_file_upload.{ext}"
        seafile_path = f"/file/{user.id}_file_upload.{ext}"  # Seafile中的存储路径
        try:
            seafile_api = SeafileAPI(login_name, pwd, server_url)
            seafile_api.auth()  # 认证

            # 获取仓库对象
            repo = seafile_api.get_repo(repo_id)

            # 创建临时目录保存文件（确保文件名正确）
            dir = tempfile.mkdtemp()
            file_path = os.path.join(dir, filename)

            with open(file_path, 'wb') as temp_file:
                for chunk in user_file.chunks():
                    temp_file.write(chunk)

            # 上传到Seafile
            if filename in [x["name"] for x in repo.list_dir("/file")]:
                repo.delete_file(seafile_path)
            repo.upload_file("/file", file_path)

            # 构造文件访问URL
            file_url = f"{server_url.rstrip('/')}/file/{repo_id}{seafile_path}"

            redis_conn = get_redis_connection("file")
            redis_conn.setex(
                name=f"{user.id}_file_upload",
                time=360000,
                value=json.dumps(file_url)
            )

            return Response({
                "code": 200,
                "message": "文件上传成功"
            })
        except Exception as e:
            return Response({
                "code": 500,
                "error": f"上传失败：{str(e)}"
            }, status=500)


class AnalyzeCodeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            print("学生输入的内容:", request.data)
            raw_input = request.data.get('code', '')
            md_matches = re.findall(r"```(?:[\w+-]*\n)?([\s\S]*?)```", raw_input)
            code = md_matches[0] if md_matches else raw_input
            # 重试调用
            # result_data = None
            result_data = DifyService.analyze_code(code)
            print("result_data=", result_data)
            # —— 如果 service 层返回了错误信息，直接返回给前端 ——
            if isinstance(result_data, dict) and 'error_message' in result_data:
                raw_msg = result_data['error_message']
                http_status = result_data['status']
                print('http_status:', http_status)
                if raw_msg == 'Access token is invalid':
                    detail = f'{http_status}，如果问题仍然存在，请联系管理员。'
                elif raw_msg == "The app's API service has been disabled.":
                    detail = f'{http_status}，如果问题仍然存在，请联系管理员。'
                elif 'Server Unavailable Error' in raw_msg or 'Network is unreachable' in raw_msg:
                    detail = f'{http_status}，如果问题仍然存在，请联系管理员。'
                else:
                    detail = f"【系统提示】{raw_msg}，如果问题仍然存在，请联系管理员。"
                return Response(
                    {
                        'detail': detail,
                    },
                    status=result_data.get(status, status.HTTP_503_SERVICE_UNAVAILABLE),
                )
            last_exception = None
            # 调用三次Dify再返回报错
            for attempt in range(1, 4):
                try:
                    url = DifyService.get_api_url()
                    print(f"Attempt {attempt} to DifyService at {url}")
                    result_data = DifyService.analyze_code(code)
                    if result_data is not None:
                        break
                except Exception as ex:
                    last_exception = ex
            if result_data is None:
                raise Exception(f"DifyService尝试3次失败: {last_exception}")

            # 处理type，可能为多个
            raw_type = result_data.get('type', [])
            print("type:", raw_type)
            if isinstance(raw_type, list):
                # 列表转为字符串，元素间用逗号分隔
                type_str = ', '.join(raw_type)
            else:
                # 已经是字符串，直接用
                type_str = raw_type
            print("type_str:", type_str)

            # ---取出各项指标---
            # 漏洞
            vul = result_data.get('vulnerabilities', 0)
            # 错误
            err = result_data.get('errors', 0)
            # 异味
            smells = result_data.get('code_smells', 0)
            # 已接收问题
            accepted = result_data.get('accepted_issues', 0)
            # 重复
            dup = result_data.get('duplicates', 0)

            # 计算 severity
            def compute_severity(vul, err, smells, accepted, dup):
                # 加权：漏洞×5，错误×3，异味×2，其它×1
                score = vul * 5 + err * 3 + smells * 2 + accepted * 1 + dup * 1
                if score == 0:
                    return '完美'
                elif score <= 10:
                    return '轻度'
                elif score <= 20:
                    return '中度'
                else:
                    return '严重'

            severity_value = compute_severity(vul, err, smells, accepted, dup)

            # 规范数据
            cleaned_data = {
                'vulnerabilities': vul,
                'errors': err,
                'code_smells': smells,
                'accepted_issues': accepted,
                'duplicates': dup,
                'type': type_str,
                'severity': severity_value,
                'user': request.user.id,
            }
            print("cleaned_data:", cleaned_data)

            serializer = AnalysisSerializer(data=cleaned_data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


@api_view(['POST'])
def upload_code(request):
    """
    接收前端上传的代码文件，读取其内容并返回给前端。
    前端应使用 multipart/form-data，字段名为 'code_file'.
    """
    # 检查文件是否存在
    uploaded_file = request.FILES.get('code_file')
    if not uploaded_file:
        return Response({'detail': '未上传任何文件'}, status=status.HTTP_400_BAD_REQUEST)

    # 只允许一定扩展名，可根据需求扩展
    allowed_ext = ['.js', '.py', '.java', '.cpp', '.cs', '.ts']
    filename = uploaded_file.name
    print(filename)
    if not any(filename.endswith(ext) for ext in allowed_ext):
        return Response({'detail': '不支持的文件类型'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # 读取文件内容，注意可能需要指定编码
        raw_bytes = uploaded_file.read()
        try:
            content = raw_bytes.decode('utf-8')
        except UnicodeDecodeError:
            content = raw_bytes.decode('latin-1')
    except Exception as ex:
        return Response({'detail': f'读取文件失败：{str(ex)}'}, status=status.HTTP_400_BAD_REQUEST)

    # 返回文件内容到前端，用于填充 codeContent
    return Response({'code_content': content}, status=status.HTTP_200_OK)


# 自定义 Dify 服务 IP 地址
@api_view(['POST'])
def set_dify_ip(request):
    ip_input = request.data.get('ip', '').strip()
    print(ip_input)
    # 简单 IP 格式校验
    ip_pattern = r'^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$'
    print(ip_pattern)
    if not re.match(ip_pattern, ip_input):
        return Response({'detail': '无效 IP 格式'}, status=400)
    IPConfig.objects.update_or_create(
        defaults={'ip_address': ip_input},
        # 也可以加个固定的 key，如果你只想要一条记录
        id=1
    )
    return Response({'current_ip': ip_input})


# 获取并设置当前本机 IP 地址
@api_view(['GET'])
def current_dify_ip(request):
    ip = get_reliable_local_ip()
    return Response({'current_ip': ip})


# 历史记录
class AnalysisHistoryView(APIView):
    def get(self, request):
        queryset = AnalysisResult.objects.filter(user=request.user)
        serializer = AnalysisSerializer(queryset, many=True)
        return Response(serializer.data)


class AnswerView(APIView):
    def post(self, request):
        user = request.user
        try:
            print("学生输入的内容:", request.data)
            raw_input = request.data.get('code', '')
            md_matches = re.findall(r"```(?:[\w+-]*\n)?([\s\S]*?)```", raw_input)
            code = md_matches[0] if md_matches else raw_input
            # 重试调用
            # result_data = None
            result_data = DifyAnswer.analyze_code(code)
            print("result_data=", result_data)
            # —— 如果 service 层返回了错误信息，直接返回给前端 ——
            if isinstance(result_data, dict) and 'error_message' in result_data:
                raw_msg = result_data['error_message']
                http_status = result_data['status']
                print('http_status:', http_status)
                if raw_msg == 'Access token is invalid':
                    detail = f'{http_status}，如果问题仍然存在，请联系管理员。'
                elif raw_msg == "The app's API service has been disabled.":
                    detail = f'{http_status}，如果问题仍然存在，请联系管理员。'
                elif 'Server Unavailable Error' in raw_msg or 'Network is unreachable' in raw_msg:
                    detail = f'{http_status}，如果问题仍然存在，请联系管理员。'
                else:
                    detail = f"【系统提示】{raw_msg}，如果问题仍然存在，请联系管理员。"
                return Response(
                    {
                        'detail': detail,
                    },
                    status=result_data.get(status, status.HTTP_503_SERVICE_UNAVAILABLE),
                )
            last_exception = None
            # 调用三次Dify再返回报错
            for attempt in range(1, 4):
                try:
                    url = DifyAnswer.analyze_code(url)
                    print(f"Attempt {attempt} to DifyService at {url}")
                    result_data = DifyService.analyze_code(code)
                    if result_data is not None:
                        break
                except Exception as ex:
                    last_exception = ex
            if result_data is None:
                raise Exception(f"DifyService尝试3次失败: {last_exception}")

            # 规范数据
            cleaned_data = {
                'correct_code': result_data.get('correct_code', ''),
                'description': result_data.get('description', '')
            }
            print("cleaned_data:", cleaned_data)

            redis_url = f"{cleaned_data}"

            redis_conn = get_redis_connection('answer')
            redis_conn.setex(
                name=f"{user.id}_file_upload",
                time=604800,  # 7天
                value=json.dumps(cleaned_data)
            )
            return Response(status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class TeaAnswerView(APIView):
    def post(self, request):
        userId = request.data.get('userId')
        try:
            if not {'userId'}.issubset(request.data):
                return Response({"message": "缺少必填字段"}, status=400)
            cache_key = f'{userId}_file_upload'
            redis_conn = get_redis_connection("answer")
            cache_value = redis_conn.get(cache_key)
            if not cache_value:
                return Response({"code": 404, "message": "无缓存数据"})

            if isinstance(cache_value, bytes):
                decoded_str = cache_value.decode('utf-8')
            else:
                decoded_str = cache_value

            # 兼容旧数据格式（如果存在单引号问题）
            if decoded_str.startswith("'") and decoded_str.endswith("'"):
                decoded_str = decoded_str.strip("'")

            # 解析JSON
            try:
                parsed_data = json.loads(decoded_str)
            except json.JSONDecodeError:
                # 处理可能存在的转义字符问题
                decoded_str = decoded_str.replace('\\n', '\n').replace('\\"', '"')
                parsed_data = json.loads(decoded_str)

            # 提取字段并处理换行符
            correct_code = parsed_data.get('correct_code', '').replace('\\n', '\n')
            description = parsed_data.get('description', '').replace('\\n', '\n')
            print('老师查看AI批改:', parsed_data)

            return Response({
                "code": 200,
                "data": {
                    'correct_code': correct_code,
                    'description': description
                }
            }, status=status.HTTP_200_OK)  # 修改为200状态码

        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


