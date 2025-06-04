import datetime
import json
import os
import tempfile
import uuid
import pandas as pd
from django.contrib.auth import authenticate, get_user_model
from django.db.models import Q
from django.http import JsonResponse, FileResponse
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.generics import RetrieveAPIView
from rest_framework.permissions import IsAuthenticated
from seafileapi import SeafileAPI, Repo
import re
from rest_framework.decorators import api_view
from sqlalchemy import create_engine
from CorrectionPlatformBackend import settings
from CorrectionPlatformBackend.base import login_name, pwd, server_url
from .models import AnalysisResult, IPConfig, StuAssignment, DepartmentMajor, Student
from .serializers import AnalysisSerializer, DepartmentMajorSerializer
from rest_framework.permissions import AllowAny
from .services import DifyService, get_reliable_local_ip, DifyAnswer
from accs.models import Roles, UserInfo, Group, GroupAssignment
from accs.permissions import IsSuperAdmin, IsTeacher
from accs.serializers import UserSerializer, UserInfoSerializer, RolesSerializer, \
    validate_image_content, GroupSerializer
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from .utils.middleware import UUIDTools

User = get_user_model()

seafile_api = SeafileAPI(login_name, pwd, server_url)
seafile_api.auth()  # 认证


def csrf_failure(request, reason=""):
    return JsonResponse({"error": "CSRF验证失败"}, status=403)


class RegisterView(APIView):
    permission_classes = [AllowAny]

    @staticmethod
    def post(request):
        username = request.data.get('username')
        if not {'username', 'password', 'role_id', 'gender'}.issubset(request.data):
            return Response({"message": "缺少必填字段"}, status=400)
        if len(request.data['password']) < 8:
            return Response({"password": "密码长度需至少8位"}, status=400)
        uuid = UUIDTools().uuid4_hex()
        user_serializer = UserSerializer(data=request.data, context={'id': uuid})
        if user_serializer.is_valid():
            if request.data.get('role_id') is not None:
                user_serializer.save()
                try:
                    repo = seafile_api.create_repo(username)
                    pri_repo_id = repo.repo_id
                    print(pri_repo_id)
                    user_info_data = request.data.copy()
                    user_info_data['pri_repo_id'] = pri_repo_id

                except Exception as e:
                    return Response({
                        "error": f"创建私人库失败: {str(e)}"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                userinfo_data = request.data.copy()
                userinfo_data['pri_repo_id'] = pri_repo_id

                userinfo_serializer = UserInfoSerializer(
                    data=userinfo_data,
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
                    return Response(userinfo_serializer.errors, status=400)

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


class GenerateClassExcelView(APIView):
    """
    接收前端 JSON 数据，生成班级 Excel 并上传到 Seafile。
    POST 数据格式示例：
    {
        "class": "高三3班",
        "count": 30,
        "department": "信息工程学院",
        "major": "计算机科学与技术"
    }
    Excel 内容：
    A1: 院系：<department>   B1: 专业：<major>
    A2: 学号              B2: 姓名
    A3~A(N+2): 1~N         B3~B(N+2): 空
    """

    def post(self, request):
        data = request.data
        user = request.user

        # 读取并校验字段
        cls = data.get('class', '')
        count = data.get('count')
        dept = data.get('department', '')
        major = data.get('major', '')

        try:
            count = int(count)
            if count < 0:
                raise ValueError
        except Exception:
            return Response({'detail': '学生人数必须为非负整数'}, status=status.HTTP_400_BAD_REQUEST)

        if not DepartmentMajor.objects.filter(department=dept, major=major).exists():
            return Response(
                {'detail': '指定的院系与专业组合在不存在'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 构造表格行
        rows = []
        # 第一行：院系、专业、班级
        rows.append([f'院系：{dept}', f'专业：{major}', f'班级：{cls}'])
        # 第二行：学号、姓名、（空）
        rows.append(['学号', '姓名', ''])
        # 后续行：学号1~count，姓名和班级列留空
        for i in range(1, count + 1):
            rows.append([i, '', ''])

        # 将行列表转换为 DataFrame，三列布局
        df = pd.DataFrame(rows)

        # 写入 Excel 文件
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        filename = f"{timestamp}_class_list.xlsx"
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, filename)
        seafile_api = SeafileAPI(login_name, pwd, server_url)
        seafile_api.auth()
        repo = seafile_api.get_repo(repo_id)
        base = f"{server_url.rstrip('/')}"
        file_url = f"{base}/file/{repo_id}/result/{filename}"
        local_save_path = "/ACCS/accs/files/" + filename
        print(file_url)
        try:
            df.to_excel(file_path, header=False, index=False)
        except ModuleNotFoundError:
            return Response({'detail': 'openpyxl 未安装，无法生成 Excel'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({'detail': f'生成Excel失败：{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 上传到 Seafile
        try:
            repo.upload_file('/result', file_path)
        except Exception as e:
            return Response({'detail': f'Seafile 上传失败：{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            repo.download_file(file_path, local_save_path)
        except Exception as e:
            return Response({'datail': f'seafile 下载失败:{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            # 清理临时文件
            try:
                os.remove(file_path)
                os.rmdir(temp_dir)
            except:
                pass

        return Response({'file_url': file_url}, status=status.HTTP_201_CREATED)


class DepartmentMajorView(APIView):
    """
    接收前端 POST 上传的 JSON：{'department': '信息工程学院', 'major': '计算机科学与技术'}
    将其存入 DepartmentMajor 表，并返回序列化后的记录。
    """
    parser_classes = [JSONParser, MultiPartParser, FormParser]

    def post(self, request):
        serializer = DepartmentMajorSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ParseFilledExcelView(APIView):
    """
    接收前端上传的已填写姓名的 Excel（Multipart），
    解析并返回包含 [班级, 院系, 专业, 学号, 姓名] 的 JSON 列表，供前端确认。
    Excel 格式要求：
      A1: 院系：<department>    B1: 专业：<major>    C1: 班级：<class>
      A2: 学号                 B2: 姓名             C2: （空）
      A3~A(N+2): 1~N            B3~B(N+2): 姓名      C3~C(N+2): （空）
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request):
        excel_file = request.FILES.get('file')
        if not excel_file:
            return Response({'detail': '未上传文件'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # 1. 将上传文件写入临时文件
            temp_dir = tempfile.mkdtemp()
            filename = f"filled_{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}.xlsx"
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'wb') as f:
                for chunk in excel_file.chunks():
                    f.write(chunk)

            # 2. 用 pandas 读取，无表头，header=None
            df = pd.read_excel(file_path, header=None, dtype=str)

            # 3. 解析第一行
            # A1 格式 “院系：...”，B1 “专业：...”，C1 “班级：...”
            try:
                dept_cell = str(df.iat[0, 0]).strip()
                major_cell = str(df.iat[0, 1]).strip()
                class_cell = str(df.iat[0, 2]).strip()
                if not dept_cell.startswith('院系：') or not major_cell.startswith('专业：') or not class_cell.startswith(
                        '班级：'):
                    raise ValueError
                department = dept_cell.split('：', 1)[1]
                major = major_cell.split('：', 1)[1]
                class_name = class_cell.split('：', 1)[1]
            except Exception:
                return Response({'detail': '第一行格式不正确，应为“院系：...”、“专业：...”、“班级：...”'},
                                status=status.HTTP_400_BAD_REQUEST)

            # 4. 校验 DepartmentMajor 存在
            try:
                deptmajor = DepartmentMajor.objects.get(department=department, major=major)
            except DepartmentMajor.DoesNotExist:
                return Response({'detail': '指定的院系与专业组合在数据库中不存在'}, status=status.HTTP_400_BAD_REQUEST)

            # 5. 第二行应为 “学号”、“姓名”、“”（C列可忽略）
            if str(df.iat[1, 0]).strip() != '学号' or str(df.iat[1, 1]).strip() != '姓名':
                return Response({'detail': '第二行应为“学号”、“姓名”'}, status=status.HTTP_400_BAD_REQUEST)

            # 6. 从第 3 行开始提取学号和姓名
            students = []
            for idx in range(2, len(df)):
                sid = str(df.iat[idx, 0]).strip()
                name = str(df.iat[idx, 1]).strip()
                if not sid or not name:
                    continue  # 只处理非空行
                students.append({
                    'student_id': sid,
                    'name': name,
                    'class_name': class_name,
                    'department': department,
                    'major': major
                })

            # 7. 清理临时文件
            try:
                os.remove(file_path)
                os.rmdir(temp_dir)
            except:
                pass

            if not students:
                return Response({'detail': '未检测到有效的学号和姓名行'}, status=status.HTTP_400_BAD_REQUEST)

            # 返回供前端预览确认
            return Response({'students': students}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'detail': f'解析失败：{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SaveStudentsView(APIView):
    """
    步骤 3：接收前端确认后的 JSON 列表，将每个学生写入数据库。
    请求 JSON 格式：
      {
        "students": [
          {
            "student_id": "2025001",
            "name": "张三",
            "class_name": "高三3班",
            "department": "信息工程学院",
            "major": "计算机科学与技术"
          },
          ...
        ]
      }
    返回 JSON：
      {
        "saved": [
          {"student_id": "2025001", "created": true},
          ...
        ],
        "errors": [
          {"student_id": "2025002", "detail": "院系-专业不存在"},
          ...
        ]
      }
    """
    parser_classes = [JSONParser]

    def post(self, request):
        data = request.data.get('students')
        if not isinstance(data, list) or not data:
            return Response({'detail': 'students 列表不能为空'}, status=status.HTTP_400_BAD_REQUEST)

        saved = []
        errors = []
        for rec in data:
            sid = rec.get('student_id')
            name = rec.get('name')
            class_name = rec.get('class_name')
            department = rec.get('department')
            major = rec.get('major')

            if not all([sid, name, class_name, department, major]):
                errors.append({'student_id': sid, 'detail': '字段不完整'})
                continue

            try:
                deptmajor = DepartmentMajor.objects.get(department=department, major=major)
            except DepartmentMajor.DoesNotExist:
                errors.append({'student_id': sid, 'detail': '院系-专业不存在'})
                continue

            # update_or_create：学号已存在则更新，否则插入
            student, created = Student.objects.update_or_create(
                student_id=sid,
                defaults={
                    'name': name,
                    'class_name': class_name,
                    'department_major': deptmajor
                }
            )
            saved.append({'student_id': sid, 'created': created})

        return Response({'saved': saved, 'errors': errors}, status=status.HTTP_200_OK)


class AddStuidView(APIView):
    @staticmethod
    def get(request):
        file = open(os.path.dirname(os.path.abspath(__file__)) + '/ACCS/accs/files/人员信息.xlsx', 'rb')
        response = FileResponse(file)
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = 'attachment;filename="excel_test.xlsx"'
        return response

    def post(self, request):
        excel_file = request.data.get('file')
        if not {'file'}.issubset(request.data):
            return Response({"message": "缺少必填字段"}, status=400)
        try:
            df = pd.read_excel(excel_file, engine='openpyxl')
            column_mapping = {
                "学号": "stuId",
                "姓名": "username",
                "班级": "study_groups",
                "专业": "specialty",
                "院系": "college"
            }
            df = df.rename(columns=column_mapping)
            table_name = StuAssignment._meta.db_table
            engine = create_engine(
                f"mysql+mysqldb://{settings.DATABASES['default']['USER']}:"
                f"{settings.DATABASES['default']['PASSWORD']}@"
                f"{settings.DATABASES['default']['HOST']}:"
                f"{settings.DATABASES['default']['PORT']}/"
                f"{settings.DATABASES['default']['NAME']}"
            )
            df.to_sql(table_name, engine, if_exists='replace', index=False)
            return Response({
                "code": status.HTTP_201_CREATED,
                "message": "数据导入成功"
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "error": f"上传失败：{str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
    permission_classes = [IsAuthenticated, IsTeacher]

    @staticmethod
    def post(request):
        user_id = request.data.get('user_id')
        group_id = request.data.get('group_id')
        if not {'user_id', 'group_id'}.issubset(request.data):
            return Response({"message": "缺少必填字段"}, status=400)

        try:
            user_info = UserInfo.objects.get(userId=user_id)
            print(user_info)

            print(user_info.role_id)
            if user_info.role_id == 2:
                return Response({"code": 403, "message": "用户为老师"}, status=403)
            if user_info.role_id == 3:
                return Response({"code": 403, "message": "用户为管理员"}, status=403)
        except User.DoesNotExist:
            return Response({"code": 403, "message": "用户不存在"}, status=403)
        except Group.DoesNotExist:

            return Response({"code": 403, "message": "班级不存在"}, status=403)
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
    permission_classes = [IsTeacher, IsAuthenticated]

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
        user = request.user
        user_id = user.id
        group_id = GroupAssignment.objects.get(userId=user_id).groupId
        print('group_id:', group_id)

        if not group_id:
            return Response({
                "code": 500,
                "error": "您没有班级，请去加入班级再来提交"
            }, status=403)
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

            redis_conn = get_redis_connection('analyze')
            redis_conn.setex(
                name=f"{group_id}_{user.id}_file_upload",
                time=604800,  # 7天
                value=json.dumps(cleaned_data)
            )
            return Response(status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


@api_view(['POST'])
def set_save_analyze(request):
    groupId = request.data.get('groupId')
    redis_conn = get_redis_connection("analyze")
    value = [x.decode() for x in redis_conn.keys() if x.decode().split('_')[0] == groupId]
    cleaned_data = value
    serializer = AnalysisSerializer(data=cleaned_data)  # 用不了
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    serializer.save()
    return Response(serializer.data, status=status.HTTP_201_CREATED)


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


class AddAnswerView(APIView):
    def post(self, request):
        user = request.user
        user_id = user.id
        group_id = GroupAssignment.objects.get(userId=user_id).groupId
        if not group_id:
            return Response({
                "code": 500,
                "error": "您没有班级，请去加入班级再来提交"
            }, status=403)
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
                name=f"{group_id}_{user.id}_file_upload",
                time=604800,  # 7天
                value=json.dumps(cleaned_data)
            )
            return Response(status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class TeaAnswerView(APIView):
    def get(self, request):
        redis_conn = get_redis_connection("answer")
        group_id = request.data.get('group_id')
        try:
            value = [x.decode() for x in redis_conn.keys() if x.decode().split('_')[0] == group_id]
            print(value)
            cache_value = " ".join(value)
            return Response({
                'code': 200,
                'cache_value': cache_value,
            })
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    def post(self, request):
        user_id = request.data.get('user_id')
        group_id = request.data.get('group_id')
        try:
            if not {'user_id'}.issubset(request.data):
                return Response({"message": "缺少必填字段"}, status=400)
            cache_key = f'{group_id}_{user_id}_file_upload'
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
                    'description': description,
                    'message': '是否保存？',
                }
            }, status=status.HTTP_200_OK)  # 修改为200状态码

        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class AnswerConfirmView(APIView):
    def post(self, request):
        group_id = request.data.get('group_id')
        user_id = request.data.get('user_id')
        if not {'user_id', 'confirm'}.issubset(request.data):
            return Response({"code": 400, "message": "缺少必要参数"}, status=400)
        if request.data['confirm'] == 'revise':
            results = request.data.get('results')
            cache_key = f'{group_id}_{user_id}_file_upload'
            redis_conn = get_redis_connection("answer")
            redis_conn.set(cache_key, results)
            return Response({
                'code': 200,
                'data': {
                    '学生': user_id,
                    "修改结果": results,
                }
            }, status=status.HTTP_200_OK)
        if request.data['confirm'] == 'again':
            return Response({
                "code": 200,
                "data": {
                    'message': '跳转ai生成',
                }
            }, status=status.HTTP_200_OK)
        return Response({"code": 404, "message": "无缓存数据"}, status=404)


class SaveExeclView(APIView):
    def post(self, request):
        execlname = request.data.get('execlname')
        groupId = request.data.get('groupId')
        seafile_path = f"/result/{execlname}.xlsx"
        if not {'groupId'}.issubset(request.data):
            return Response({"code": 400, "message": "缺少必要参数"}, status=400)
        if not {"execlname"}.issubset(request.data):
            return Response({"code": 400, "message": "请为表格命名"}, status=400)
        redis_conn = get_redis_connection("answer")
        print('redis_conn:', redis_conn)
        value = [x.decode() for x in redis_conn.keys() if x.decode().split('_')[0] == groupId]
        print('value', value)

        cache_value = " ".join(value)
        keys = redis_conn.mget(value)
        print('01', keys)
        user = request.groupId if request.groupId.is_authenticated else None
        print('user:', user)
        queryset = redis_conn.objects
        print('queryset:', queryset)
        if user:
            queryset = queryset.filter(groupId=groupId)
        result_obj = queryset.order_by('groupId')
        print('result_obj:', result_obj)
        if not result_obj:
            return Response({'detail': '未找到分析结果'}, status=status.HTTP_404_NOT_FOUND)

        # 3. 将结果字段存入 DataFrame
        data = {
            'correct_code': result_obj.correct_code,
            'description': result_obj.description,
        }

        df = pd.DataFrame([data])
        print('df:', df)

        # 4. 写入 Excel
        table_filename = f"{execlname}.xlsx"
        temp_dir = tempfile.mkdtemp()
        table_path = os.path.join(temp_dir, table_filename)
        try:
            df.to_excel(table_path, index=False)
        except Exception as e:
            return Response({'detail': f'生成表格失败：{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 1) 使用 pandas 创建 DataFrame，把返回 JSON 放入第一格
        df = pd.DataFrame([[data]], columns=['hhh'])
        table_filename = f"{execlname}.xlsx"
        table_path = os.path.join(temp_dir, table_filename)
        df.to_excel(table_path, index=False)

        try:
            # 2) 上传表格到 Seafile
            seafile_api = SeafileAPI(login_name, pwd, server_url)
            seafile_api.auth()
            repo = seafile_api.get_repo(repo_id)

            # 上传表格文件
            repo.upload_file('/result', table_path)

            # 构造访问 URL
            base = f"{server_url.rstrip('/')}"
            table_url = f"{base}/{repo_id}/result/{table_filename}"

            return Response({
                'table_file_url': table_url,
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'detail': f'Seafile 上传失败：{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            # 清理本地临时目录
            try:
                os.remove(table_path)
                os.rmdir(temp_dir)
            except:
                pass
# @api_view(['POST'])
# def set_save_execl(request):
#     try:
#         userId = request.data.get('userId')
#         study_groups = request.data.get('study_groups')
#         filename = f"{study_groups}_file_upload.xlsx"
#         seafile_path = f"/result/{study_groups}_file_upload.xlsx"  # Seafile中的存储路径
#         if not userId:
#             return Response({"message": "缺少必填字段: userId"}, status=400)
#
#         # 获取 Redis 数据
#         cache_key = f'{userId}_file_upload'
#         redis_conn = get_redis_connection("answer")
#         cache_value = redis_conn.get(cache_key)
#
#         if not cache_value:
#             return Response({"code": 404, "message": "无缓存数据"}, status=404)
#
#         # 解析数据
#         decoded_str = cache_value.decode('utf-8').strip("'")  # 兼容旧格式
#         data = json.loads(decoded_str)
#         correct_code = data.get('correct_code', '').replace('\\n', '\n')
#         description = data.get('description', '').replace('\\n', '\n')
#
#         # --- 生成 Excel 的逻辑 ---
#         # 创建空 DataFrame 初始化 Excel
#         buffer = BytesIO()
#         pd.DataFrame().to_excel(buffer, index=False, engine='openpyxl')
#
#         # 使用 openpyxl 操作单元格
#         buffer.seek(0)
#         wb = load_workbook(buffer)
#         ws = wb.active
#
#         # 写入 A1: 用户ID
#         ws['A1'] = f"用户ID: {userId}"
#
#         # 写入 A2: 合并代码和描述
#         combined_content = f"修正后的代码：\n{correct_code}\n\n修改说明：\n{description}"
#         ws['A2'] = combined_content
#
#         # 设置样式
#         ws.column_dimensions['A'].width = 100  # 列宽
#         ws.row_dimensions[2].height = 300  # A2 行高
#         for cell in ['A1', 'A2']:
#             ws[cell].alignment = Alignment(
#                 wrap_text=True,
#                 vertical='top',
#                 horizontal='left'
#             )
#
#         # 保存到缓冲流
#         buffer = BytesIO()
#         wb.save(buffer)
#         buffer.seek(0)
#
#         save_dir = os.path.join(settings.BASE_DIR, 'file')  # 项目根目录/file
#         os.makedirs(save_dir, exist_ok=True)  # 自动创建目录
#
#         # 生成唯一文件名（用户ID + 时间戳）
#         timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#         filename = f"user_{userId}_code_{timestamp}.xlsx"
#         file_path = os.path.join(save_dir, filename)
#
#         # 写入文件
#         with open(file_path, 'wb') as f:
#             f.write(buffer.getvalue())
#
#         try:
#             seafile_api = SeafileAPI(login_name, pwd, server_url)
#             seafile_api.auth()  # 认证
#
#             # 获取仓库对象
#             repo = seafile_api.get_repo(repo_id)
#
#             # 创建临时目录保存文件（确保文件名正确）
#             dir = tempfile.mkdtemp()
#             file_path = os.path.join(dir, filename)
#
#             with open(file_path, 'wb') as temp_file:
#                 for chunk in user_file.chunks():
#                     temp_file.write(chunk)
#
#             # 上传到Seafile
#             if filename in [x["name"] for x in repo.list_dir("/file")]:
#                 repo.delete_file(seafile_path)
#             repo.upload_file("/file", file_path)
#
#             # 构造文件访问URL
#             file_url = f"{server_url.rstrip('/')}/file/{repo_id}{seafile_path}"
#
#             redis_conn = get_redis_connection("file")
#             redis_conn.setex(
#                 name=f"{user.id}_file_upload",
#                 time=360000,
#                 value=json.dumps(file_url)
#             )
#
#             return Response({
#                 "code": 200,
#                 "message": "文件上传成功"
#             })
#         except Exception as e:
#             return Response({
#                 "code": 500,
#                 "error": f"上传失败：{str(e)}"
#             }, status=500)
#
#         # 返回 Excel 文件给用户下载
#         response = HttpResponse(
#             buffer.getvalue(),
#             content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
#         )
#         response['Content-Disposition'] = f'attachment; filename="{filename}"'
#         return response
#
#     except json.JSONDecodeError:
#         return Response({"code": 500, "message": "数据解析失败"}, status=500)
#     except Exception as e:
#         return Response({"code": 503, "message": str(e)}, status=503)
