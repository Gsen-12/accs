import base64
import datetime
import json
import os
import tempfile
from sqlite3 import IntegrityError
import logging

import pandas as pd
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models import Q
from django.http import JsonResponse
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import RetrieveAPIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from seafileapi import SeafileAPI

from CorrectionPlatformBackend.settings_dev import login_name, pwd, server_url, admin_repo_id, ava_repo_id, repo_token
from accs.models import (
    DepartmentMajor,
    Student,
    Class,
    Roles,
    UserInfo,
    SubmissionTemplate,
    StudentSubmission,
)
from accs.permissions import IsSuperAdmin
from accs.serializers import (
    DepartmentMajorSerializer,
    UserRoleUpdateSerializer,
    UserSerializer,
    RolesSerializer,
    validate_image_content,
    SubmissionTemplateSerializer,
    StudentSubmissionSerializer,
)
from accs.utils.middleware import UUIDTools
from accs.utils.seafile_operate import SeafileOperations, FileUpload

User = get_user_model()

seafile_api = SeafileAPI(login_name, pwd, server_url)
seafile_api.auth()  # 认证
seafile_ops = SeafileOperations(server_url, repo_token)


def csrf_failure(request, reason=""):
    return JsonResponse({"error": "CSRF验证失败"}, status=403)


class RegisterView(APIView):
    permission_classes = [AllowAny]

    @staticmethod
    def post(request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email', '')
        role_id = request.data.get('role_id')
        real_name = request.data.get('real_name')
        gender = request.data.get('gender')
        avatar_file = request.FILES.get('avatar')
        student_id = request.data.get('student_id')
        class_name = request.data.get('class_name')

        # 基础字段校验
        if not {'username', 'password', 'role_id', 'gender'}.issubset(request.data):
            return Response({'status': 'error', 'message': '用户名、密码和角色必须提供'}, status=400)
        if gender not in ["0", "1", "2"]:
            return Response({'status': 'error', 'message': '无效的性别'}, status=400)
        if role_id not in ["1", "2"]:
            return Response({'status': 'error', 'message': '无效的角色 ID'}, status=400)
        if len(password) < 8:
            return Response({'password': '密码长度需至少8位'}, status=400)
        if User.objects.filter(username=username).exists():
            return Response({'status': 'error', 'message': '用户名已存在'}, status=400)

        student_obj = None
        class_obj = None
        uuid = UUIDTools().uuid4_hex()
        user_id = uuid

        if role_id == "1":
            # 1. 检查学号
            if not student_id:
                return Response(
                    {'status': 'error', 'message': 'student_id（学号）未填写'},
                    status=400
                )
            # 2. 检查班级
            # 3. 分别查 Student 和 Class
            if not class_name:
                return Response({'status': 'error', 'message': 'class_name（班级名）未填写'}, status=400)
            try:
                class_obj = Class.objects.get(class_name=class_name)
            except Class.DoesNotExist:
                return Response({'status': 'error', 'message': '班级不存在'}, status=400)

            # 用 student_id + 班级 联合查询
            try:
                student_obj = Student.objects.get(
                    student_id=student_id,
                    class_info=class_obj
                )
            except Student.DoesNotExist:
                return Response({'status': 'error', 'message': '该班级下学号不存在，请检查后重试'}, status=400)
            if not student_id or not class_name:
                return Response({'status': 'error', 'message': 'role_id=1 时必须填写 student_id 和 class_name'},
                                status=400)
            # 4. 最后判断该学生是否属于这个班级
            if student_obj.class_info_id != class_obj.id:
                return Response({'status': 'error', 'message': '学号和班级不匹配，请确认后再试'}, status=400)

            try:
                # 使用反向关系检查注册状态
                if hasattr(student_obj, 'user_info'):
                    return Response({
                        'status': 'error',
                        'message': '该学号已被注册'
                    }, status=400)
            except AttributeError:
                pass

        if role_id == "2":
            if not real_name or not avatar_file:
                return Response({'status': 'error', 'message': '请提供真实姓名和审核图片'}, status=400)
            if UserInfo.objects.filter(realName=real_name).exists():
                return Response({'status': 'error', 'message': '该真实姓名已被使用，请换一个'}, status=400)

        # 创建 Django 用户
        user = User.objects.create_user(
            username=username,
            password=password,
            email=email,
            id=user_id
        )

        # 默认审核状态
        audit_value = 1 if role_id == "1" else 0
        print(student_obj)
        print(class_obj)
        class_id = int(class_obj.id if role_id == "1" else '0')
        student_id = student_obj.id if role_id == "1" else '0'
        print('student_id', student_id)
        print('class_id', class_id)
        # 2. 尝试创建 UserInfo
        try:
            user_info = UserInfo.objects.create(
                userId=user.id,
                student_id=student_id if role_id == "1" else None,
                class_id_id=class_id if role_id == "1" else '',
                realName=real_name if role_id == "2" else '',
                role_id=int(role_id),
                audit=audit_value,
                gender=int(gender),
            )
        except IntegrityError as e:
            # 如果创建 UserInfo 失败，删掉刚创建的 user，避免残留
            user.delete()
            if 'user_info_student_id' in str(e):
                return Response({
                    'status': 'error',
                    'message': '该学号已被其他用户注册'
                }, status=400)
            else:
                return Response({
                    'status': 'error',
                    'message': f'数据库错误: {str(e)}'
                }, status=500)
        except Exception as e:
            user.delete()
            return Response({
                'status': 'error',
                'message': f'保存用户信息失败: {str(e)}'
            }, status=500)

        # 角色2：保存图片到本地 + 存 Redis
        if role_id == "2":
            # 本地存储目录（可配置到 settings）
            local_dir = os.path.join(settings.BASE_DIR, 'tmp', 'verify')
            os.makedirs(local_dir, exist_ok=True)

            # 构造文件名并保存到本地
            ext = avatar_file.name.rsplit('.', 1)[-1]
            filename = f"{user.id}_{real_name}.{ext}"
            file_path = os.path.join(local_dir, filename)
            with open(file_path, 'wb') as f:
                for chunk in avatar_file.chunks():
                    f.write(chunk)

            # 构造可访问的 URL 或相对路径
            # 这里假设前端可以通过 /accs/verify/ 访问 tmp/verify 下的文件
            file_url = f"/accs/verify/{filename}"

            redis_conn = get_redis_connection("verify")
            # 存 Redis，14 天过期
            redis_conn.setex(
                name=f"{user.id}_verify",
                time=15000 * 24 * 3600,
                value=json.dumps({'real_name': real_name, 'file_url': file_url})
            )

        resp = {
            'status': 'success',
            'user_id': user.id,
            'message': '注册成功' if role_id == "1" else '注册成功，待审核'
        }
        if role_id == "1":
            resp['student_id'] = student_id
            resp['class_name'] = class_name

        return Response(resp, status=status.HTTP_201_CREATED)


class AuditUsersView(APIView):
    """
    管理员审核视图，权限仅限 IsSuperAdmin
    GET: 返回所有待审核 (audit=0) 的 role_id=2 用户列表，包含真实姓名和头像（Base64 编码）
    POST: 接收 { user_id, audit }，将对应用户的 audit 更新为 1（通过）或 2（拒绝）
    """
    # permission_classes = [IsSuperAdmin]
    permission_classes = [AllowAny]  # 需删除

    def get(self, request):
        """
        管理员查看所有待审核用户的信息和头像（Base64）
        """
        pending = UserInfo.objects.filter(role_id=2, audit=0)
        result = []

        for ui in pending:
            entry = {"user_id": ui.userId, "real_name": ui.realName}
            try:
                # 1. 查 Django User
                user = User.objects.get(id=ui.userId)
                entry["username"] = user.username

                # 2. 拿到 Repo 对象
                repo = seafile_api.get_repo(admin_repo_id)

                # 3. 列出 /ava/ 下文件
                dirents = repo.list_dir('/verify')

                # 过滤出文件（非目录）
                files = [d['name'] for d in dirents if not d.get('is_dir')]
                if not files:
                    raise ValueError("Seafile verify/ 目录为空")
                # 取第一个文件（通常只有一张）
                fname = files[0]
                print('fname', fname)
                remote_path = f'/verify/{fname}'
                print("remote_path", remote_path)

                # 4. 下载到临时文件
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp_path = f"{tmp}/downloaded_file.jpg"
                    print('tmp_path', tmp_path)

                repo.download_file(remote_path, tmp_path)
                # 5. Base64 编码
                with open(tmp_path, 'rb') as f:
                    data = f.read()
                os.remove(tmp_path)
                b64 = base64.b64encode(data).decode('utf-8')
                # 按 MIME 推测后缀
                mime = 'jpeg' if fname.lower().endswith(('jpg', 'jpeg')) else 'png'
                entry["avatar_base64"] = f"data:image/{mime};base64,{b64}"

            except User.DoesNotExist:
                entry["error"] = "对应的 User 不存在"
            except Exception as e:
                entry["error"] = f"获取头像失败: {e}"

            result.append(entry)

        return Response({
            "code": 200,
            "data": result,
            "message": "获取待审核用户成功"
        }, status=status.HTTP_200_OK)

    def post(self, request):
        user_id = request.data.get('user_id')
        audit = request.data.get('audit')
        if audit not in ("1", "2"):
            return Response({
                'code': 400,
                'message': 'audit 必须是 1（通过）或 2（拒绝）'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            ui = UserInfo.objects.get(userId=user_id, role_id=2)
        except UserInfo.DoesNotExist:
            return Response({
                'code': 404,
                'message': '找不到待审核的用户'
            }, status=status.HTTP_404_NOT_FOUND)

        ui.audit = audit
        ui.save()

        return Response({
            'code': 200,
            'message': '审核已更新',
            'data': {
                'user_id': user_id,
                'new_audit': audit
            }
        }, status=status.HTTP_200_OK)


class LoginView(APIView):
    permission_classes = [AllowAny]

    @staticmethod
    def post(request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)

        # 用户不存在或密码错误
        if not user:
            return Response({
                "code": 401,
                "message": "用户名或密码错误",
                "result": None
            }, status=status.HTTP_200_OK)

        user_id = user.id

        # 如果是 role_id = 2，需要检查 audit 状态
        try:
            userinfo = UserInfo.objects.get(userId=user.id)
        except UserInfo.DoesNotExist:
            # 理论上不应该发生，用户一定有对应的 UserInfo
            return Response({
                "code": 500,
                "message": "用户信息不完整，请联系客服",
                "result": None
            }, status=status.HTTP_200_OK)

        if userinfo.role_id == 2:
            if userinfo.audit == 0:
                return Response({
                    "code": 403,
                    "message": "您的资料正在审核中，请耐心等待",
                    "result": None
                }, status=status.HTTP_200_OK)
            elif userinfo.audit == 2:
                return Response({
                    "code": 403,
                    "message": "您的审核申请已被拒绝，如有疑问请联系系统负责人",
                    "result": None
                }, status=status.HTTP_200_OK)

        # —— 新增：检查并创建 Seafile 个人库 —— #
        try:
            # 列出当前所有库，检查是否有 name == username 的
            repo_list = seafile_api.list_repos()
            has_personal_repo = any(r.get('name') == username for r in repo_list)
            if not has_personal_repo:
                # 创建个人库并初始化目录
                repo = seafile_api.create_repo(username)
                repo.create_dir('/file')
                repo.create_dir('/result')

                # 更新 UserInfo.pri_repo_id
                userinfo.pri_repo_id = repo.repo_id
                userinfo.save()
        except Exception as e:
            # 如果 Seafile 操作失败，不影响登录，但可记录日志
            print(f"[Seafile] 创建个人库失败: {e}")

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
    接收前端 JSON 数据，生成班级 Excel 并上传到 Seafile，返回上传结果；
    GET 方法用来生成并返回下载链接。
    POST 数据格式示例：
    {
        "class": "高三3班",
        "count": 30,
        "department": "信息工程学院",
        "major": "计算机科学与技术"
    }
    """
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        cls_name = data.get('class', '').strip()
        count = data.get('count')
        dept = data.get('department', '').strip()
        major = data.get('major', '').strip()

        # 校验 count
        try:
            count = int(count)
            if count < 0:
                raise ValueError
        except Exception:
            return Response({'detail': f'学生人数 {count} 必须为非负整数'}, status=status.HTTP_400_BAD_REQUEST)

        # 验证院系+专业
        try:
            dep_major = DepartmentMajor.objects.get(department=dept, major=major)
        except DepartmentMajor.DoesNotExist:
            return Response({
                'detail': f'院系“{dept}”与专业“{major}”组合不存在'
            }, status=status.HTTP_400_BAD_REQUEST)

        # 检查班级全局唯一
        existing = Class.objects.filter(class_name=cls_name).first()
        if existing:
            exist_dm = existing.department_major
            return Response({
                'detail': f'班级“{cls_name}”已在“{exist_dm.department}”院系的“{exist_dm.major}”专业下存在'
            }, status=status.HTTP_400_BAD_REQUEST)

        # 构造表格数据并保存到本地
        rows = [[f'院系：{dept}', f'专业：{major}', f'班级：{cls_name}'], ['学号', '姓名', '']]
        rows += [[i, '', ''] for i in range(1, count + 1)]
        df = pd.DataFrame(rows)

        tmpdir = tempfile.mkdtemp()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"{major}-{dept}-{cls_name}_{count}_{timestamp}_class_list.xlsx"
        local_path = os.path.join(tmpdir, filename)
        print(local_path)
        try:
            df.to_excel(local_path, header=False, index=False)
        except ModuleNotFoundError:
            return Response({'detail': 'openpyxl 未安装'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({'detail': f'生成 Excel 失败：{e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 上传至 Seafile
        try:
            user = request.user
            info = UserInfo.objects.get(userId=user.id)
            repo_id = info.pri_repo_id

            service = FileUpload(seafile_api, seafile_ops)

            seafile_path = f"/file/{filename}"
            # 调用服务层上传本地文件
            service.upload_file(repo_id, seafile_path, local_path)
            # 缓存路径到 Redis，用于后续 GET 生成链接
            redis_key = f"file:{user.id}"
            get_redis_connection('file').setex(redis_key, 360000, json.dumps(seafile_path))
        except Exception as e:
            return Response({'detail': f'上传 Seafile 失败：{e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            # 清理本地临时
            try:
                os.remove(local_path)
                os.rmdir(tmpdir)
            except:
                pass

        # 保存数据库班级记录
        Class.objects.create(class_name=cls_name, department_major=dep_major)

        return Response({'detail': 'Excel 上传成功，下载链接请通过 GET 接口获取'}, status=status.HTTP_201_CREATED)

    def get(self, request):
        """获取最近一次生成的班级名单下载链接"""
        user = request.user
        try:
            info = UserInfo.objects.get(userId=user.id)
            repo_id = info.pri_repo_id
        except UserInfo.DoesNotExist:
            return Response({'detail': '未找到用户信息'}, status=status.HTTP_404_NOT_FOUND)

        redis_key = f"file:{user.id}"
        raw = get_redis_connection('file').get(redis_key)
        if not raw:
            return Response({
                'detail': '下载链接不存在，请先上传'
            }, status=status.HTTP_400_BAD_REQUEST)
        seafile_path = json.loads(raw.decode() if isinstance(raw, bytes) else raw)

        # 生成并返回下载链接
        try:
            down_file = seafile_ops.down_file_by_repo(repo_id, seafile_path)
            return Response({
                'file_url': down_file
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'detail': f'生成下载链接失败：{e}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DepartmentMajorView(APIView):
    """
    接收前端 POST 上传的 JSON：{'department': '信息工程学院', 'major': '计算机科学与技术'}
    将其存入 DepartmentMajor 表，并返回序列化后的记录。
    """
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    permission_classes = [AllowAny]  # 删

    def post(self, request):
        department = request.data.get('department')
        major = request.data.get('major')

        if not major and not department:
            return Response(
                {'detail': '院系、专业字段不能为空'}, status=status.HTTP_400_BAD_REQUEST)

        if not department:
            return Response({'detail': '院系字段不能为空'}, status=status.HTTP_400_BAD_REQUEST)

        if not major:
            return Response({'detail': '专业字段不能为空'}, status=status.HTTP_400_BAD_REQUEST)

        if DepartmentMajor.objects.filter(department=department, major=major).exists():
            return Response({'detail': '该院系和专业组合已经存在'}, status=status.HTTP_400_BAD_REQUEST)

        existing = DepartmentMajor.objects.filter(major=major).first()
        if existing:
            return Response(
                {'detail': f'专业 “{major}” 已在 “{existing.department}” 院系下存在'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = DepartmentMajorSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def get(self, request):
        department_majors = DepartmentMajor.objects.all()
        data = [
            {
                'id': dm.id,
                'department': dm.department,
                'major': dm.major
            }
            for dm in department_majors
        ]
        return Response(data, status=status.HTTP_200_OK)

    def delete(self, request):
        """
        院系专业组合删除（分两步操作）。首次请求返回待删除内容，确认后删除。
        请求 JSON 格式：
        {
            "confirm": false,   # 首次请求设为false，确认请求设为true
            "delete_list": [     # 删除列表（仅在首次请求时必需）
                {"id": 1},
                {"id": 2},
                ...
            ]
        }
        """
        # ===== 第一阶段：处理首次请求（返回待删除内容） =====
        if not request.data.get('confirm', False):
            delete_list = request.data.get('delete_list')
            if not delete_list or not isinstance(delete_list, list):
                return Response(
                    {'detail': '删除请求格式不正确，需要 delete_list 数组'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 预校验删除项并收集信息
            preview_data = []
            errors = []

            for idx, item in enumerate(delete_list):
                dm_id = item.get('id')

                # 检查必填字段
                if dm_id is None:
                    errors.append(f"第 {idx + 1} 项: 缺少院系专业组合ID")
                    continue

                # 查询院系专业组合
                try:
                    dept_major = DepartmentMajor.objects.get(id=dm_id)

                    # 检查该院系专业组合是否有关联的班级
                    class_count = Class.objects.filter(department_major=dept_major).count()

                    # 添加预览信息
                    preview_data.append({
                        'id': dept_major.id,
                        'department': dept_major.department,
                        'major': dept_major.major,
                        'associated_classes': class_count
                    })

                except DepartmentMajor.DoesNotExist:
                    errors.append(f"第 {idx + 1} 项: id '{dm_id}' 不存在")
                except Exception as e:
                    errors.append(f"第 {idx + 1} 项: 查询院系专业组合时发生错误: {str(e)}")

            # 返回错误或预览数据
            if errors:
                return Response(
                    {
                        'detail': '删除请求包含错误',
                        'errors': errors,
                        'preview': preview_data
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:
                return Response(
                    {
                        'detail': '请确认以下待删除院系专业组合',
                        'warning': '删除院系专业组合将级联删除所有关联的班级及其学生数据',
                        'preview': preview_data,
                        'total': len(preview_data)
                    },
                    status=status.HTTP_200_OK
                )

        # ===== 第二阶段：处理确认请求（执行删除） =====
        else:
            delete_list = request.data.get('delete_list', [])
            if not delete_list or not isinstance(delete_list, list):
                return Response(
                    {'detail': '确认请求格式不正确'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 获取要删除的院系专业组合ID
            dm_ids = [item['id'] for item in delete_list if 'id' in item]

            # 直接获取全部待删除对象
            dept_majors = DepartmentMajor.objects.filter(id__in=dm_ids)
            dept_major_map = {dm.id: dm for dm in dept_majors}

            # 执行删除（原子操作）
            try:
                with transaction.atomic():
                    # 记录删除结果
                    results = []
                    for item in delete_list:
                        dm_id = item.get('id')
                        if dm_id is None:
                            continue  # 跳过无效项

                        dept_major = dept_major_map.get(dm_id)

                        # 验证存在
                        if not dept_major:
                            continue  # 跳过无效项

                        # 记录删除前的信息
                        department = dept_major.department
                        major = dept_major.major

                        # 执行删除（会级联删除关联的Class）
                        dept_major.delete()

                        results.append({
                            'id': dm_id,
                            'department': department,
                            'major': major
                        })
            except Exception as e:
                return Response(
                    {'detail': f'删除失败: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # 返回最终结果
            return Response(
                {
                    'detail': f'成功删除 {len(results)} 个院系专业组合',
                    'deleted': results
                },
                status=status.HTTP_200_OK
            )

    def put(self, request):
        """
        修改已有的院系-专业组合。
        请求体 (application/json)：
          {
            "id": 5,
            "department": "新的院系名称",
            "major": "新的专业名称"
          }
        注意：department 和 major 至少传其中一个。id 必须对应已有记录。
        """
        dm_id = request.data.get('id')
        new_dept = request.data.get('department')
        new_major = request.data.get('major')

        if not dm_id:
            return Response({'detail': '缺少 id 参数'}, status=status.HTTP_400_BAD_REQUEST)

        if not new_dept and not new_major:
            return Response(
                {'detail': 'department 和 major 至少传一个用于更新'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            dept_major = DepartmentMajor.objects.get(id=dm_id)
        except DepartmentMajor.DoesNotExist:
            return Response({'detail': '指定的院系-专业组合不存在'}, status=status.HTTP_404_NOT_FOUND)

        # 更新字段前先检查新的 department+major 组合是否冲突
        updated_dept = new_dept if new_dept is not None else dept_major.department
        updated_major = new_major if new_major is not None else dept_major.major

        # 如果新的组合和原来不一致，需要判断目标组合是否已存在
        if (updated_dept != dept_major.department) or (updated_major != dept_major.major):
            if DepartmentMajor.objects.filter(department=updated_dept, major=updated_major).exists():
                return Response(
                    {'detail': f'院系 "{updated_dept}" + 专业 "{updated_major}" 已存在，无法重复。'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # 执行更新
        dept_major.department = updated_dept
        dept_major.major = updated_major
        dept_major.save()

        return Response({
            'id': dept_major.id,
            'department': dept_major.department,
            'major': dept_major.major
        }, status=status.HTTP_200_OK)


class ParseExcelView(APIView):
    """
    接收用户“写完姓名”的 Excel，解析并返回预览 JSON。
    前端上传含姓名的 Excel（字段名 'file'，multipart/form-data）后，
    后端会：
      1. 检查第一行格式（“院系：...”、“专业：...”、“班级：...”）；
      2. 校验该院系+专业在数据库中是否存在；
      3. 检查第二行必须为“学号”、“姓名”；
      4. 自第三行开始遍历：若学号或姓名有缺失，则记录该行错误；
      5. 如果发现任何错误行，直接返回 400 + errors 列表；否则返回完整 students 列表供前端预览。
    返回格式示例（包含错误时）：
    {
      "errors": [
        {"row": 3, "detail": "学号或姓名缺失"},
        {"row": 5, "detail": "学号或姓名缺失"}
      ]
    }
    正常无误时返回：
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
    """
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [AllowAny]  # 删

    def post(self, request):
        excel_file = request.FILES.get('file')
        if not excel_file:
            return Response({'detail': '未上传文件'}, status=status.HTTP_400_BAD_REQUEST)

        # 1. 保存上传的 Excel 到临时目录
        temp_dir = tempfile.mkdtemp()
        intermediate_name = f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_upload.xlsx"
        intermediate_path = os.path.join(temp_dir, intermediate_name)
        with open(intermediate_path, 'wb') as f:
            for chunk in excel_file.chunks():
                f.write(chunk)

        try:
            # 2. 用 pandas 读取，无表头
            df = pd.read_excel(intermediate_path, header=None, dtype=str)

            # 3. 解析第一行：院系、专业、班级
            try:
                # 取单元格原始值（此时是字符串或 None）
                dept_cell = df.iat[0, 0]
                major_cell = df.iat[0, 1]
                class_cell = df.iat[0, 2]

                # 先按空值判断；如果是 NaN 或 None 或空字符串，都视为缺失
                if pd.isna(dept_cell) or pd.isna(major_cell) or pd.isna(class_cell):
                    raise ValueError

                dept_str = str(dept_cell).strip()
                major_str = str(major_cell).strip()
                class_str = str(class_cell).strip()
                if (
                        not dept_str.startswith('院系：') or
                        not major_str.startswith('专业：') or
                        not class_str.startswith('班级：')
                ):
                    raise ValueError
                department = dept_cell.split('：', 1)[1]
                major = major_cell.split('：', 1)[1]
                class_name = class_cell.split('：', 1)[1]
            except Exception:
                os.remove(intermediate_path)
                os.rmdir(temp_dir)
                return Response(
                    {'detail': '第一行格式不正确，应为“院系：...”、“专业：...”、“班级：...”'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 4. 校验 DepartmentMajor 是否存在，并获取对应实例
            try:
                deptmajor = DepartmentMajor.objects.get(department=department, major=major)
            except DepartmentMajor.DoesNotExist:
                os.remove(intermediate_path)
                os.rmdir(temp_dir)
                return Response(
                    {'detail': '指定的院系与专业组合在数据库中不存在'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            existing_class = Class.objects.filter(class_name=class_name).first()
            if existing_class:
                # 如果已存在同名班级，但它的 department_major 与当前解析到的不一致，就报错
                if existing_class.department_major_id != deptmajor.id:
                    dm_exist = DepartmentMajor.objects.get(id=existing_class.department_major_id)
                    # 清理临时文件
                    os.remove(intermediate_path)
                    os.rmdir(temp_dir)
                    return Response(
                        {
                            'detail': (
                                f'班级 “{class_name}” 已在 '
                                f'“{dm_exist.department} - {dm_exist.major}” 下存在，'
                                f'无法在 “{department} - {major}” 下使用'
                            )
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # 5. 校验第二行：必须是“学号”、“姓名”
            header_sid = df.iat[1, 0]
            header_name = df.iat[1, 1]

            # 空值判断
            if pd.isna(header_sid) or pd.isna(header_name):
                os.remove(intermediate_path)
                os.rmdir(temp_dir)
                return Response(
                    {'detail': '第二行应为“学号”、“姓名”，且不能为空'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            sid_label = str(header_sid).strip()
            name_label = str(header_name).strip()
            if sid_label != '学号' or name_label != '姓名':
                os.remove(intermediate_path)
                os.rmdir(temp_dir)
                return Response(
                    {'detail': '第二行应为“学号”、“姓名”'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 6. 从第三行开始提取并校验学号和姓名
            students = []
            errors = []
            for idx in range(2, len(df)):
                row_num = idx + 1  # Excel 中的实际行号 (1-based)
                cell_sid = df.iat[idx, 0]
                cell_name = df.iat[idx, 1]
                # 先判断是否缺失
                if pd.isna(cell_sid) or pd.isna(cell_name):
                    errors.append(
                        {
                            'row': f'第{row_num}行',
                            'sid': f'学号：{int(row_num - 2)}号',
                            'detail': '学号或姓名缺失'
                        }
                    )
                    continue
                sid = str(cell_sid).strip()
                name = str(cell_name).strip()
                # 如果转为字符串后还是空，也认为缺失
                if not sid or not name:
                    errors.append(
                        {
                            'row': f'第{row_num}行',
                            'sid': f'学号：{int(row_num - 2)}号',
                            'detail': '学号或姓名缺失'
                        }
                    )
                else:
                    students.append({
                        'student_id': sid,
                        'name': name,
                        'class_name': class_name,
                        'department': department,
                        'major': major
                    })

            # 7. 如果有任何错误行，直接返回错误列表
            if errors:
                os.remove(intermediate_path)
                os.rmdir(temp_dir)
                return Response(
                    {'errors': errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 8. 如果解析到的学生列表为空，也返回提示
            if not students:
                os.remove(intermediate_path)
                os.rmdir(temp_dir)
                return Response(
                    {'detail': '未检测到有效的学号和姓名行'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 9. 重命名临时文件：院系+专业+班级_提交时间_filled.xlsx
            submit_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            safe_filename = f"{department}-{major}-{class_name}_{submit_time}_filled.xlsx"
            new_path = os.path.join(temp_dir, safe_filename)
            os.rename(intermediate_path, new_path)

            # 10. 返回供前端预览确认
            return Response(
                {
                    'students': students,
                    'temp_file_path': new_path,
                    'filename': safe_filename
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            # 出现其它意外错误，清理并返回
            if os.path.exists(intermediate_path):
                os.remove(intermediate_path)
            os.rmdir(temp_dir)
            return Response(
                {'detail': f'解析失败：{str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SaveStudentsView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [AllowAny]  # 删

    def post(self, request):
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
        students = request.data.get('students')
        file_path = request.data.get('temp_file_path')
        filename = request.data.get('filename')
        # user_info = UserInfo.objects.get(userId=request.user.id)
        # repo_id = user_info.pri_repo_id
        # repo = seafile_api.get_repo(repo_id)

        if not isinstance(students, list) or not students:
            return Response({'detail': 'students 列表不能为空'}, status=status.HTTP_400_BAD_REQUEST)
        if not file_path or not filename:
            return Response({'detail': '缺少 temp_file_path 或 filename'}, status=status.HTTP_400_BAD_REQUEST)

        saved = []
        errors = []

        print(students)

        for rec in students:
            sid = rec.get('student_id')
            name = rec.get('name')
            class_name = rec.get('class_name')
            department = rec.get('department')
            major = rec.get('major')
            print(sid, name, class_name, department, major)

            # 基本字段完整性校验
            if not all([sid, name, class_name, department, major]):
                errors.append({'student_id': sid, 'detail': '字段不完整'})
                continue

            # 1. 校验院系+专业是否存在
            try:
                deptmajor = DepartmentMajor.objects.get(department=department, major=major)
            except DepartmentMajor.DoesNotExist:
                errors.append({'student_id': sid, 'detail': '院系-专业不存在'})
                continue

            # 2. 在全局范围检查同名班级是否已存在
            existing_class = Class.objects.filter(class_name=class_name).first()
            if existing_class:
                # 如果已存在，则判断它所属的院系+专业是否与当前记录一致
                if existing_class.department_major_id != deptmajor.id:
                    # 不同院系-专业下已有该班级，报错
                    dm_exist = DepartmentMajor.objects.get(id=existing_class.department_major_id)
                    errors.append({
                        'student_id': sid,
                        'detail': f'班级 “{class_name}” 已在 “{dm_exist.department}” 院系的 “{dm_exist.major}” 专业下存在，无法在 “{department} - {major}” 下创建'
                    })
                    continue
                # 否则 existing_class 属于同一院系-专业，可以复用 existing_class
                class_info = existing_class
                created_class = False
            else:
                # 3. 如果全局未出现同名班级，则在当前院系-专业下新建
                try:
                    class_info, created_class = Class.objects.get_or_create(
                        class_name=class_name,
                        department_major=deptmajor
                    )
                except IntegrityError:
                    # 理论上如果对 class_name 加了唯一性索引，这里可能捕获到冲突
                    errors.append({
                        'student_id': sid,
                        'detail': f'班级 “{class_name}” 在 “{department} - {major}” 下已存在，无法重复创建'
                    })
                    continue

            # 4. 保存/更新学生记录
            #    假设 Student 模型中有：student_id, name, class_info（ForeignKey to Class）
            try:
                student, created_student = Student.objects.update_or_create(
                    student_id=sid,
                    class_info=class_info,
                    defaults={'name': name}
                )
                print(student, created_student)
                saved.append({'student_id': sid, 'created': created_student})
            except Exception as e:
                errors.append({'student_id': sid, 'detail': f'保存学生失败：{str(e)}'})
                continue

        return Response({'saved': saved}, status=status.HTTP_200_OK)

    def get(self, request):
        """
        查询学生。支持下列可选 URL 参数过滤：
          - student_id
          - department, major
          - class_name
        如果都不传，则返回全体学生列表。
        返回格式（顺序固定为 department, major, class_name, student_id, name）：
        {
          "students": [
            {
              "department": "...",
              "major": "...",
              "class_name": "...",
              "student_id": "...",
              "name": "..."
            },
            ...
          ]
        }
        """
        student_id = request.query_params.get('student_id')
        department = request.query_params.get('department')
        major = request.query_params.get('major')
        class_name = request.query_params.get('class_name')

        qs = Student.objects.all().select_related('class_info__department_major')
        if student_id:
            qs = qs.filter(student_id=student_id)
        if department and major:
            try:
                dm = DepartmentMajor.objects.get(department=department, major=major)
                qs = qs.filter(class_info__department_major=dm)
            except DepartmentMajor.DoesNotExist:
                return Response(
                    {'detail': '指定的院系-专业组合不存在'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        if class_name:
            qs = qs.filter(class_info__class_name=class_name)

        results = []
        for stu in qs:
            dm = stu.class_info.department_major
            # 按 department, major, class_name, student_id, name 顺序组装
            results.append({
                'department': dm.department,
                'major': dm.major,
                'class_name': stu.class_info.class_name,
                'student_id': stu.student_id,
                'name': stu.name
            })

        return Response({'students': results}, status=status.HTTP_200_OK)

    def put(self, request):
        """
        批量更新学生姓名。前端请求示例：
        {
          "students": [
            {
              "id": 123,               # 必传：Student 表的主键
              "student_id": "2025001", # 必传：学号，用于校验
              "name": "李四"           # 必传：新的姓名
            },
            {
              "id": 124,
              "student_id": "2025002",
              "name": "王五"
            },
            ...
          ]
        }
        逻辑：
          1) 检查 students 列表非空，否则返回 400；
          2) 遍历每条记录，校验 id、student_id、name 均已提供；
          3) 按 id 取出 Student，不存在则记录错误；
          4) 校验数据库中的 student.student_id 与传入 student_id 是否一致，不一致则记录错误；
          5) 更新 name 并保存，保存成功则记录 saved，否则记录错误；
          6) 循环结束后，如果存在任何错误，则返回 400，包含 saved 列表和 errors 列表；
             如果全部成功，则返回 200，仅包含 saved 列表。
        返回示例（部分失败时）：
        {
          "saved": [
            {"id": 123, "student_id": "2025001", "updated": true}
          ],
          "errors": [
            {"id": 124, "student_id": "2025002", "detail": "该记录不存在"},
            {"id": 125, "student_id": "2025003", "detail": "提供的 student_id 与数据库不匹配"}
          ]
        }
        返回示例（全部成功时）：
        {
          "saved": [
            {"id": 123, "student_id": "2025001", "updated": true},
            {"id": 124, "student_id": "2025002", "updated": true}
          ]
        }
        """
        updates = request.data.get('updates')
        if not isinstance(updates, list) or not updates:
            return Response(
                {'detail': 'updates 列表不能为空'},
                status=status.HTTP_400_BAD_REQUEST
            )

        saved = []
        errors = []

        for rec in updates:
            pk = rec.get('id')
            provided_sid = rec.get('student_id')
            new_name = rec.get('name')

            # 校验必传字段
            if not pk or not provided_sid or not new_name:
                errors.append({
                    'id': pk,
                    'student_id': provided_sid,
                    'detail': 'id、student_id、name 均为必传字段'
                })
                continue

            # 按主键查找学生
            try:
                student = Student.objects.get(pk=pk)
            except Student.DoesNotExist:
                errors.append({
                    'id': pk,
                    'student_id': provided_sid,
                    'detail': '该记录不存在'
                })
                continue

            # 校验 student_id 是否匹配
            if student.student_id != provided_sid:
                errors.append({
                    'id': pk,
                    'student_id': provided_sid,
                    'detail': '提供的 student_id 与数据库中记录不匹配'
                })
                continue

            # 更新姓名并保存
            student.name = new_name
            try:
                student.save()
                saved.append({
                    'id': pk,
                    'student_id': provided_sid,
                    'updated': True
                })
            except Exception as e:
                errors.append({
                    'id': pk,
                    'student_id': provided_sid,
                    'detail': f'更新失败：{str(e)}'
                })

        # 如果有任何错误，返回 400，同时包含 saved 和 errors
        if errors:
            return Response(
                {'saved': saved, 'errors': errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 全部成功，返回 200，仅包含 saved 列表
        return Response({'saved': saved}, status=status.HTTP_200_OK)

    def delete(self, request):
        """
        批量删除学生（分两步操作）。首次请求返回待删除内容，确认后删除。
        请求 JSON 格式：
          {
            "confirm": false,          # 首次请求设为false，确认请求设为true
            "delete_list": [            # 删除列表（仅在首次请求时必需）
              {"id": 1, "student_id": "2025001"},
              {"id": 2, "student_id": "2025002"},
              ...
            ]
          }
        """
        # ===== 第一阶段：处理首次请求（返回待删除内容） =====
        if not request.data.get('confirm', False):
            delete_list = request.data.get('delete_list')
            if not delete_list or not isinstance(delete_list, list):
                return Response(
                    {'detail': '删除请求格式不正确，需要 delete_list 数组'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 预校验删除项并收集信息
            preview_data = []
            errors = []

            for idx, item in enumerate(delete_list):
                id_val = item.get('id')
                sid = item.get('student_id')

                # 检查必填字段
                if id_val is None or sid is None:
                    errors.append(f"第 {idx + 1} 项: 必须提供 id 和 student_id")
                    continue

                # 查询学生并验证
                try:
                    student = Student.objects.get(id=id_val)
                    if str(student.student_id) != str(sid):
                        raise ValueError("学号不匹配")

                    # 若没有关联对象，这里会抛出 ObjectDoesNotExist
                    class_info = student.class_info
                    dept_major = class_info.department_major

                except Student.DoesNotExist:
                    errors.append(f"第 {idx + 1} 项: id '{id_val}' 不存在")
                except ValueError:
                    errors.append(f"第 {idx + 1} 项: student_id '{sid}' 与记录不匹配")
                except ObjectDoesNotExist:
                    errors.append(f"第 {idx + 1} 项: 学生缺少班级或专业信息")
                except Exception as e:
                    errors.append(f"第 {idx + 1} 项: 查询关联信息时发生错误: {e}")
                else:
                    preview_data.append({
                        'id': student.id,
                        'student_id': student.student_id,
                        'name': student.name,
                        'class': class_info.class_name,
                        'department': dept_major.department,
                        'major': dept_major.major
                    })

                if errors:
                    return Response(
                        {'detail': '删除请求包含错误', 'errors': errors, 'preview': preview_data},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                return Response(
                    {
                        'detail': '请确认以下待删除学生，删除后该学号就为空值',
                        'preview': preview_data,
                        'total': len(preview_data)
                    },
                    status=status.HTTP_200_OK
                )

        # ===== 第二阶段：处理确认请求（执行删除） =====
        else:
            delete_list = request.data.get('delete_list', [])
            if not delete_list or not isinstance(delete_list, list):
                return Response(
                    {'detail': '确认请求格式不正确'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 获取要删除的学生ID（优化性能）
            student_ids = [item['id'] for item in delete_list if 'id' in item]

            # 直接获取全部待删除对象（关联查询专业信息）
            students = Student.objects.filter(id__in=student_ids)
            student_map = {s.id: s for s in students}

            # 执行删除（原子操作）
            try:
                with transaction.atomic():
                    # 记录删除结果
                    results = []
                    for item in delete_list:
                        student = student_map.get(item['id'])

                        # 验证存在且学号匹配
                        if not student or str(student.student_id) != str(item['student_id']):
                            continue  # 跳过无效项

                        student.delete()
                        results.append({
                            'id': student.id,
                            'student_id': student.student_id
                        })
            except Exception as e:
                return Response(
                    {'detail': f'删除失败: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # 返回最终结果
            return Response(
                {
                    'detail': f'成功删除 {len(results)} 名学生',
                    'deleted': results
                },
                status=status.HTTP_200_OK)


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
        redis_conn = get_redis_connection("default")
        user_serializer = UserSerializer
        user_info = UserInfo.objects.get(userId=request.user.id)
        repo_id = ava_repo_id

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
                avatar_file = request.FILES['avatar']
                try:
                    validate_image_content(avatar_file)  # 自定义验证函数
                except ValidationError as e:
                    return Response({
                        "code": 415,
                        "error": f"文件验证失败: {e.detail[0]}"
                    }, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

                ext = request.FILES.get("avatar").name.split(".")[-1]
                seafile_path = f"/{user.id}_tmp_ava_upload.{ext}"
                ava_path = f"/{user.id}_ava_upload.{ext}"
                final_filename = f'{user.id}_ava_upload.{ext}'
                cache_key = f"{user.id}_tmp_ava_upload"

                try:
                    if not redis_conn.exists(cache_key):
                        return Response({"code": 404, "message": "无待确认的头像"}, status=404)
                    seafile_api.auth()

                    repo = seafile_api.get_repo(repo_id)

                    if final_filename in [x["name"] for x in repo.list_dir("/")]:
                        repo.delete_file(ava_path)
                    repo.rename_file(seafile_path, final_filename)
                    user_info = UserInfo.objects.get(userId=user.id)
                    user_info.avatar = f'{server_url}/files/{repo_id}{final_filename}'
                    user_info.save()

                    try:
                        dow_file = seafile_ops.down_file_by_repo(repo_id, seafile_path)
                        print(dow_file)
                        return Response({
                            'file_url': dow_file
                        }, status=status.HTTP_200_OK)
                    except Exception as e:
                        return Response({
                            "detail": f'生成下载链接失败：: {e}',
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
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
        seafile_path = f"/{user.id}_tmp_ava_upload.{ext}"  # Seafile中的存储路径
        repo_id = ava_repo_id
        try:
            # 获取仓库对象
            repo = seafile_api.get_repo(repo_id)

            # 创建临时目录保存文件（确保文件名正确）
            temp_dir = tempfile.mkdtemp()
            temp_file_path = os.path.join(temp_dir, filename)

            with open(temp_file_path, 'wb') as temp_file:
                for chunk in avatar_file.chunks():
                    temp_file.write(chunk)

            # 上传到Seafile
            if filename in [x["name"] for x in repo.list_dir("/")]:
                repo.delete_file(seafile_path)
            repo.upload_file("/", temp_file_path)
            avatar_url = f"{server_url.rstrip('/')}/{repo_id}{seafile_path}"

            # 用户头像信息
            user_info = UserInfo.objects.get(userId=user.id)
            user_info.avatar = avatar_url
            user_info.save()

            redis_conn = get_redis_connection("default")
            redis_conn.setex(
                name=f"{user.id}_tmp_ava_upload",
                time=3600,  # 1小时回滚有效期
                value=json.dumps(avatar_url)
            )

            try:
                dow_file = seafile_ops.down_file_by_repo(repo_id, seafile_path)
                print(dow_file)
                return Response({
                    'file_url': dow_file
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({
                    "detail": f'生成下载链接失败：: {e}',
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
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


class AdminUserRoleModificationView(APIView):  # 类名去重
    permission_classes = [IsSuperAdmin]

    def post(self, request):
        # 1. 参数提取与验证
        user_id = request.data.get('user_id')
        role_id = request.data.get('role_id')

        if not user_id:
            return Response({
                "code": 400,
                "message": "请填写要修改的用户ID"
            }, status=status.HTTP_400_BAD_REQUEST)

        if not role_id:
            return Response({
                "code": 400,
                "message": "请填写角色ID"
            }, status=status.HTTP_400_BAD_REQUEST)

        # 2. 提前获取用户对象
        try:
            user = UserInfo.objects.get(userId=user_id)
        except UserInfo.DoesNotExist:
            return Response({
                "code": 404,
                "message": "用户不存在"
            }, status=status.HTTP_404_NOT_FOUND)

        # 3. 检查角色是否实际需要修改
        if user.role_id == role_id:
            return Response({
                "code": 400,
                "message": "用户角色未变更"
            }, status=status.HTTP_400_BAD_REQUEST)

        # 4. 验证角色是否存在
        if not Roles.objects.filter(role_id=role_id).exists():
            return Response({
                "code": 400,
                "message": "指定的角色不存在"
            }, status=status.HTTP_400_BAD_REQUEST)

        # 5. 使用指定用户的序列化器实例
        serializer = UserRoleUpdateSerializer(
            instance=user,
            data={'role_id': role_id},
            partial=True
        )

        if serializer.is_valid():
            try:
                serializer.save()
                return Response({
                    "code": 200,
                    "data": serializer.data,
                    "message": "用户角色修改成功"
                })
            except Exception as e:  # 捕获数据库操作异常
                logging.error(f"角色更新失败: {str(e)}")
                return Response({
                    "code": 500,
                    "message": "服务器内部错误"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                "code": 400,
                "errors": serializer.errors,
                "message": "数据验证失败"
            }, status=status.HTTP_400_BAD_REQUEST)


class TemplateCreateView(APIView):
    """教师创建新的提交模板；必须提供本次提交的标题。"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # 验证老师身份
        user = request.user
        try:
            info = UserInfo.objects.get(userId=user.id)
        except UserInfo.DoesNotExist:
            return Response({
                'code': 404,
                'error': '未找到用户信息，请联系管理员'
            }, status=404)
        if not info or info.role_id != 2:
            return Response({
                'detail': '只有老师(role_id=2)才能创建模板'
            }, status=status.HTTP_403_FORBIDDEN)

        # 确保提供了标题
        title = request.data.get('title', '').strip()
        if not title:
            return Response({'detail': '请提供本次提交的标题'}, status=status.HTTP_400_BAD_REQUEST)

        # 构造序列化器数据
        data = {
            'title': title,
            'description': request.data.get('description', ''),
            'due_date': request.data.get('due_date'),
        }
        serializer = SubmissionTemplateSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        # save() 内部会自动计算并赋值 version
        serializer.save(created_by=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class StudentSubmitView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        # 验证学生
        user = request.user
        try:
            info = UserInfo.objects.get(userId=user.id)
            print('info:', info)
            print("info_s:", info.student.id)
        except UserInfo.DoesNotExist:
            return Response({
                'code': 404,
                'error': '未找到用户信息，请联系管理员'
            }, status=404)
        if not info or info.role_id != 1:
            return Response({
                'detail': '只有学生可提交作业'
            }, status=status.HTTP_403_FORBIDDEN)

        # 获取模板
        template_id = request.data.get('template')
        print('template_id:', template_id)
        template = SubmissionTemplate.objects.filter(id=template_id).first()
        print('template:', template)
        if not template:
            return Response({'detail': '模板不存在'}, status=status.HTTP_404_NOT_FOUND)

        # 构建版本号与文件名
        version = template.version
        ext = request.FILES['file'].name.rsplit('.', 1)[-1]
        print('ext:', ext)
        userid = str(user.id)
        filename = f"{userid}_upload_t{template.id}_v{version}.{ext}"
        print('filename:', filename)
        seafile_path = f"/file/{filename}"
        print('seafile_path:', seafile_path)
        repo_id = info.pri_repo_id

        tmp_dir = tempfile.mkdtemp()
        local_path = os.path.join(tmp_dir, filename)
        with open(local_path, 'wb') as f:
            for chunk in request.FILES['file'].chunks():
                f.write(chunk)

        # 上传
        service = FileUpload(seafile_api, seafile_ops)
        try:
            service.upload_file(
                repo_id,
                seafile_path,
                local_path
            )
        except Exception as e:
            return Response({
                'detail': f'文件上传失败：{e}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            try:
                os.remove(local_path)
                os.rmdir(tmp_dir)
            except:
                pass

        # 保存提交记录
        data = {
            'template': template_id,
            'student': userid,
            'file_name': filename,
            'version': template.version
        }
        print('data:', data)
        serializer = StudentSubmissionSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': f'提交成功，版本 {version}',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        """
        通过 template 和 version 查询该次提交的所有历史下载链接。
        URL 示例: GET /api/submit/?template=1&version=2
        """
        # 验证学生身份
        user = request.user
        try:
            info = UserInfo.objects.get(userId=user.id)
            repo_id = info.pri_repo_id
            print(repo_id)
        except UserInfo.DoesNotExist:
            return Response({'detail': '未找到用户信息'}, status=404)
        if info.role_id != "1":
            return Response({'detail': '只有学生可操作'}, status=403)

        # 获取并校验参数
        tpl_id = request.query_params.get('template')
        ver = request.query_params.get('version')
        if not tpl_id or not ver:
            return Response({'detail': '请提供 template 和 version 参数'}, status=400)
        try:
            ver = int(ver)
        except ValueError:
            return Response({'detail': 'version 必须为整数'}, status=400)

        # 查找对应提交记录
        submission = StudentSubmission.objects.filter(
            template_id=tpl_id,
            student=user,
            version=ver
        ).first()
        if not submission:
            return Response({'detail': '指定版本的提交不存在'}, status=404)

        seafile_path = f"/file/{submission.file_name}"

        try:
            history = seafile_ops.get_file_history_by_repo(repo_id, seafile_path)
        except Exception as e:
            return Response({'detail': f'获取历史失败：{e}'}, status=500)

        data_list = history.get('data') if isinstance(history, dict) else None
        if not data_list:
            return Response({'detail': '历史记录格式不正确'}, status=500)

        links = []
        for item in data_list:
            commit = item.get('commit_id')
            ctime = item.get('ctime')
            description = item.get('description', '')
            # 去掉开头动作描述，如 'Added '
            desc = description.split(' ', 1)[-1] if ' ' in description else description
            # 构造下载链接，使用 Seafile HTTP API 标准格式
            print(desc)
            print(repo_id)
            try:
                down_file = seafile_ops.down_file_by_repo(repo_id, seafile_path)
                print('down_file:', down_file)
                return Response({
                    'file_url': down_file,
                    'links': links,
                    'commit': commit,
                    'ctime': ctime
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({
                    'detail': f'生成下载链接失败：{e}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
