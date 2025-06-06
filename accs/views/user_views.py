import datetime
import json
import os
import tempfile
import uuid
from sqlite3 import IntegrityError

import pandas as pd
from django.contrib.auth import authenticate, get_user_model
from django.db import transaction
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
from seafileapi import SeafileAPI
from django.core.files.storage import default_storage
from sqlalchemy import create_engine
from CorrectionPlatformBackend import settings
from CorrectionPlatformBackend.base import login_name, pwd, server_url
from accs.models import StuAssignment, DepartmentMajor, Student, Class
from accs.serializers import DepartmentMajorSerializer
from rest_framework.permissions import AllowAny
from accs.models import Roles, UserInfo, Group, GroupAssignment
from accs.permissions import IsSuperAdmin, IsTeacher
from accs.serializers import UserSerializer, UserInfoSerializer, RolesSerializer, \
    validate_image_content, GroupSerializer
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from accs.utils.middleware import UUIDTools

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
                    repo.create_dir('/file')
                    repo.create_dir('/ava')
                    repo.create_dir('/result')
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
    A1: 院系：<department>   B1: 专业：<major>   C1: 班级：<class>
    A2: 学号              B2: 姓名   C2:（空）
    A3~A(N+2): 1~N       B3~B(N+2): 空   C3~C(N+2): 空
    """

    parser_classes = [JSONParser, MultiPartParser, FormParser]

    def post(self, request):
        data = request.data
        # 1. 读取并校验字段
        upload_path = data.get("upload_path")
        if not {'upload_path'}.issubset(request.data):
            return Response({"message": "请选择你要保存的路径"}, status=400)
        directory = os.path.dirname(upload_path)
        # 检查目录是否存在，不存在则创建
        if not default_storage.exists(directory):
            # 递归创建目录（包括所有父级目录）
            os.makedirs(directory, exist_ok=True)
        cls_name = data.get('class', '').strip()
        count = data.get('count')
        dept = data.get('department', '').strip()
        major = data.get('major', '').strip()

        user_info = UserInfo.objects.get(userId=request.user.id)
        repo_id = user_info.pri_repo_id

        # 校验 count 是否为非负整数
        try:
            count = int(count)
            if count < 0:
                raise ValueError
        except Exception:
            return Response(
                {'detail': f'学生人数 {count} 必须为非负整数'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 2. 判断院系+专业组合是否存在
        try:
            dep_major = DepartmentMajor.objects.get(department=dept, major=major)
        except DepartmentMajor.DoesNotExist:
            return Response(
                {'detail': f'指定的院系“{dept}”与专业“{major}”组合不存在'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 3. 全局检查 class_name 是否已存在
        existing_class = Class.objects.filter(class_name=cls_name).first()
        if existing_class:
            # 如果存在，找出它对应的院系+专业，告诉前端
            dep_major_exist = DepartmentMajor.objects.get(id=existing_class.department_major_id)
            exist_dept = dep_major_exist.department
            exist_major = dep_major_exist.major
            return Response(
                {
                    'detail': f'班级 “{cls_name}” 已在 “{exist_dept}” 院系的 “{exist_major}” 专业下存在，无法重复创建'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # 4. 构造 Excel 行数据
        rows = []
        # 第一行：院系、专业、班级
        rows.append([f'院系：{dept}', f'专业：{major}', f'班级：{cls_name}'])
        # 第二行：学号、姓名、（空列）
        rows.append(['学号', '姓名', ''])
        # 后续行：学号从1到count，姓名和班级列留空
        for i in range(1, count + 1):
            rows.append([i, '', ''])

        df = pd.DataFrame(rows)

        # 5. 写入临时 Excel
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"{major}-{dept}-{cls_name}_{count}_{timestamp}_class_list.xlsx"
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, filename)
        repo = seafile_api.get_repo(repo_id)
        base = f"{server_url.rstrip('/')}"
        file_url = f"{base}/file/{repo_id}/result/{filename}"

        try:
            # header=False, index=False：不写列名、不写行索引
            df.to_excel(file_path, header=False, index=False)
        except ModuleNotFoundError:
            return Response(
                {'detail': 'openpyxl 未安装，无法生成 Excel'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response(
                {'detail': f'生成 Excel 失败：{str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # 6. 上传到 Seafile
        try:
            repo.upload_file('/result', file_path)
        except Exception as e:
            return Response(
                {'detail': f'Seafile 上传失败：{str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        try:
            with open(file_path, 'rb') as f:  # 以二进制模式打开文件
                default_storage.save(
                    os.path.join(upload_path, f"{filename}.xlsx"),  # 显式添加扩展名
                    f
                )
        except Exception as e:
            return Response(
                {'detail': f'保存到默认存储失败：{str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        finally:
            # 清理临时目录和文件
            try:
                os.remove(file_path)
                os.rmdir(temp_dir)
            except:
                pass

        # 7. 返回前端文件地址
        return Response({
            'file_url': file_url
        }, status=status.HTTP_201_CREATED)

    # def get(self, request):
    #     data = request.data
    #     user = request.user
    #     save_path = request.data.get('save_path')
    #     target_path = request.data.get('target_path')
    #     user_info = UserInfo.objects.get(userId=request.user.id)
    #     repo_id = user_info.pri_repo_id
    #     repo_name = user.username
    #     if os.path.exists(save_path) is False:
    #         return Response(
    #             {'detail': '保存路径不存在'},
    #             status=status.HTTP_400_BAD_REQUEST
    #         )
    #     api_url = f'https://seafile.accs.rabbitmind.net/library/{repo_id}/{repo_name}/result/{target_path}'
    #     response = requests.get(api_url)
    #     if response.status_code == 404:
    #         return Response(
    #             {'detail': f'没找到这个文件，是否创建了表格？'},
    #             status=status.HTTP_404_NOT_FOUND
    #         )
    #     temp_dir = tempfile.mkdtemp()
    #     repo = seafile_api.get_repo(repo_id)
    #     base = f"{server_url.rstrip('/')}"
    #     local_save_path = f'{save_path}/downloaded_file.jpg'
    #     try:
    #         repo.download_file(target_path, local_save_path)
    #     except Exception as e:
    #         return Response(
    #             {'detail': f'Seafile 下载失败：{str(e)}'},
    #             status=status.HTTP_500_INTERNAL_SERVER_ERROR
    #         )
    #     return Response({'detail': '下载完成'}, status=status.HTTP_201_CREATED)


class DepartmentMajorView(APIView):
    """
    接收前端 POST 上传的 JSON：{'department': '信息工程学院', 'major': '计算机科学与技术'}
    将其存入 DepartmentMajor 表，并返回序列化后的记录。
    """
    parser_classes = [JSONParser, MultiPartParser, FormParser]

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


class ParseFilledExcelView(APIView):
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
        user_info = UserInfo.objects.get(userId=request.user.id)
        repo_id = user_info.pri_repo_id
        repo = seafile_api.get_repo(repo_id)

        base = f"{server_url.rstrip('/')}"
        file_url = f"{base}/file/{repo_id}/result/{filename}"
        if not isinstance(students, list) or not students:
            return Response({'detail': 'students 列表不能为空'}, status=status.HTTP_400_BAD_REQUEST)
        if not file_path or not filename:
            return Response({'detail': '缺少 temp_file_path 或 filename'}, status=status.HTTP_400_BAD_REQUEST)

        saved = []
        errors = []

        for rec in students:
            sid = rec.get('student_id')
            name = rec.get('name')
            class_name = rec.get('class_name')
            department = rec.get('department')
            major = rec.get('major')

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
                saved.append({'student_id': sid, 'created': created_student})
            except Exception as e:
                errors.append({'student_id': sid, 'detail': f'保存学生失败：{str(e)}'})
                continue

        # 如果有任何错误，则直接返回，不进行文件上传
        if errors:
            return Response({'saved': saved, 'errors': errors}, status=status.HTTP_400_BAD_REQUEST)

        # 5. 上传已重命名的 Excel 到 Seafile
        try:
            repo.upload_file('/result', file_path)
        except Exception as e:
            return Response({'detail': f'Seafile 上传失败：{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            # 上传成功后清理临时文件
            try:
                os.remove(file_path)
                os.rmdir(os.path.dirname(file_path))
            except:
                pass

        return Response({'saved': saved, 'file_url': file_url}, status=status.HTTP_200_OK)

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
                        errors.append(f"第 {idx + 1} 项: student_id '{sid}' 与记录不匹配")
                    else:
                        # 获取完整的院系专业信息
                        class_info = student.class_info
                        department_major = class_info.department_major

                        # 添加详细的预览信息
                        preview_data.append({
                            'id': student.id,
                            'student_id': student.student_id,
                            'name': student.name,
                            'class': class_info.class_name,
                            'department': department_major.department,
                            'major': department_major.major
                        })
                except Student.DoesNotExist:
                    errors.append(f"第 {idx + 1} 项: id '{id_val}' 不存在")
                except Student.class_info.RelatedObjectDoesNotExist:
                    errors.append(f"第 {idx + 1} 项: 学生缺少班级信息")
                except Exception as e:
                    errors.append(f"第 {idx + 1} 项: 查询关联信息时发生错误: {str(e)}")

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
        user_info = UserInfo.objects.get(userId=request.user.id)
        repo_id = user_info.pri_repo_id

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
        user_info = UserInfo.objects.get(userId=request.user.id)
        repo_id = user_info.pri_repo_id
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