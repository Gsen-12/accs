import json
import os
import tempfile
import pandas as pd
from django.contrib.auth import get_user_model
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from seafileapi import SeafileAPI
import re
from rest_framework.decorators import api_view
from CorrectionPlatformBackend.base import login_name, pwd, server_url
from accs.models import AnalysisResult, IPConfig
from accs.serializers import AnalysisSerializer
from rest_framework.permissions import AllowAny
from accs.services import DifyService, get_reliable_local_ip, DifyAnswer
from accs.models import Roles, UserInfo, Group, GroupAssignment
from rest_framework.parsers import MultiPartParser, FormParser

User = get_user_model()

seafile_api = SeafileAPI(login_name, pwd, server_url)
seafile_api.auth()  # 认证


class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        user = request.user
        user_info = UserInfo.objects.get(userId=request.user.id)
        repo_id = user_info.pri_repo_id
        user_file = request.FILES.get('file')
        ext = request.FILES.get('file').name.split('.')[-1]
        filename = f"{user.id}_file_upload.{ext}"
        seafile_path = f"/file/{user.id}_file_upload.{ext}"  # Seafile中的存储路径
        try:
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
        user = request.user
        user_info = UserInfo.objects.get(userId=request.user.id)
        repo_id = user_info.pri_repo_id
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
