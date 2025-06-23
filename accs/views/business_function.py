import json
import os
import re

import pandas as pd
from django.contrib.auth import get_user_model
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from seafileapi import SeafileAPI

from CorrectionPlatformBackend.settings_dev import login_name, pwd, server_url
from accs.models import UserInfo, IPConfig, AnalysisResult, Student
from accs.serializers import AnalysisSerializer
from accs.services import get_reliable_local_ip, DifyService

User = get_user_model()

seafile_api = SeafileAPI(login_name, pwd, server_url)
seafile_api.auth()  # 认证


class AnalyzeCodeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            user_id = int(request.data.get('id'))
            print('1', user_id)
        except (TypeError, ValueError):
            return Response({"error": "Invalid or missing 'id' parameter"}, status=status.HTTP_400_BAD_REQUEST)

            # 2. 用 select_related 预先把外键的 Class 一起查出来，避免两次查询
        try:
            user_info = UserInfo.objects.select_related('class_id').get(userId=user_id)
        except UserInfo.DoesNotExist:
            return Response({"error": "UserInfo not found"}, status=status.HTTP_404_NOT_FOUND)

            # 3. 直接拿 class_name：
        class_obj = user_info.class_id  # Class 实例
        class_pk = user_info.class_id_id  # 整数 ID
        class_name = class_obj.class_name  # 字符串名字

        # —— debug 打印（可删） ——
        print(f"找到用户 {user_id}，班级 ID={class_pk}，班级名={class_name}")
        print("学生输入的内容:", request.data)
        try:
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
            # 修复后的代码
            correct = result_data.get('correct_code', '')
            # 修复建议
            des = result_data.get('description', '')

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
                'user': user_id,
                'correct_code': correct,
                'description': des,
            }
            print("cleaned_data:", cleaned_data)

            redis_conn = get_redis_connection('analyze')
            redis_conn.setex(
                name=f"{class_name}_{user_id}_file_upload",
                time=604800,  # 7天
                value=json.dumps(cleaned_data)
            )
            return Response({
                'vulnerabilities': vul,
                'errors': err,
                'code_smells': smells,
                'accepted_issues': accepted,
                'duplicates': dup,
                'type': type_str,
                'severity': severity_value,
                'correct_code': correct,
                'description': des,
                'user': user_id,
            }, status=status.HTTP_201_CREATED)
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
        # 获取请求参数
        execlname = request.data.get('execlname')
        class_name = request.data.get('class_name')
        save_path = request.data.get('path')  # 用户指定的保存路径

        # 参数验证
        required_params = {'execlname', 'class_name', 'path'}
        if not required_params.issubset(request.data):
            missing = required_params - set(request.data.keys())
            return Response({
                "code": 400,
                "message": f"缺少必要参数: {', '.join(missing)}"
            }, status=400)

        # 验证路径是否合法
        if not os.path.isdir(save_path):
            return Response({
                "code": 400,
                "message": "提供的路径不存在或不是目录"
            }, status=400)

        # 从Redis获取数据
        redis_conn = get_redis_connection("answer")

        # 构建Redis key模式: {class_name}_{student_id}_file_upload
        redis_key_pattern = f"{class_name}_*_file_upload"
        redis_keys = [k.decode() for k in redis_conn.keys(redis_key_pattern)]

        if not redis_keys:
            return Response({
                "detail": f"未找到班级 '{class_name}' 的分析结果"
            }, status=status.HTTP_404_NOT_FOUND)

        # 获取所有键对应的值
        redis_values = redis_conn.mget(redis_keys)

        # 准备数据结构
        data_list = []
        student_ids = set()

        # 第一步：提取学生ID并准备批量查询
        for key in redis_keys:
            # 从key中提取student_id: {class_name}_{student_id}_file_upload
            parts = key.split('_')
            if len(parts) >= 3:
                student_id = parts[1]  # 假设student_id是key的第二部分
                student_ids.add(student_id)

        # 批量查询学生信息
        students = Student.objects.filter(student_id__in=student_ids)
        student_map = {str(student.student_id): student for student in students}

        # 第二步：处理Redis数据
        for key, value in zip(redis_keys, redis_values):
            if not value:
                continue

            # 从key中提取student_id
            parts = key.split('_')
            if len(parts) < 3:
                continue

            student_id = parts[1]
            student = student_map.get(student_id)

            if not student:
                # 如果找不到学生信息，使用默认值
                student_name = "未知学生"
                class_info = "未知班级"
            else:
                student_name = student.name
                class_info = student.class_info.name if student.class_info else "未知班级"

            try:
                # 解析Redis值 (假设存储的是JSON字符串)
                data_dict = json.loads(value.decode())

                # 获取correct_code和description
                correct_code = data_dict.get('correct_code', '')
                description = data_dict.get('description', '')

                # 添加到数据列表
                data_list.append({
                    '学号': student_id,
                    '姓名': student_name,
                    '班级': class_info,
                    'correct_code': correct_code,
                    'description': description
                })

            except json.JSONDecodeError:
                # 如果解析失败，存储原始值
                data_list.append({
                    '学号': student_id,
                    '姓名': student_name,
                    '班级': class_info,
                    'correct_code': '解析错误',
                    'description': value.decode()
                })

        # 如果没有有效数据
        if not data_list:
            return Response({
                "detail": "未找到有效的分析结果数据"
            }, status=status.HTTP_404_NOT_FOUND)

        # 创建DataFrame
        try:
            df = pd.DataFrame(data_list)
            # 重新排序列顺序
            df = df[['学号', '姓名', '班级', 'correct_code', 'description']]
        except Exception as e:
            return Response({
                'detail': f'创建数据框失败: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 构建完整文件路径
        filename = f"{execlname}.xlsx"
        full_path = os.path.join(save_path, filename)

        # 保存Excel文件
        try:
            df.to_excel(full_path, index=False)
        except Exception as e:
            return Response({
                'detail': f'保存Excel文件失败: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 返回成功响应
        return Response({
            "code": 200,
            "message": "文件保存成功",
            "path": full_path,
            "student_count": len(data_list)
        }, status=status.HTTP_200_OK)
