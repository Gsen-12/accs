import json
import os
import re

from django.db import transaction
from django.shortcuts import get_object_or_404
from accs.utils.seafile_operate import SeafileOperations, FileUpload
import tempfile

import pandas as pd
from django.contrib.auth import get_user_model
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from seafileapi import SeafileAPI

from CorrectionPlatformBackend.settings_dev import login_name, pwd, server_url, repo_token
from accs.models import UserInfo, IPConfig, AnalysisResult, Student, SubmissionTemplate, Class, StudentSubmission
from accs.serializers import AnalysisSerializer
from accs.services import get_reliable_local_ip, DifyService

User = get_user_model()

seafile_api = SeafileAPI(login_name, pwd, server_url)
seafile_api.auth()  # 认证
seafile_ops = SeafileOperations(server_url, repo_token)


class AnalyzeCodeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            user_id = int(request.data.get('id'))
            print('1', user_id)

            # 获取前端传递的模板ID和版本号
            template_id = request.data.get('template_id')
            version = request.data.get('version')

            # 查询模板
            template = SubmissionTemplate.objects.get(id=template_id)
            print('template:', template)
            if not template:
                return Response({
                    'detail': '模板不存在'
                }, status=status.HTTP_404_NOT_FOUND)
        except (TypeError, ValueError):
            return Response({
                "error": "无效或缺少“id”参数"
            }, status=status.HTTP_400_BAD_REQUEST)

            # 2. 用 select_related 预先把外键的 Class 一起查出来，避免两次查询
        try:
            user_info = UserInfo.objects.select_related('class_id').get(userId=user_id)
        except UserInfo.DoesNotExist:
            return Response({
                "error": "找不到用户信息"
            }, status=status.HTTP_404_NOT_FOUND)

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
                'template_id': template_id,
                'version': version
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
                'template_id': template_id,
                'version': version,
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
        redis_conn = get_redis_connection("analyze")
        class_id = request.data.get('class_id')
        print(class_id)
        print(redis_conn.keys())
        try:
            value = [x.decode() for x in redis_conn.keys() if x.decode().split('_')[0] == class_id]
            print(value)
            cache_value = " ".join(value)
            return Response({
                'code': 200,
                'cache_value': cache_value,
            })
        except Exception as e:
            return Response({
                'detail': str(e)
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    def post(self, request):
        user_id = request.data.get('user_id')
        class_name = request.data.get('class_name')

        try:
            # 校验必传字段
            if not {'user_id'}.issubset(request.data):
                return Response({
                    "message": "缺少必填字段"
                }, status=400)

            # 从Redis中获取缓存数据
            cache_key = f'{class_name}_{user_id}_file_upload'
            redis_conn = get_redis_connection("analyze")
            cache_value = redis_conn.get(cache_key)
            if not cache_value:
                return Response({
                    "code": 404, "message": "无缓存数据"
                })

            # 解码缓存数据
            if isinstance(cache_value, bytes):
                decoded_str = cache_value.decode('utf-8')
            else:
                decoded_str = cache_value

            # 兼容处理可能存在的旧数据格式
            if decoded_str.startswith("'") and decoded_str.endswith("'"):
                decoded_str = decoded_str.strip("'")

            # 解析JSON格式数据
            try:
                parsed_data = json.loads(decoded_str)
            except json.JSONDecodeError:
                # 处理转义字符问题
                decoded_str = decoded_str.replace('\\n', '\n').replace('\\"', '"')
                parsed_data = json.loads(decoded_str)

            # 提取字段
            correct_code = parsed_data.get('correct_code', '').replace('\\n', '\n')
            description = parsed_data.get('description', '').replace('\\n', '\n')

            # 打印解析后的数据（可以删除）
            print('老师查看AI批改:', parsed_data)

            # 获取模板ID和版本号
            template_id = parsed_data.get('template_id')  # 假设数据中有 template_id 字段
            version = parsed_data.get('version')  # 假设数据中有 version 字段

            # 查询模板和提交记录
            template = SubmissionTemplate.objects.get(id=template_id)
            submission = StudentSubmission.objects.get(template=template, student_id=user_id, version=version)
            print('template:', template)
            print('submission', submission)
            if not template or not submission:
                return Response({
                    'detail': '模板不存在 或 提交不存在'
                }, status=status.HTTP_404_NOT_FOUND)

            # 保存到 AnalysisResult 模型
            with transaction.atomic():  # 使用事务保证数据一致性
                analysis_result = AnalysisResult(
                    vulnerabilities=parsed_data.get('vulnerabilities', 0),
                    errors=parsed_data.get('errors', 0),
                    code_smells=parsed_data.get('code_smells', 0),
                    accepted_issues=parsed_data.get('accepted_issues', 0),
                    duplicates=parsed_data.get('duplicates', 0),
                    type=parsed_data.get('type', []),
                    severity=parsed_data.get('severity', 'low'),
                    correct_code=correct_code,
                    description=description,
                    template=template,  # 关联模板
                    user_id=user_id,  # 存储用户ID
                )
                analysis_result.save()

            # 返回成功的响应
            return Response({
                "code": 200,
                "data": {
                    'correct_code': correct_code,
                    'description': description,
                    'template_id': template.id,
                    'version': version
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # 处理异常
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


class SaveExcelView(APIView):
    """
    通过 template_id 和 class_id 从数据库查询 AI 批改结果并上传到 Seafile，
    文件名取自 SubmissionTemplate.title_v{version}.xlsx，只有老师(role_id=2)可调用。
    POST 参数：
    {
        "template_id": 1,
        "class_id": 3,
    }
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        download_link = ''

        try:
            info = UserInfo.objects.get(userId=user.id)
        except UserInfo.DoesNotExist:
            return Response({
                'code': 404,
                'error': '未找到用户信息，请联系管理员'
            }, status=404)
        if not info or info.role_id != 2:
            return Response({
                'detail': '只有老师才能'
            }, status=status.HTTP_403_FORBIDDEN)

        # 2. 参数校验
        tpl_id = request.data.get('template_id')
        stu_id = request.data.get('stu_id')
        print(tpl_id)
        cls_id = request.data.get('class_id')
        if not tpl_id or not cls_id:
            return Response({
                'detail': '缺少 template_id、class_id'
            }, status=status.HTTP_400_BAD_REQUEST)

        # 3. 模板 & 班级 校验
        # 只允许查询当前老师创建的模板
        template = SubmissionTemplate.objects.filter(id=tpl_id).first()
        print(template)
        if not template:
            return Response({
                'detail': '模板不存在'
            }, status=status.HTTP_404_NOT_FOUND)

        submissions = StudentSubmission.objects.filter(
            template_id=tpl_id,
        ).select_related('student')
        print(submissions)

        if not submissions.exists():
            return Response({
                'detail': '未找到任何提交记录'
            }, status=status.HTTP_404_NOT_FOUND)

        # 5. 准备 Excel 数据
        rows = []
        for sub in submissions:
            try:
                ar = AnalysisResult.objects.get(user_id=stu_id)
                correct_code = ar.correct_code  # 替换为实际字段
                description = ar.description  # 替换为实际字段
            except AnalysisResult.DoesNotExist:
                correct_code = ''
                description = ''

            stu = sub.student
            student_id = stu.studentinfo.student.student_id if hasattr(stu, 'studentinfo') else str(stu.id)
            student_name = stu.studentinfo.student.name if hasattr(stu, 'studentinfo') else stu.get_username()
            user_info = UserInfo.objects.select_related('class_id').get(userId=stu_id)
            class_obj = user_info.class_id  # Class 实例
            class_name = class_obj.class_name
            print('class_name', class_name)

            rows.append({
                '学号': student_id,
                '姓名': student_name,
                '班级': class_name,
                'correct_code': correct_code,
                'description': description
            })

        # 6. 构建 DataFrame
        df = pd.DataFrame(rows)[['学号', '姓名', '班级', 'correct_code', 'description']]

        # 7. 保存到临时文件并上传到 Seafile
        title = template.title.strip().replace('/', '_')
        filename = f"{title}_v{template.version}.xlsx"

        # 临时目录用于存储 Excel 文件
        tmp_dir = tempfile.mkdtemp()
        file_path = os.path.join(tmp_dir, filename)

        try:
            df.to_excel(file_path, index=False)
        except Exception as e:
            return Response({'detail': f'保存失败：{e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 8. 上传到 Seafile
        try:
            file_upload = FileUpload(seafile_api, seafile_ops)
            repo_id = info.pri_repo_id
            seafile_path = f"/file/{filename}"

            file_upload.upload_file(repo_id, seafile_path, file_path)

            # 获取下载链接
            download_link = seafile_ops.down_file_by_repo(repo_id, seafile_path)

        except Exception as e:
            return Response({'detail': f'上传到 Seafile 失败：{e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            # 删除临时文件
            try:
                os.remove(file_path)
                os.rmdir(tmp_dir)
            except:
                pass

        # 返回 Seafile 链接
        return Response({
            'code': 200,
            'message': '文件上传成功',
            'file_url': download_link,
            'record_count': len(rows)
        }, status=status.HTTP_200_OK)
