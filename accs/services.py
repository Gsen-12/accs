# accs_project/dify/services.py
import netifaces
import requests
import json
from django.conf import settings
import re
from .models import IPConfig
import datetime


class DifyService:

    @staticmethod
    def get_current_host_ip():
        # 从数据库获取最新一条 IP 配置，否则返回 默认值：localhost
        latest = IPConfig.objects.order_by('-updated_at').first()
        ip = latest.ip_address if latest else 'localhost'
        print(f"[get_current_host_ip] 从数据库取到的 IP 是：{ip}")  # 打印 数据库IP
        return ip

    @classmethod
    def get_api_url(cls):
        # dify后端API
        # host_ip：数据库提取IP，默认值localhost
        host_ip = cls.get_current_host_ip()
        url = f"http://{host_ip}/v1/chat-messages"
        print(f"[get_api_url]：{url}")
        return url

    @classmethod
    def analyze_code(cls, code_content):
        # 调用Dify的请求头
        headers = {
            "Authorization": f"Bearer {settings.DIFY_API_KEY}",
            "Content-Type": "application/json"
        }

        # 调用Dify的格式，阻塞模式
        payload = {
            "inputs": {},
            # 学生输入的代码
            "query": code_content,
            "response_mode": "blocking",
            "conversation_id": "",
            # 跟Dify对话的用户名，后续可用学生id
            "user": "django_backend",
        }
        try:
            # 从get_api_url拿URL
            url = cls.get_api_url()
            print(f"Dify API: {url}")
            response = requests.post(url, headers=headers, json=payload)
            print("response:", response)
            resp_json = response.json()
            print('resp_json', resp_json)
            # 处理报错
            if isinstance(resp_json, dict) and resp_json.get('status') not in (None, 200):
                time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')    # 打印报错时间
                print(time)
                return {
                    'error_message': resp_json.get('message', 'Unknown error'),
                    'status': resp_json.get('status'),
                }

            # 打印原始响应
            print("\n" + "=" * 50 + " 原始响应内容 " + "=" * 50)
            # print(response.text)
            print("resp_json:", resp_json)
            print("=" * 120 + "\n")

            # 检测HTTP状态码
            response.raise_for_status()
            return cls._handle_response(resp_json)
        except Exception as e:
            # 一般为Dify_Api错误,或者Dify未启动
            # return None
            print(f"API请求失败: {e}")
            # 如果是 HTTPError，有可能 response.json() 已经包含 code/message/status
            try:
                err = response.json()
                return {
                    'error_message': err.get('message', str(e)),
                    'status': err.get('status', response.status_code),
                }
            except:
                # 一般网络异常等，返回通用错误
                return {
                    'error_message': str(e),
                    'status': getattr(response, 'status', None) or 500,
                }

    @classmethod
    def _handle_response(cls, response_data):
        try:
            raw_answer = response_data.get('answer', '{}')
            # 处理可能的markdown格式
            raw_answer = re.sub(r"```json?|```", '', raw_answer)
            print("处理后的内容：", raw_answer)
            json_texts = re.findall(r"\{[\s\S]*?\}", raw_answer)
            combined = {}
            for text in json_texts:
                try:
                    part = json.loads(text)
                    combined.update(part)
                except json.JSONDecodeError:
                    continue
            # 返回数据转换
            return {
                'vulnerabilities': int(combined.get('vulnerabilities', 0)),
                'errors': int(combined.get('errors', 0)),
                'code_smells': int(combined.get('code_smells', 0)),
                'accepted_issues': int(combined.get('accepted_issues', 0)),
                'duplicates': int(combined.get('duplicates', 0)),
                'type': combined.get('type', []),
                'correct_code': combined.get('correct_code', ''),
                'description': combined.get('description', '')
            }
        except Exception as e:
            print(f"Dify数据转换失败: {e}")
            raise


class DifyAnswer:

    @classmethod
    def analyze_code(cls, code_content):
        url = 'http://192.168.101.50/v1/chat-messages'
        # 调用Dify的请求头
        headers = {
            "Authorization": f"Bearer app-uzS2iFDn2VLVAznB2KogZRWq",  # Dify_key在settings
            "Content-Type": "application/json"
        }

        # 调用Dify的格式，阻塞模式
        payload = {
            "inputs": {},
            # 学生输入的代码
            "query": code_content,
            "response_mode": "blocking",
            "conversation_id": "",
            # 跟Dify对话的用户名，后续可用学生id
            "user": "django_a",
        }
        try:
            # 从get_api_url拿URL

            print(f"Dify_a API: {url}")
            response = requests.post(url, headers=headers, json=payload)
            print("response:", response)
            resp_json = response.json()
            # 处理报错
            if isinstance(resp_json, dict) and resp_json.get('status') not in (None, 200):
                time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')    # 打印报错时间
                print(time)
                return {
                    'error_message': resp_json.get('message', 'Unknown error'),
                    'status': resp_json.get('status'),
                }

            # 打印原始响应
            print("\n" + "=" * 50 + " 原始响应内容 " + "=" * 50)
            print("resp_json:", resp_json)
            print("=" * 120 + "\n")

            # 检测HTTP状态码
            response.raise_for_status()
            return cls._handle_response(resp_json)
        except Exception as e:
            # 一般为Dify_Api错误,或者Dify未启动
            # return None
            print(f"API请求失败: {e}")
            # 如果是 HTTPError，有可能 response.json() 已经包含 code/message/status
            try:
                err = response.json()
                return {
                    'error_message': err.get('message', str(e)),
                    'status': err.get('status', response.status_code),
                }
            except:
                # 一般网络异常等，返回通用错误
                return {
                    'error_message': str(e),
                    'status': getattr(response, 'status', None) or 500,
                }

    @classmethod
    def _handle_response(cls, response_data):
        try:
            raw_answer = response_data.get('answer', '{}')
            # 处理可能的markdown格式
            raw_answer = re.sub(r"```json?|```", '', raw_answer)
            print("处理后的内容：", raw_answer)
            parsed = json.loads(raw_answer)
            # 返回数据转换
            return {
                'correct_code': parsed.get('correct_code', ''),
                'description': parsed.get('description', '')
            }
        except Exception as e:
            print(f"Dify数据转换失败: {e}")
            raise


# 自定义IP
def is_private_ip(ip):
    patterns = [r'^10\.', r'^172\.(1[6-9]|2\d|3[0-1])\.', r'^192\.168\.']
    return any(re.match(p, ip) for p in patterns)


# 获取可靠本地 IP 的函数
def get_reliable_local_ip():
    priority = ['eth0', 'en0', 'enp0s3', 'wlan0']
    for iface in priority + netifaces.interfaces():
        if iface in priority or not re.match(r'^(lo|docker|veth)', iface):
            try:
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                print(addrs)
                if addrs:
                    ip = addrs[0]['addr']
                    if is_private_ip(ip):
                        return ip
            except Exception:
                continue
    return '未找到局域网 IP'
