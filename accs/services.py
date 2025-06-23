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
        latest = IPConfig.objects.order_by('-updated_at').first()
        ip = latest.ip_address if latest else 'localhost'
        print(f"[get_current_host_ip] 从数据库取到的 IP 是：{ip}")
        return ip

    @classmethod
    def get_api_url(cls):
        host_ip = cls.get_current_host_ip()
        url = f"http://{host_ip}/v1/chat-messages"
        print(f"[get_api_url]：{url}")
        return url

    @classmethod
    def analyze_code(cls, code_content):
        headers = {
            "Authorization": f"Bearer {settings.DIFY_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "inputs": {},
            "query": code_content,
            "response_mode": "blocking",
            "conversation_id": "",
            "user": "django_backend",
        }

        url = cls.get_api_url()
        print(f"Dify API: {url}")

        response = None
        try:
            response = requests.post(url, headers=headers, json=payload)
            resp_json = response.json()
            print('resp_json', resp_json)

            # 处理 Dify 层面错误
            if isinstance(resp_json, dict) and resp_json.get('status') not in (None, 200):
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(now, "Dify 返回错误状态", resp_json.get('status'))
                return {
                    'error_message': resp_json.get('message', 'Unknown error'),
                    'status': resp_json.get('status'),
                }

            response.raise_for_status()
            return cls._handle_response(resp_json)

        except requests.HTTPError as http_err:
            # HTTP 错误，优先返回 Dify 自己的 message/status
            err_data = {}
            try:
                err_data = response.json()
            except Exception:
                pass
            return {
                'error_message': err_data.get('message', str(http_err)),
                'status': err_data.get('status', response.status_code if response else 500),
            }
        except Exception as e:
            # 网络或其他异常
            print(f"API请求失败: {e}")
            return {
                'error_message': str(e),
                'status': getattr(response, 'status_code', 500),
            }

    @classmethod
    def _handle_response(cls, response_data):
        try:
            raw_answer = response_data.get('answer', '')
            # 去掉 ```json``` 等代码块标记
            raw_answer = re.sub(r"```json?|```", '', raw_answer)

            # 匹配 JSON 对象字符串
            json_texts = re.findall(r"\{[\s\S]*?}", raw_answer)
            combined = {}
            for text in json_texts:
                try:
                    part = json.loads(text)
                    combined.update(part)
                except json.JSONDecodeError:
                    continue

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
