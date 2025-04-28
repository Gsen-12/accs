import requests
from django.conf import settings


class SeafileClient:
    @staticmethod
    def get_upload_link(repo_id, parent_dir='/'):
        """获取Seafile上传链接"""
        url = f"{settings.SEAFILE_CONFIG['API_BASE']}{settings.SEAFILE_CONFIG['UPLOAD_URL'].format(repo_id=repo_id)}"
        headers = {'Authorization': f'Token {settings.SEAFILE_CONFIG["API_TOKEN"]}'}
        params = {'parent_dir': parent_dir}

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()['upload_link']
        raise Exception(f"获取上传链接失败: {response.text}")

    @staticmethod
    def upload_file(upload_url, file_obj, parent_dir='/', filename=None):
        """执行文件上传"""
        filename = filename or file_obj.name
        files = {'file': (filename, file_obj, file_obj.content_type)}
        data = {'parent_dir': parent_dir, 'replace': 1}

        response = requests.post(upload_url, files=files, data=data)
        if response.status_code == 200:
            return response.json()['name']
        raise Exception(f"文件上传失败: {response.text}")