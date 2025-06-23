import warnings
import requests
import os
from accs.utils.response import check_response
from seafileapi import SeafileAPI


class SeafileOperations:
    def __init__(self, server_url: str, token: str):
        self.server_url = server_url.strip().strip('/')
        self.timeout = 30
        self.headers = {
            'Accept': 'application/json',
            'Content-type': 'application/json',
            'charset': 'utf-8',
            'indent': '4',
            'Authorization': token
        }

    def get_file_history_by_repo(self, repo_id: str, file_path: str) -> list:
        url = self.server_url + f'/api/v2.1/repos/{repo_id}/file/history/?path={file_path}'
        response = requests.get(
            url,
            headers=self.headers,
            json={
                'path': file_path,
                'repo_id': repo_id,
            }
        )
        if check_response(response):
            return response.json()

    def down_file_by_repo(self, repo_id: str, file_path: str) -> dict:
        url = self.server_url + f'/api2/repos/{repo_id}/file/?p={file_path}'
        response = requests.get(
            url,
            headers=self.headers,
            data={
                'path': file_path,
                'repo_id': repo_id,
            }
        )
        if check_response(response):
            return response.json()


class FileUpload:
    def __init__(self, seafile_api: SeafileAPI, seafile_ops: SeafileOperations):
        self.seafile_api = seafile_api
        self.seafile_ops = seafile_ops

    def upload_file(
            self,
            repo_id: str,
            seafile_path: str,
            local_path: str,
    ) -> str:
        """
        将本地文件上传到 Seafile 指定仓库和路径，返回最终路径。
        :param repo_id: Seafile 仓库 ID
        :param seafile_path: Seafile 存储路径（含文件名）
        :param local_path: 本地文件绝对路径
        """
        repo = self.seafile_api.get_repo(repo_id)
        parent_dir = os.path.dirname(seafile_path)
        filename = os.path.basename(seafile_path)
        existing = [info['name'] for info in repo.list_dir(parent_dir)]
        if filename in existing:
            repo.delete_file(seafile_path)
        repo.upload_file(parent_dir, local_path)
        return seafile_path
