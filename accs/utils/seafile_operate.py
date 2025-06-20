import warnings
import requests

from accs.utils.response import check_response


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

    def get_share_file_by_repo(self, repo_id: str, file_path: str) -> list:
        url = self.server_url + f'/api/v2.1/share-links/?repo_id={repo_id}&path={file_path}'
        response = requests.get(url, headers=self.headers)
        if check_response(response):
            return response.json()

    def delete_share_file_by_repo(self, repo_id: str, file_path: str) -> list:
        share_links = self.get_share_file_by_repo(repo_id=repo_id, file_path=file_path)
        result_list = []
        for share_link in share_links:
            # todo：某个文件删除失败
            url = self.server_url + f"/api/v2.1/share-links/{share_link['token']}"
            response = requests.delete(url, headers=self.headers)
            if check_response(response):
                result_list.append(response.json()['success'])
        if not result_list:
            warnings.warn("不存在该文件，结束删除操作")

        return result_list

    def post_share_ava_by_repo(self, repo_id: str, file_path: str) -> list:

        url = self.server_url + f'/api/v2.1/share-links/'
        response = requests.post(
            url,
            headers=self.headers,
            json={
                'path': file_path,
                'repo_id': repo_id,
                'permissions': {
                    'can_edit': False,
                    'can_download': True
                }
            }
        )
        if check_response(response):
            return response.json()

    def post_share_file_by_repo(self, repo_id: str, file_path: str, password: str) -> list:

        url = self.server_url + f'/api/v2.1/share-links/'
        response = requests.post(
            url,
            headers=self.headers,
            json={
                'path': file_path,
                'repo_id': repo_id,
                'password': password,
                'permissions': {
                    'can_edit': False,
                    'can_download': True
                }
            }
        )
        if check_response(response):
            return response.json()
