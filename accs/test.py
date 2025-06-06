from seafileapi import SeafileAPI
import os
import logging
import requests
from django.http import JsonResponse
from CorrectionPlatformBackend.base import login_name, pwd, server_url

# 设置日志记录
logging.basicConfig(level=logging.DEBUG)

# 初始化Seafile客户端
seafile_api = SeafileAPI(login_name, pwd, server_url)
seafile_api.auth()

repo_id = 'ad406967-dd0d-4d5c-949c-cdd62d21b9fe'
api_url = 'https://seafile.accs.rabbitmind.net/library/ad406967-dd0d-4d5c-949c-cdd62d21b9fe/accs_private/ava/25012490(1).png'

# # 1. 验证仓库是否存在
# repo = seafile_api.get_repo(repo_id)
response = requests.get(api_url)
if response.status_code == 200:
    print(1111111111111)
elif response.status_code == 404:
    print(2222222222222)
else:
    print(3333333333333)


# # 2. 检查目标路径是否存在
# target_path = '/ava/2501249(1).png'  # 需要下载的文件路径
# print('target_path11111:', repo.get_file(target_path))
# if repo.get_file(target_path) is None:
#     print(00000000000000000000000000000000000000000000)
# print('target_path:', os.path.exists(target_path))
# # 3. 设置有效的本地保存路径
# # Windows路径示例
# save_path = f'C:/Users/33465/PycharmProjects/ACCS/accs'
# print('save_path:', os.path.exists(save_path))
# local_save_path = f'{save_path}/downloaded_file.jpg'
# print('local_save_path:', os.path.exists(local_save_path))
# # 创建目录（如果不存在）
# # os.makedirs(os.path.dirname(local_save_path), exist_ok=True)
# # 4. 执行下载
# repo.download_file(target_path, local_save_path)
