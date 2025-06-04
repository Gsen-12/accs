from seafileapi import SeafileAPI
import os
import logging

from CorrectionPlatformBackend.base import login_name, pwd, server_url

# 设置日志记录
logging.basicConfig(level=logging.DEBUG)

# 初始化Seafile客户端
seafile_api = SeafileAPI(login_name, pwd, server_url)
seafile_api.auth()

repo_id = 'ad406967-dd0d-4d5c-949c-cdd62d21b9fe'


# 1. 验证仓库是否存在
repo = seafile_api.get_repo(repo_id)

# 2. 检查目标路径是否存在
target_path = '/ava'  # 需要下载的文件路径
print(f"错误：路径 '{target_path}' 不存在或不是文件")
print("仓库根目录内容:")
# 3. 设置有效的本地保存路径
# Windows路径示例
local_save_path = 'C:\\temp\\downloaded_file.jpg'
# 创建目录（如果不存在）
os.makedirs(os.path.dirname(local_save_path), exist_ok=True)
# 4. 执行下载
repo.download_file(target_path, local_save_path)
