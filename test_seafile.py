# import os
#
# from seafileapi import SeafileAPI
#
# server_url = "https://seafile.accs.rabbitmind.net/"
# login_name = "accs@admin.com"
# pwd = "accs@Aa"
# repo_id = "ad406967-dd0d-4d5c-949c-cdd62d21b9fe"
#
# seafile_api = SeafileAPI(login_name,pwd,server_url)
# seafile_api.auth()
#
# seafile_path = "/ava/25012490_tmp_ava_upload.png"
# temp_filename = '25012490_tmp_ava_upload.png'
# final_filename = f'25012490_ava_upload.png'
# repo = seafile_api.get_repo(repo_id)
#
# print(repo.get_file("/ava/25012490_tmp_ava_upload.png"))
# file_path = os.path.join("/ava",final_filename)
# temp_path = os.path.join("/ava", temp_filename)
# repo.rename_file(seafile_path,final_filename)
# # 临时文件的判断
# if "25012490_tmp_ava_upload.png" in [x["name"] for x in repo.list_dir("/ava")]:
#     repo.delete_file("/ava/25012490_tmp_ava_upload.png")
# else:
#     # repo.upload_file(...)
#     pass
#
#
# print(repo.rename_file("/ava/25012490_tmp_ava_upload.png", "25012490_ava_upload.png"))
#
# if filename in [x["name"] for x in repo.list_dir("/ava")]:
#     repo.delete_file(seafile_path)