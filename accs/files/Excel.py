# import pandas as pd
# from seafileapi import SeafileAPI
#
# from CorrectionPlatformBackend.settings import login_name, pwd, server_url, repo_id
#
# seafile_api = SeafileAPI(login_name, pwd, server_url)
# seafile_api.auth()  # 认证
#
# # 获取仓库对象
# repo = seafile_api.get_repo(repo_id)
# # 1. 创建数据
# data = {
#     '姓名': ['张三', '李四', '王五'],
#     '年龄': [25, 30, 28],
#     '城市': ['北京', '上海', '广州']
# }
# df = pd.DataFrame(data)
#
# # 2. 保存到Excel
# df.to_excel('人员信息.xlsx', index=False, sheet_name='员工表')
#
# # 读取Excel文件
# excel_path = "人员信息.xlsx"  # 替换成你的文件路径
# df = pd.read_excel(excel_path, sheet_name='员工表')
# repo.upload_file("/file", excel_path)
#
# # 方法1：直接打印DataFrame（带格式对齐）
# print("\n----- 完整数据打印 -----")
# print(df)
#
# # 方法2：逐行打印数据（适合命令行显示）
# print("\n----- 逐行打印 -----")
# for index, row in df.iterrows():
#     print(f"第{index + 1}行：", end=" ")
#     print(row.to_dict())  # 转换为字典格式更易读
