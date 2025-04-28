# import requests
# import json
#
# url = 'http://192.168.101.69/v1/chat-messages'
# api_key = 'app-uMcRADhYaBLnJCbByBIsjG8r'
#
# headers = {
#     'Authorization': f'Bearer {api_key}',
#     'Content-Type': 'application/json'
# }
# data = {
#     "inputs": {},
#     "query": "你好",  # 用户输入内容
#     "response_mode": "streaming",  # 流式响应模式
#     "user": "user-123",  # 用户唯一标识
#     "conversation_id": "" # 会话ID（支持连续对话）
# }
#
# response = requests.post(url, headers=headers, json=data)
# if response.status_code == 200:
#     try:
#         print("响应内容:", response.json().get('answer'))
#     except requests.exceptions.JSONDecodeError:
#         print("响应非JSON格式:", response.text)
# else:
#     print(f"请求失败[状态码{response.status_code}]:", response.text)