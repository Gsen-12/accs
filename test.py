class FileUploadView(APIView):
    """文件上传视图（第一阶段：临时存储）"""
    # 权限控制：需要登录用户
    permission_classes = [IsAuthenticated]
    # 支持表单和文件上传解析
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        """处理文件上传请求"""
        try:
            # 从请求中获取上传的文件对象
            uploaded_file = request.FILES['file']

            # 文件大小验证（限制100MB）
            if uploaded_file.size > settings.MAX_FILE_SIZE:
                return Response({"error": "文件大小超过100MB限制"}, status=413)

            # 文件类型验证
            ext = uploaded_file.name.split('.')[-1].lower()
            if ext not in settings.ALLOWED_FILE_TYPES:
                return Response({"error": "不支持的文件类型"}, status=415)

            # 生成临时文件名（包含用户ID和随机字符串）
            temp_filename = f"temp_{uuid.uuid4().hex[:8]}_{request.user.id}.{ext}"
            # 保存到临时目录（使用Django默认存储系统）
            temp_path = default_storage.save(
                os.path.join(settings.TEMP_FILE_DIR, temp_filename),
                uploaded_file
            )

            # 在Redis中缓存文件元数据（有效期1小时）
            redis_conn = get_redis_connection("default")
            redis_key = f"file_temp_{request.user.id}"
            redis_conn.hmset(redis_key, {
                'temp_path': temp_path,          # 存储路径
                'original_name': uploaded_file.name,  # 原始文件名
                'expire': str(int(time.time()) + 3600)  # 过期时间戳
            })

            # 返回预览URL和确认提示
            return Response({
                "code": 200,
                "preview_url": f"/media/{temp_path}",
                "message": "文件已暂存，请确认提交"
            })

        except KeyError:
            # 处理未上传文件的异常
            return Response({"error": "未接收到文件"}, status=400)

class FileConfirmView(APIView):
    """文件确认视图（第二阶段：正式存储）"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """确认文件转存（主业务逻辑）"""
        temp_path = None  # 用于异常处理时清理
        user = request.user
        redis_conn = get_redis_connection("default")
        cache_key = f"file_temp_{user.id}"

        # 检查是否存在待确认的文件
        if not redis_conn.exists(cache_key):
            return Response({"code": 404, "message": "无待确认的文件"}, status=404)

        try:
            # 从Redis获取缓存数据
            cache_data = redis_conn.hgetall(cache_key)
            temp_path = cache_data[b'temp_path'].decode()
            original_name = cache_data[b'original_name'].decode()

            # 生成正式文件名（UUID + 原始文件名）
            final_filename = f"{uuid.uuid4().hex[:8]}_{original_name}"
            final_path = os.path.join(settings.FINAL_FILE_DIR, final_filename)

            # 执行文件转存操作（从临时到正式目录）
            with default_storage.open(temp_path) as src_file:
                saved_path = default_storage.save(final_path, src_file)

            # 创建数据库记录
            UserFile.objects.create(
                user=user,
                file=saved_path,
                is_temporary=False,
                original_name=original_name
            )

            # 清理缓存和临时文件
            redis_conn.delete(cache_key)
            default_storage.delete(temp_path)

            return Response({
                "code": 200,
                "file_url": f"/media/{saved_path}",
                "message": "文件已正式保存"
            })

        except Exception as e:
            # 异常处理：确保删除临时文件
            if temp_path and default_storage.exists(temp_path):
                default_storage.delete(temp_path)
            return Response({
                "code": 500,
                "error": f"文件确认失败：{str(e)}"
            }, status=500)

    def put(self, request):
        """示例：调用流式聊天API（演示用）"""
        # 注意：实际应使用配置管理API地址和密钥
        url = 'http://192.168.101.69/v1/chat-messages'
        api_key = 'app-uMcRADhYaBLnJCbByBIsjG8r'

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        data = {
            "inputs": {},
            "query": "你好",        # 用户输入内容
            "response_mode": "streaming",  # 流式响应模式
            "user": "user-123",     # 用户标识
            "conversation_id": ""   # 会话ID（用于连续对话）
        }

        # 发送POST请求到第三方API
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            try:
                # 尝试解析JSON响应
                print("响应内容:", response.json().get('answer'))
            except requests.exceptions.JSONDecodeError:
                # 处理非JSON格式的响应
                print("响应非JSON格式:", response.text)
                return Response({
                    "code": 200,
                    "response": response.text,
                })
        else:
            # 处理请求失败情况
            print(f"请求失败[状态码{response.status_code}]:", response.text)
            return Response(
                f"请求失败[状态码{response.status_code}]:",
                            )

    def get(self, request):
        """示例：调用聊天API的GET请求（演示用）"""
        # 注意：实际应使用配置管理API地址和密钥
        url = 'http://192.168.101.59/v1/chat-messages'
        api_key = 'app-cwrAJXuax5FvL8IbKSsKCjG6'
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        data = {
            "inputs": {},
            "query": "你好",        # 用户输入内容
            "response_mode": "streaming",  # 流式响应模式
            "user": "user-123",     # 用户标识
            "conversation_id": ""   # 会话ID（用于连续对话）
        }

        # 发送POST请求（虽然方法名为GET，但实际使用POST）
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            try:
                print("响应内容:", response.json().get('answer'))
            except requests.exceptions.JSONDecodeError:
                print("响应非JSON格式:", response.text)
                return Response({
                    "code": 200,
                    "response": response.text,
                })
        else:
            print(f"请求失败[状态码{response.status_code}]:", response.text)
            return Response(
                f"请求失败[状态码{response.status_code}]:",
            )



class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        """分阶段上传文件到临时目录"""
        try:
            uploaded_file = request.FILES['file']

            # 文件验证
            if uploaded_file.size > settings.MAX_FILE_SIZE:
                return Response({"error": "文件大小超过100MB限制"}, status=413)

            ext = uploaded_file.name.split('.')[-1].lower()
            if ext not in settings.ALLOWED_FILE_TYPES:
                return Response({"error": "不支持的文件类型"}, status=415)

            # 生成临时存储路径
            temp_filename = f"temp_{uuid.uuid4().hex[:8]}_{request.user.id}.{ext}"
            temp_path = default_storage.save(
                os.path.join(settings.TEMP_FILE_DIR, temp_filename),
                uploaded_file
            )

            # Redis缓存文件信息
            redis_conn = get_redis_connection("default")
            redis_key = f"file_temp_{request.user.id}"
            redis_conn.hmset(redis_key, {
                'temp_path': temp_path,
                'original_name': uploaded_file.name,
                'expire': str(int(time.time()) + 3600)  # 1小时有效期
            })

            return Response({
                "code": 200,
                "preview_url": f"/media/{temp_path}",
                "message": "文件已暂存，请确认提交"
            })

        except KeyError:
            return Response({"error": "未接收到文件"}, status=400)

class FileConfirmView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """将临时文件转为正式存储"""
        temp_path=None
        user = request.user
        redis_conn = get_redis_connection("default")
        cache_key = f"file_temp_{user.id}"

        if not redis_conn.exists(cache_key):
            return Response({"code": 404, "message": "无待确认的文件"}, status=404)

        cache_data = redis_conn.hgetall(cache_key)
        try:
            temp_path = cache_data[b'temp_path'].decode()
            original_name = cache_data[b'original_name'].decode()

            # 创建正式存储路径（网页1）
            final_filename = f"{uuid.uuid4().hex[:8]}_{original_name}"
            final_path = os.path.join(settings.FINAL_FILE_DIR, final_filename)

            # 移动文件（网页4）
            with default_storage.open(temp_path) as src_file:
                saved_path = default_storage.save(final_path, src_file)

            # 创建数据库记录
            UserFile.objects.create(
                user=user,
                file=saved_path,
                is_temporary=False,
                original_name=original_name
            )

            # 清理缓存和临时文件
            redis_conn.delete(cache_key)
            default_storage.delete(temp_path)

            return Response({
                "code": 200,
                "file_url": f"/media/{saved_path}",
                "message": "文件已正式保存"
            })

        except Exception as e:
            if temp_path and default_storage.exists(temp_path):
                default_storage.delete(temp_path)
            return Response({
                "code": 500,
                "error": f"文件确认失败：{str(e)}"
            }, status=500)

    def put(self, request):
        url = 'http://192.168.101.69/v1/chat-messages'
        api_key = 'app-uMcRADhYaBLnJCbByBIsjG8r'

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        data = {
            "inputs": {},
            "query": "你好",  # 用户输入内容
            "response_mode": "streaming",  # 流式响应模式
            "user": "user-123",  # 用户唯一标识
            "conversation_id": ""  # 会话ID（支持连续对话）
        }

        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            try:
                print("响应内容:", response.json().get('answer'))
            except requests.exceptions.JSONDecodeError:
                print("响应非JSON格式:", response.text)
                return Response({
                    "code": 200,
                    "response": response.text,
                })
        else:
            print(f"请求失败[状态码{response.status_code}]:", response.text)
            return Response(
                f"请求失败[状态码{response.status_code}]:",
                            )

    def get(self, request):
        url = 'http://192.168.101.59/v1/chat-messages'
        api_key = 'app-cwrAJXuax5FvL8IbKSsKCjG6'
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        data = {
            "inputs": {},
            "query": "你好",  # 用户输入内容
            "response_mode": "streaming",  # 流式响应模式
            "user": "user-123",  # 用户唯一标识
            "conversation_id": ""  # 会话ID（支持连续对话）
        }

        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            try:
                print("响应内容:", response.json().get('answer'))
            except requests.exceptions.JSONDecodeError:
                print("响应非JSON格式:", response.text)
                return Response({
                    "code": 200,
                    "response": response.text,
                })
        else:
            print(f"请求失败[状态码{response.status_code}]:", response.text)
            return Response(
                f"请求失败[状态码{response.status_code}]:",
            )








