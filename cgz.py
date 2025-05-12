from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated  # 权限控制
from rest_framework.parsers import MultiPartParser, FormParser  # 文件上传解析器
from django.core.files.storage import default_storage  # 文件存储系统
from django.conf import settings  # 配置文件
import uuid
import time
import os
from redis import RedisError


class AvatarChangeView(APIView):
    """
    用户头像上传和临时存储API视图

    功能流程：
    1. 接收含头像文件的POST请求
    2. 验证文件类型和内容安全性
    3. 生成临时存储路径并保存文件
    4. 在Redis记录临时文件元数据
    5. 返回临时文件预览地址
    """

    # 权限控制：必须登录用户才能访问
    permission_classes = [IsAuthenticated]

    # 解析器：支持multipart/form-data格式（文件上传必需）
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        """处理头像上传请求"""
        user = request.user  # 从请求中获取已认证用户
        redis_conn = get_redis_connection("default")  # 获取Redis连接
        temp_path = None  # 初始化临时文件路径
        response_data = {"code": 200, "message": "信息更新成功"}  # 默认响应

        try:
            # 检查请求中是否包含头像文件
            if 'avatar' in request.FILES:
                uploaded_file = request.FILES['avatar']

                # 验证文件内容（格式、尺寸、安全性等）
                try:
                    validate_image_content(uploaded_file)  # 自定义验证函数
                except ValidationError as e:
                    return Response({
                        "code": 415,
                        "error": f"文件验证失败: {e.detail[0]}"
                    }, status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

                # 生成唯一文件名（防止冲突）
                ext = uploaded_file.name.split('.')[-1]  # 获取文件扩展名
                temp_filename = f"temp_{uuid.uuid4().hex[:6]}_{user.id}.{ext}"  # 添加随机UUID前缀

                # 存储到临时目录（示例路径：tmp/avatars/temp_89ab3c_123.jpg）
                temp_path = default_storage.save(
                    os.path.join(settings.TEMP_AVATAR_DIR, temp_filename),
                    uploaded_file  # 文件内容
                )

                # Redis存储元数据（哈希结构）
                redis_key = f"avatar_temp_{user.id}"
                final_path = f"{settings.FINAL_AVATAR_DIR}/{user.id}_{int(time.time())}.{ext}"
                redis_data = {
                    'temp_path': temp_path,  # 临时存储路径
                    'final_path': final_path,  # 最终存储路径（带时间戳）
                    'expire': str(int(time.time()) + 3600)  # 1小时后过期
                }

                # 使用hset替代hmset（hmset已弃用）
                redis_conn.hset(redis_key, mapping=redis_data)
                redis_conn.expire(redis_key, 3600)  # 设置键过期时间

                # 构造响应数据（包含预览地址）
                response_data.update({
                    "preview_url": f"{settings.MEDIA_URL}{temp_path}"  # 需配置MEDIA_URL
                })

                return Response(response_data)

        except RedisError as e:
            # Redis异常处理
            logger.error(f"Redis操作失败: {str(e)}")
            return Response({"code": 500, "error": "缓存服务异常"}, status=500)

        except Exception as e:
            # 通用异常处理：删除临时文件
            if temp_path and default_storage.exists(temp_path):
                default_storage.delete(temp_path)

            # 记录日志并返回错误
            logger.error(f"头像上传失败: {str(e)}", exc_info=True)
            return Response({
                "code": 500,
                "error": f"服务器错误: {str(e)}"
            }, status=500)

# user = request.user  # 直接获取当前登录用户
        # user_info = UserInfo.objects.get(userId = user.id)
        # redis_conn = get_redis_connection("default")
        # user_serializer = UserSerializer
        #
        # seafile_api = None
        # repo = None
        # final_seafile_path = None  # 用于回滚的最终路径
        # # response_data = {"code": 200, "message": "信息更新成功"}
        # # return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        #
        # print(request.data)
        # print(user)
        # print(user_info)
        # try:
        #     # if user_info.avatar == request.data['avatar'] \
        #     #     and user_info.realName == request.data['realName'] \
        #     #     and user_info.gender == request.data['gender']:
        #     #     return Response({
        #     #         "code": 406,
        #     #         "data": {
        #     #             "username": user.username,
        #     #             "realName": user_info.realName,
        #     #             "avatar": user_info.avatar,
        #     #             "gender": user_info.gender
        #     #         },
        #     #         "message": "没有任何修改请检查!"
        #     #     })
        #
        #     if 'avatar' in request.FILES:
        #         seafile_api = SeafileAPI(login_name, pwd, server_url)
        #         avatar_file = request.FILES['avatar']
        #         validate_image_content(avatar_file)
        #         ext = request.FILES.get('avatar').name.split('.')[-1]
        #         final_filename = f"{user.id}_ava_upload.{ext}"
        #         seafile_path = f"/ava/{user.id}_ava_upload.{ext}"  # Seafile中的存储路径
        #         seafile_api = None
        #         repo = None
        #         seafile_file_uploaded = False
        #         cache_key = f"{user.id}_ava_upload.{ext}"
        #         if not redis_conn.exists(cache_key):
        #             return Response({"code": 404, "message": "无待确认的头像"}, status=404)
        #         try:
        #             seafile_api = SeafileAPI(login_name, pwd, server_url)
        #             seafile_api.auth()  # 认证
        #             repo = seafile_api.get_repo(repo_id)
        #             file_path = os.path.join("/ava", final_filename)
        #             # TODO: temp_seafile_path获取redis中键名为  file_temp_{user id}
        #             repo.rename_file("/ava", file_path)
        #             seafile_file_uploaded = True
        #             # avatar_url = f"{server_url.rstrip('/')}/avatar/{repo_id}{seafile_path}"
        #             # user_info = UserInfo.objects.get(userId=user.id)
        #             # user_info.avatar = avatar_url
        #             # user_info.save()
        #             # 初始化 Seafile 客户端
        #             repo = seafile_api.get_repo(repo_id)
        #
        #             repo.move_file(seafile_path, final_seafile_path)
        #
        #             # 更新数据库记录
        #             user_info = UserInfo.objects.get(userId=user.id)
        #             # old_avatar = user_info.avatar
        #             user_info.avatar = f"{server_url}/files/{repo_id}{final_seafile_path}"
        #             user_info.save()
        #
        #             redis_conn.delete(cache_key)
        #
        #             # redis_conn.delete(cache_key)
        #             # default_storage.delete(temp_path)
        #             return Response({
        #                 "code": 200,
        #                 "avatar_url": user_info.avatar,
        #                 "message": "头像更新成功"
        #             })
        #         except Exception as e:
        #             if seafile_file_uploaded and repo is not None:
        #                 try:
        #                     repo.delete_file(seafile_path)  # 确保有删除文件的方法
        #                 except Exception as delete_error:
        #                     pass  # 可记录日志
        #
        #             return Response({
        #                 "code": 500,
        #                 "error": f"上传失败：{str(e)}"
        #             }, status=500)

class AvatarConfirmView(APIView):
    # 权限控制：仅允许已登录用户访问
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """处理头像确认的POST请求"""
        # 获取当前用户对象
        user = request.user

        # 连接Redis数据库（使用default配置）
        redis_conn = get_redis_connection("default")
        # 构建Redis缓存键名：avatar_temp_用户ID
        cache_key = f"avatar_temp_{user.id}"

        # 初始化后续可能需要的变量（用于异常回滚）
        seafile_api = None  # Seafile客户端实例
        repo = None  # Seafile仓库对象
        final_seafile_path = None  # 最终存储路径（用于回滚操作）

        try:
            # --------------------- 缓存验证阶段 ---------------------
            # 检查Redis中是否存在对应的缓存记录
            if not redis_conn.exists(cache_key):
                return Response({"code": 404, "message": "无待确认的头像"}, status=404)

            # 从Redis哈希表中获取缓存数据
            cache_data = redis_conn.hgetall(cache_key)

            # 解码字节数据为字符串（注意：此处路径可能需要优化为变量）
            temp_seafile_path = cache_data[r'/library/ad45.../tmp/ava'].decode()  # 临时存储路径
            final_seafile_path = cache_data[r'/library/ad45.../ava'].decode()  # 最终存储路径

            # --------------------- 文件操作阶段 ---------------------
            # 初始化Seafile客户端（注意：需要确保login_name/pwd/server_url已定义）
            seafile_api = SeafileAPI(login_name, pwd, server_url)
            seafile_api.auth()  # 进行身份认证

            # 获取指定的仓库对象（注意：需要确保repo_id已定义）
            repo = seafile_api.get_repo(repo_id)

            # 执行文件移动操作（从临时路径移动到正式路径）
            repo.move_file(temp_seafile_path, final_seafile_path)

            # --------------------- 数据库更新阶段 ---------------------
            # 获取用户信息对象并更新头像URL
            user_info = UserInfo.objects.get(userId=user.id)
            user_info.avatar = f"{server_url}/files/{repo_id}{final_seafile_path}"
            user_info.save()

            # 删除Redis缓存（确认操作完成）
            redis_conn.delete(cache_key)

            # --------------------- 响应阶段 ---------------------
            # 返回成功的响应
            return Response({
                "code": 200,
                "avatar_url": user_info.avatar,
                "message": "头像更新成功"
            })

        except Exception as e:
            # --------------------- 异常处理阶段 ---------------------
            # 回滚操作：如果文件已移动但后续失败，删除已移动的文件
            if final_seafile_path and repo:
                try:
                    repo.delete_file(final_seafile_path)
                except Exception as delete_error:
                    # 实际项目中建议记录日志（此处静默处理）
                    pass

                    # 返回错误响应
            return Response({
                "code": 500,
                "error": f"确认失败：{str(e)}"
            }, status=500)

        finally:
            # --------------------- 资源清理阶段 ---------------------
            # 确保关闭Seafile客户端连接
            if seafile_api is not None and hasattr(seafile_api, 'close'):
                try:
                    seafile_api.close()
                except Exception as close_error:
                    # 实际项目中建议记录日志（此处静默处理）
                    pass