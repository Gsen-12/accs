import time
from datetime import datetime

from django_redis import get_redis_connection
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken


# 删除token
def delete_token(token):
    try:
        refresh_token = RefreshToken(token)
        refresh_token.set_exp(str(datetime.now()))
    except:
        raise AuthenticationFailed('Invalid token')


def add_to_blacklist(token):
    """将令牌加入黑名单"""
    redis_conn = get_redis_connection("token")
    try:
        # 计算剩余有效时间
        payload = token.payload
        expires_at = payload['exp'] - int(time.time())
        if expires_at > 0:
            redis_conn.setex(
                name=f"blacklist_{token}",
                time=expires_at,
                value=1  # 存储标志值
            )
    except Exception as e:
        raise ValueError(f"黑名单操作失败: {str(e)}")


def is_blacklisted(token):
    """检查令牌是否在黑名单"""
    redis_conn = get_redis_connection("token")
    return redis_conn.exists(f"blacklist_{token}") > 0
