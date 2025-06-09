from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from .models import BlacklistedToken


class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # 调用父类方法验证 Token
        validated = super().authenticate(request)
        if validated:
            user, token = validated
            # 检查 Token 是否在黑名单中
            if BlacklistedToken.objects.filter(token=str(token)).exists():
                raise InvalidToken("Token 已失效")
            return user, token
        return None

# class RedisBlacklistMixin(BlacklistMixin):
#     def verify(self, *args, **kwargs):
#         super().verify(*args, **kwargs)
#
#         jti = self.payload[api_settings.JTI_CLAKE]
#         if cache.get(f'blacklist_{jti}') is not None:
#             raise TokenError('Token is blacklisted')
#
#     def blacklist(self):
#         jti = self.payload[api_settings.JTI_CLAKE]
#         exp = self.payload['exp']
#
#         # 计算剩余存活时间（秒）
#         from datetime import datetime
#         now = datetime.utcnow().timestamp()
#         ttl = int(exp - now)
#
#         if ttl > 0:
#             cache.set(f'blacklist_{jti}', '1', timeout=ttl)
#
#
# class RedisRefreshToken(RedisBlacklistMixin, RefreshToken):
#     # token_type = 'refresh'
#     # lifetime = api_settings.REFRESH_TOKEN_LIFETIME
#     pass
#
#
#
# class RedisSlidingToken(RedisBlacklistMixin, RefreshToken):
#     token_type = 'sliding'
#     lifetime = api_settings.SLIDING_TOKEN_LIFETIME
