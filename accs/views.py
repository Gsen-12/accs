import datetime

from django.contrib.auth import authenticate, get_user_model
from django.db.models import Q
from django.http import JsonResponse
from django_redis import get_redis_connection
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from accs.models import Roles
from accs.serializers import UserSerializer

User = get_user_model()


def csrf_failure(request, reason=""):
    return JsonResponse({"error": "CSRF验证失败"}, status=403)


# Create your views here.


class RegisterView(APIView):
    @staticmethod
    def post(request):
        user_serializer = UserSerializer(data=request.data)
        if user_serializer.is_valid():
            if request.data.get('role_id') is not None:
                user_serializer.save()
                Roles.objects.create(role_id=request.data.get('role_id'), user_id=user_serializer.data.get('id'))
                return Response(user_serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "未获取到role_id"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    @staticmethod
    def post(request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if not user:
            return Response({"error": "无效的凭证"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # 生成双令牌
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            # 存储到Redis
            redis_conn = get_redis_connection("default")
            user_id = user.id

            # 转换时间单位为整数秒
            access_expire = int(datetime.timedelta(minutes=30).total_seconds())
            refresh_expire = int(datetime.timedelta(days=7).total_seconds())

            # 使用正确参数顺序：name, time, value
            redis_conn.setex(
                name=f"access_{user_id}",
                time=access_expire,
                value=access_token.encode('utf-8')  # 转换为bytes
            )
            redis_conn.setex(
                name=f"refresh_{user_id}",
                time=refresh_expire,
                value=refresh_token.encode('utf-8')
            )

            return Response({
                "access": access_token,
                "refresh": refresh_token,
                "user_id": user_id,
                "expires_in": access_expire
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"令牌生成失败: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    def post(self, request):
        try:
            # refresh_token = request.data.get('refresh')
            # access_token = request.auth
            #

            if not request.auth:
                return Response({"error": "未登录"}, status=400)
            # # 加入黑名单
            # add_to_blacklist(access_token)
            # add_to_blacklist(RefreshToken(refresh_token))

            print(type(request))

            # 清理Redis存储
            user_id = request.user.id
            redis_conn = get_redis_connection("default")
            redis_conn.delete(f"access_{user_id}", f"refresh_{user_id}")

            return Response({"message": "成功登出"}, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)


# MyCustomBackend
class MyCustomBackend(TokenObtainPairView):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None
