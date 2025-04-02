import time
import datetime

from django.db.models import Q
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import MyTokenObtainPairSerializer
from rest_framework.permissions import AllowAny
from accs.models import Roles, BlacklistedToken
from accs.serializers import UserSerializer
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from .utils import token

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
    @staticmethod
    def post(request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)

        if user is not None:
            token = MyTokenObtainPairSerializer.get_token(user)
            # token.set_exp(lifetime=datetime.timedelta())
            return Response({'message': 'Login successful', 'token': str(token)}, status=status.HTTP_200_OK)
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


@csrf_exempt
class LogoutView(APIView):
    @csrf_protect
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response(
                    {"error": "缺少 refresh_token"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            # 将 refresh_token 加入黑名单
            token = RefreshToken(refresh_token)
            BlacklistedToken.add(token)

            return Response({"message": "退出成功"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "无效的 Token"},
                status=status.HTTP_400_BAD_REQUEST
            )
        # token = MyTokenObtainPairSerializer.get_token(user)
        # token.set_exp(lifetime=datetime.timedelta())


class MyObtainTokenPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = MyTokenObtainPairSerializer


# MyCustomBackend
class MyCustomBackend(TokenObtainPairView):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None
