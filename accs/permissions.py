from rest_framework import permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView


class IsSuperAdmin(permissions.BasePermission):
    """验证超级管理员权限"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_superuser

# 在视图中使用
class AdminRoleView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdmin]  # 替换原有权限.id