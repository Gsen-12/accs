from rest_framework import permissions
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework.views import APIView

class IsSuperAdmin(permissions.BasePermission):
    """验证超级管理员权限"""

    def has_permission(self, request, view):
        return (
                request.user.is_authenticated and
                hasattr(request.user, 'userinfo') and
                request.user.userinfo.role_id == 3
        )

class AdminRoleView(APIView):
    permissions_classes = [IsAuthenticated, IsSuperAdmin]

class CreateGroupView(APIView):
    permissions_classes = [IsSuperAdmin]

class IsTeacher(permissions.BasePermission):
    """验证超级管理员权限"""

    def has_permission(self, request, view):
        return (
                request.user.is_authenticated and
                hasattr(request.user, 'userinfo') and
                request.user.userinfo.role_id == 2
        )

class AssignGroupView(APIView):
    permissions_classes = [IsTeacher]

class InvitationCodeview(APIView):
    permissions_classes = [IsTeacher]