from rest_framework import permissions
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework.views import APIView

from accs.models import UserInfo


class IsSuperAdmin(permissions.BasePermission):
    """验证超级管理员权限"""

    def has_permission(self, request, view):
        return (
                request.user.is_authenticated and
                hasattr(request.user, 'userinfo') and
                request.user.userinfo.role_id == 3
        )


# class AdminRoleView(APIView):
#     permission_classes = [IsAuthenticated, IsSuperAdmin]
#
#
# class CreateGroupView(APIView):
#     permission_classes = [IsSuperAdmin]
#

class IsTeacher(permissions.BasePermission):
    """验证超级管理员权限"""

    def has_permission(self, request, view):
        if request.user.is_authenticated:
            user_info = UserInfo.objects.get(userId=request.user.id)
            print(user_info.role_id)
            return user_info.role_id == 2
        else:
            raise


# class AssignGroupView(APIView):
#     permission_classes = [IsTeacher]
#
#
# class InvitationCodeview(APIView):
#     permission_classes = [IsTeacher]
