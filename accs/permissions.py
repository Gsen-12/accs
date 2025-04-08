from rest_framework import permissions

from accs.models import Roles


class IsAdminPermission(permissions.BasePermission):
    """检查是否是管理员"""
    def has_permission(self, request, view):
        try:
            role = Roles.objects.get(user_id=request.user.id)
            return role.role_id == 2  # 假设2是管理员角色ID
        except Roles.DoesNotExist:
            return False

class IsAdminOrOwnerPermission(permissions.BasePermission):
    """组合权限：管理员或数据所有者"""
    def has_object_permission(self, request, view, obj):
        if IsAdminPermission().has_permission(request, view):
            return True
        return obj.id == request.user.id