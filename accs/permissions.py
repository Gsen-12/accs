from rest_framework import permissions

class IsOwnerPermission(permissions.BasePermission):
    """验证用户是否为数据所有者"""
    def has_object_permission(self, request, view, obj):
        return obj.id == request.user.id