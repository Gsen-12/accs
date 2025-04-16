from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin
from .models import Roles
from .views import User
from django.contrib.admin import site
from django.contrib.admin.models import LogEntry

class RoleAdmin(admin.ModelAdmin):
    filter_horizontal = ('permissions',)  # 权限多选界面优化
    list_display = ('role_name', 'get_permissions_count')

    def get_permissions_count(self, obj):
        return obj.permissions.count()

    get_permissions_count.short_description = "权限数量"


admin.site.register(Roles, RoleAdmin)


# 扩展默认用户Admin
# class UserInfoInline(admin.StackedInline):
#     model = UserInfo
#     can_delete = False
#     verbose_name_plural = '用户信息'
#
#
# class CustomUserAdmin(UserAdmin):
#     inlines = (UserInfoInline,)
#     list_display = ('username', 'email', 'get_role', 'is_staff')
#
#     def get_role(self, obj):
#         return obj.userinfo.role_id
#
#     get_role.short_description = '角色'


# admin.site.unregister(User)  # 取消默认注册
# admin.site.register(User)

class LogEntryAdmin(admin.ModelAdmin):
    list_display = ['action_time', 'user', 'content_type', 'object_repr', 'change_message']

site.register(LogEntry, LogEntryAdmin)  # 在管理后台查看日志