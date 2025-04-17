from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
# from drf_yasg import openapi
# from drf_yasg.views import get_schema_view
from accs.views import RegisterView, LoginView, LogoutView, CurrentUserView, AdminRoleView, AdminRoleModificationView, \
    UserModificationView, PasswordChangeView, AvatarUploadView, AvatarRollbackView
from django.conf import settings
from django.conf.urls.static import static
from accs.views import FileUploadView
# from accs.views import AdminUserListView

router = DefaultRouter()
# router.register(r'XXXX', XXXXX)

# schema_view = get_schema_view(
#     openapi.Info(
#         title="API文档",
#         default_version='v1',
#     ),
#     public=True,
# )
urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('user/info/', CurrentUserView.as_view(), name='current-user'),
    path('user/update/', UserModificationView.as_view(), name='user-modification'),
    path('user/password/change/', PasswordChangeView.as_view()),
    path('admin/roles/', AdminRoleView.as_view(), name='admin-roles'),
    path('admin/roles/modification/', AdminRoleModificationView.as_view(), name='admin-roles-modification'),
    path('admin/roles/<int:role_id>/', AdminRoleView.as_view(), name='admin-role-detail'),
    # path('user/', UserDetailView.as_view(), name='user-detail'),
    # path('users/', AdminUserListView.as_view(), name='admin-users'),
    path('user_upload/', FileUploadView.as_view(), name='user_upload'),
    # path('swagger/', schema_view.with_ui('swagger', cache_timeout=0)),
    path('captcha/', include('captcha.urls')),
    path('avatar/upload/', AvatarUploadView.as_view(), name='avatar-upload'),
    path('avatar/rollback/', AvatarRollbackView.as_view(), name='avatar-rollback'),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
