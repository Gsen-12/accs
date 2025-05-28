from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
# from drf_yasg import openapi
# from drf_yasg.views import get_schema_view
from accs.views import RegisterView, LoginView, LogoutView, CurrentUserView, AdminRoleView, AdminRoleModificationView, \
    UserModificationView, PasswordChangeView, TempAvatarUploadView, CreateGroupView, InvitationCodeview, \
    AssignGroupView, JoinGroupView, JoinConfirmView, AnalyzeCodeView, AnalysisHistoryView, TeaAnswerView
from django.conf import settings
from django.conf.urls.static import static
from accs.views import FileUploadView
from .views import (
    AnalyzeCodeView,
    AnalysisHistoryView,
    AnswerView

)
from . import views
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
    # path('swagger/', schema_view.with_ui('swagger', cache_timeout=0)),
    path('captcha/', include('captcha.urls')),
    path('avatar/upload/', TempAvatarUploadView.as_view(), name='avatar-upload'),
    path('upload-code/', FileUploadView.as_view(), name='file-upload'),
    # path('call/dify/',DifyView.as_view(),name='call-dify'),
    path('group/create/', CreateGroupView.as_view(),name='create-group'),
    path('group/invite_code/', InvitationCodeview.as_view(),name='invite-code'),
    path('assign/', AssignGroupView.as_view(),name='assign-group'),
    path('group/join/', JoinGroupView.as_view(),name='join-group'),
    path('confirm/join/', JoinConfirmView.as_view(),name='confirm-join'),
    path('analyze/', AnalyzeCodeView.as_view(), name='analyze-code'),
    path('history/', AnalysisHistoryView.as_view(), name='analysis-history'),
    path('current-dify-ip/', views.current_dify_ip, name='current-dify-ip'),
    path('set-dify-ip/', views.set_dify_ip, name='set-dify-ip'),
    path('upload-code/', views.upload_code, name='upload-code'),
    path('answer/', AnswerView.as_view(), name='answer'),
    path('tea/answer/', TeaAnswerView.as_view(), name='tea-answer'),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
