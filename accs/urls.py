from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
# from drf_yasg import openapi
# from drf_yasg.views import get_schema_view
from . import views
from .views import business_function
from .views.business_function import FileUploadView, TeaAnswerView, \
    SaveExeclView
from .views.custom_system import RegisterView, LoginView, LogoutView, CurrentUserView, UserModificationView, \
    PasswordChangeView, AdminRoleView, AdminRoleModificationView, TempAvatarUploadView, GenerateClassExcelView, \
    DepartmentMajorView, ParseFilledExcelView

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
    path('captcha/', include('captcha.urls')),
    path('avatar/upload/', TempAvatarUploadView.as_view(), name='avatar-upload'),
    path('upload-code/', FileUploadView.as_view(), name='file-upload'),
    # path('analyze/', AnalyzeCodeView.as_view(), name='analyze-code'),
    # path('history/', AnalysisHistoryView.as_view(), name='analysis-history'),
    # path('current-dify-ip/', business_views.current_dify_ip, name='current-dify-ip'),
    # path('set-dify-ip/', business_views.set_dify_ip, name='set-dify-ip'),
    # path('upload-code/', business_views.upload_code, name='upload-code'),
    # path('answer/', AddAnswerView.as_view(), name='answer'),
    path('tea/answer/', TeaAnswerView.as_view(), name='tea-answer'),
    path('save/execl/', SaveExeclView.as_view(), name='save-execl'),
    # path('save/analyze/', business_views.set_save_analyze, name='save-analyze'),
    # path('add/stuid/', AddStuidView.as_view(), name='add-stuid'),
    path('generate/excel/', GenerateClassExcelView.as_view(), name='generate-excel'),
    path('admin/department/major/', DepartmentMajorView.as_view(), name='admin-department-major'),
    path('parsefille/excel', ParseFilledExcelView.as_view(), name='parsefille-Excel'),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
