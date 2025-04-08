from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from accs.views import RegisterView, LoginView, LogoutView, UserDetailView, CurrentUserView, AdminUserListView, \
    FileUploadView

router = DefaultRouter()
# router.register(r'XXXX', XXXXX)


urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('userinfo/', CurrentUserView.as_view(), name='current-user'),
    path('user/', UserDetailView.as_view(), name='user-detail'),
    path('users/', AdminUserListView.as_view(), name='admin-users'),
    path('user_upload/', FileUploadView.as_view(), name='user_upload'),
]
