from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import path, include
from accs.views import MyObtainTokenPairView
from rest_framework.routers import DefaultRouter
from django.conf import settings
from accs.views import RegisterView, LoginView
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

router = DefaultRouter()
# router.register(r'XXXX', XXXXX)


urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/', MyObtainTokenPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
