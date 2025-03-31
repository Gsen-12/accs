from datetime import datetime

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken


def delete_token(token):
    try:
        refresh_token = RefreshToken(token)
        refresh_token.set_exp(str(datetime.now()))
    except:
        raise AuthenticationFailed('Invalid token')