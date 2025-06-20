from accs.utils.exceptions import ClientHttpError


def check_response(response):
    if response.status_code == 200:
        return True
    else:
        if response.status_code == 500:
            message = '服务错误，检查参数！'
        elif response.status_code == 403:
            message = '权限错误或邮件发送错误！'
        elif response.status_code == 404:
            message = '提供的参数（如token、仓库id等）可能不存在，请检查！'
        elif response.status_code == 400:
            message = 'token 或者仓库 id 参数错误！'
        else:
            message = '未知错误，自己调试！'
        raise ClientHttpError(response.status_code, message)