import uuid

from django.utils.deprecation import MiddlewareMixin


class CloseCsrfMiddleware(MiddlewareMixin):
    def process_request(self, request):
        print('csrf')
        request.csrf_processing_done = True  #csrf处理完毕

class UUIDTools(object):
    @staticmethod
    def uuid4_hex():
        hex_str = uuid.uuid4().hex  # 生成32位十六进制字符串
        return hex_str.translate(str.maketrans('abcdef', '012345'))[:8]