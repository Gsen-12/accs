class ClientHttpError(Exception):
    def __init__(self, code, message):
        super(ClientHttpError, self).__init__()
        self.code = code
        self.message = message

    def __str__(self):
        return 'ClientHttpError[%s: %s]' % (self.code, self.message)
