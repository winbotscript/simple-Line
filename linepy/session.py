# -*- coding: utf-8 -*-
from thrift.transport import THttpClient
from thrift.protocol import TCompactProtocol
#from liff import LiffService
from akad import AuthService
class Session:

    def __init__(self, url, headers, path=''):
        self.host = url + path
        self.headers = headers

    def Auth(self, isopen=True):
        self.transport = THttpClient.THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)
        self.protocol = TCompactProtocol.TCompactProtocolAccelerated(self.transport)
        self._auth  = AuthService.Client(self.protocol)
        if isopen:
            self.transport.open()
        return self._auth

    """
    def Liff(self, isopen=True):
        self.transport = THttpClient.THttpClient(self.host)
        self.transport.setCustomHeaders(self.headers)
        self.protocol = TCompactProtocol.TCompactProtocol(self.transport)
        self._liff  = LiffService.Client(self.protocol)
        if isopen:
            self.transport.open()
        return self._liff
    """