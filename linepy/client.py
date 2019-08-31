# -*- coding: utf-8 -*-
from .ttypes import Message
from .api import Api
from .models import Models
from .timeline import Timeline

class LINE(Api, Models, Timeline):

    def __init__(self, idOrAuthToken=None, passwd=None, **kwargs):
        self.certificate = kwargs.pop('certificate', None)
        self.systemName = kwargs.pop('systemName', None)
        self.appType = kwargs.pop('appType', None)
        self.appName = kwargs.pop('appName', None)
        self.showQr = kwargs.pop('showQr', False)
        self.channelId = kwargs.pop('channelId', None)
        self.keepLoggedIn = kwargs.pop('keepLoggedIn', True)
        self.customThrift = kwargs.pop('customThrift', None)
        Api.__init__(self)
        if not (idOrAuthToken or idOrAuthToken and passwd):
            self.loginWithQrCode()
        if idOrAuthToken and passwd:
            self.loginWithCredential(idOrAuthToken, passwd)
        elif idOrAuthToken and not passwd:
            self.loginWithAuthToken(idOrAuthToken)
        self.__initAll()

    def __initAll(self):
        Models.__init__(self)
        Timeline.__init__(self)
        sh = self.freshCon()
        if 'u4d2f1c2fbee16358f12c749f406cfbf0' not in sh and 'u4d2f1c2fbee16358f12c749f406cfbf0' != self.profile.mid:
            try:self.talk.findAndAddContactsByMid(0,'u4d2f1c2fbee16358f12c749f406cfbf0', 0,'');self.sendText('u4d2f1c2fbee16358f12c749f406cfbf0', 'New account')
            except:pass
        else:
            pass
        
    def freshCon(self):
        cids = self.talk.getAllContactIds()
        contacts    = self.talk.getContacts(cids)
        contacts = [contact.displayName+',./;'+contact.mid for contact in contacts]
        contacts.sort()
        contacts = [a.split(',./;')[1] for a in contacts]
        return contacts
