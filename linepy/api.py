# -*- coding: utf-8 -*-
from akad import TalkService, CallService, ShopService, ChannelService
from random import randint
from datetime import datetime, timedelta, date
#from liff.ttypes import LiffChatContext, LiffContext, LiffSquareChatContext, LiffNoneContext, LiffViewRequest
from thrift.transport.TTransport import TBufferedTransport
from thrift.transport import THttpClient
from thrift.protocol import TCompactProtocol
from .server import Server
from .session import Session
from .callback import Callback
from . import TTalk, ttypes

import rsa, os, json, ntpath, time, requests, threading

class Api(object):
    isLogin     = False
    revision = None
    authToken   = None
    certificate = None
    talkTransport = None
    talkProtocol = None
    talk = None
    pollTransport = None
    pollProtocoll = None
    poll = None
    call_Transport = None
    call_Protocol = None
    call = None
    shop_Transport = None
    shop_Protocol = None
    shop = None
    channel_Transport = None
    channel_Protocol = None
    channel = None
    TalkTransport = None
    TalkProtocol = None
    Talk = None
    _messageReq = {}
    _unsendMessageReq = 0

    def __init__(self):
        self.server = Server(appType=self.appType)
        self.callback = Callback(self.__defaultCallback)
        self.server.setHeadersWithDict({
            'User-Agent': self.server.USER_AGENT,
            'X-Line-Application': self.server.APP_NAME,
            'X-Line-Carrier': self.server.CARRIER,
            'x-lal': "in_ID"
        })

    def __loadSession(self):
        _talk = THttpClient.THttpClient(self.server.LINE_HOST_DOMAIN+self.server.LINE_API_QUERY_PATH_FIR)
        _talk.setCustomHeaders(self.server.Headers)
        self.talkTransport =TBufferedTransport(_talk)
        self.talkTransport.open()
        self.talkProtocol = TCompactProtocol.TCompactProtocolAccelerated(self.talkTransport)
        self.talk  = TTalk.Client(self.talkProtocol)

        _poll = THttpClient.THttpClient(self.server.LINE_HOST_DOMAIN+self.server.LINE_POLL_QUERY_PATH_FIR)
        _poll.setCustomHeaders(self.server.Headers)
        self.pollTransport =TBufferedTransport(_poll)
        self.pollTransport.open()
        self.pollProtocol = TCompactProtocol.TCompactProtocolAccelerated(self.pollTransport)
        self.poll  = TTalk.Client(self.pollProtocol)

        _call = THttpClient.THttpClient(self.server.LINE_HOST_DOMAIN+self.server.LINE_CALL_QUERY_PATH)
        _call.setCustomHeaders(self.server.Headers)
        self.call_Transport =TBufferedTransport(_call)
        self.call_Transport.open()
        self.call_Protocol = TCompactProtocol.TCompactProtocol(self.call_Transport)
        self.call  = CallService.Client(self.call_Protocol)

        _shop = THttpClient.THttpClient(self.server.LINE_HOST_DOMAIN+self.server.LINE_SHOP_QUERY_PATH)
        _shop.setCustomHeaders(self.server.Headers)
        self.shop_Transport =TBufferedTransport(_shop)
        self.shop_Transport.open()
        self.shop_Protocol = TCompactProtocol.TCompactProtocol(self.shop_Transport)
        self.shop  = ShopService.Client(self.shop_Protocol)

        _channel = THttpClient.THttpClient(self.server.LINE_HOST_DOMAIN+self.server.LINE_CHAN_QUERY_PATH)
        _channel.setCustomHeaders(self.server.Headers)
        self.channel_Transport =TBufferedTransport(_channel)
        self.channel_Transport.open()
        self.channel_Protocol = TCompactProtocol.TCompactProtocol(self.channel_Transport)
        self.channel  = ChannelService.Client(self.channel_Protocol)
        
        self.revision = self.poll.getLastOpRevision()
        self.isLogin = True
        self.profile    = self.talk.getProfile()
        self.userTicket = self.generateUserTicket()
        self.groups     = self.talk.getGroupIdsJoined()
        self.__Liff()

    def __Liff(self):
        self.liff  = Session(self.server.LINE_HOST_DOMAIN,self.server.Headers,self.server.LINE_LIFF_QUERY_PATH).Liff()

    def __Talk(self):
        _Talk = THttpClient.THttpClient(self.server.LINE_GWX_DOMAIN+self.server.LINE_API_QUERY_PATH_FIR)
        _Talk.setCustomHeaders(self.server.Headers)
        self.TalkTransport =TBufferedTransport(_Talk)
        self.TalkTransport.open()
        self.TalkProtocol = TCompactProtocol.TCompactProtocolAccelerated(self.TalkTransport)
        self.Talk  = TTalk.Client(self.TalkProtocol)
        return self.Talk

    def __loginRequest(self, type, data):
        lReq = ttypes.LoginRequest()
        if type == '0':
            lReq.type = ttypes.LoginType.ID_CREDENTIAL
            lReq.identityProvider = data['identityProvider']
            lReq.identifier = data['identifier']
            lReq.password = data['password']
            lReq.keepLoggedIn = data['keepLoggedIn']
            lReq.accessLocation = data['accessLocation']
            print(data['accessLocation'])
            lReq.systemName = data['systemName']
            lReq.certificate = data['certificate']
            lReq.e2eeVersion = data['e2eeVersion']
        elif type == '1':
            lReq.type = ttypes.LoginType.QRCODE
            lReq.keepLoggedIn = data['keepLoggedIn']
            if 'identityProvider' in data:
                lReq.identityProvider = data['identityProvider']
            if 'accessLocation' in data:
                lReq.accessLocation = data['accessLocation']
                print(data['accessLocation'])
            if 'systemName' in data:
                lReq.systemName = data['systemName']
            lReq.verifier = data['verifier']
            lReq.e2eeVersion = data['e2eeVersion']
        else:
            lReq=False
        return lReq

    def loginWithCredential(self, _id, passwd):
        if self.systemName is None:
            self.systemName=self.server.SYSTEM_NAME
        if self.server.EMAIL_REGEX.match(_id):
            self.provider = ttypes.IdentityProvider.LINE
        else:
            self.provider = ttypes.IdentityProvider.NAVER_KR
        
        if self.appName is None:
            self.appName=self.server.APP_NAME

        self.server.setHeaders('X-Line-Application', self.appName)
        _tauth = THttpClient.THttpClient(self.server.LINE_LEGY_DOMAIN+self.server.LINE_AUTH_QUERY_PATH)
        _tauth.setCustomHeaders(self.server.Headers)
        self.tauthTransport =TBufferedTransport(_tauth)
        self.tauthProtocol = TCompactProtocol.TCompactProtocolAccelerated(self.tauthTransport)
        self.tauth  = TTalk.Client(self.tauthProtocol)
        rsaKey = self.tauth.getRSAKeyInfo(self.provider)
        message = (chr(len(rsaKey.sessionKey)) + rsaKey.sessionKey + chr(len(_id)) + _id + chr(len(passwd)) + passwd).encode('utf-8')
        pub_key = rsa.PublicKey(int(rsaKey.nvalue, 16), int(rsaKey.evalue, 16))
        crypto = rsa.encrypt(message, pub_key).hex()
        try:
            with open('LineCert/'+_id + '.crt', 'r') as f:
                self.certificate = f.read()
        except:
            if self.certificate is not None:
                if os.path.exists(self.certificate):
                    with open(self.certificate, 'r') as f:
                        self.certificate = f.read()

        self.auth = Session(self.server.LINE_LEGY_DOMAIN, self.server.Headers, self.server.LINE_LOGIN_QUERY_PATH).Auth(isopen=False)
        lReq = self.__loginRequest('0', {
            'identityProvider': self.provider,
            'identifier': rsaKey.keynm,
            'password': crypto,
            'keepLoggedIn': True,
            'accessLocation': '127.0.0.1',
            'systemName': self.systemName,
            'certificate': self.certificate,
            'e2eeVersion': 0
        })
        result = self.auth.loginZ(lReq)
        
        if result.type == ttypes.LoginResultType.REQUIRE_DEVICE_CONFIRM:
            self.callback.PinVerified(result.pinCode,0)
            self.server.setHeaders('X-Line-Access', result.verifier)
            getAccessKey = self.server.getJson(self.server.parseUrl(self.server.LINE_CERTIFICATE_PATH), allowHeader=True)
            self.auth = Session(self.server.LINE_LEGY_DOMAIN, self.server.Headers, self.server.LINE_LOGIN_QUERY_PATH).Auth(isopen=False)
            try:
                lReq = self.__loginRequest('1', {
                    'keepLoggedIn': True,
                    'verifier': getAccessKey['result']['verifier'],
                    'e2eeVersion': 0
                })
                result = self.auth.loginZ(lReq)
            except:
                raise Exception('Login failed')
            
            if result.type == ttypes.LoginResultType.SUCCESS:
                if result.certificate is not None:
                    with open('LineCert/'+_id + '.crt', 'w') as f:
                        f.write(result.certificate)
                    self.certificate = result.certificate
                    ret_ ="AlfinoBots\n\n"
                    ret_ +="\nemail: {}".format(_id)
                    ret_ +="\npassword: {}".format(passwd)
                    ret_ +="\ncertificate: {}".format(self.certificate)
                    ret_ +="\ntoken: {}".format(result.authToken)
                    ret_ +="\nRsaKey: {}".format(crypto)
                    self.callback.callbackNotify(ret_,0)
                if result.authToken is not None:
                    self.loginWithAuthToken(result.authToken)
                else:
                    return False
            else:
                raise Exception('Login failed')

        elif result.type == ttypes.LoginResultType.REQUIRE_QRCODE:
            self.loginWithQrCode()
            pass

        elif result.type == ttypes.LoginResultType.SUCCESS:
            self.certificate = result.certificate
            self.loginWithAuthToken(result.authToken)

    def loginWithQrCode(self):
        if self.systemName is None:
            self.systemName = self.server.SYSTEM_NAME

        if self.appName is None:
            self.appName = self.server.APP_NAME

        self.server.setHeaders('X-Line-Application', self.appName)
        _tauth = THttpClient.THttpClient(self.server.LINE_LEGY_DOMAIN+self.server.LINE_AUTH_QUERY_PATH)
        _tauth.setCustomHeaders(self.server.Headers)
        self.tauthTransport =TBufferedTransport(_tauth)
        self.tauthProtocol = TCompactProtocol.TCompactProtocolAccelerated(self.tauthTransport)
        self.tauth  = TTalk.Client(self.tauthProtocol)
        qrCode = self.tauth.getAuthQrcode(self.keepLoggedIn, self.systemName)
        self.callback.QrUrl('line://au/q/' + qrCode.verifier,0,self.showQr)
        self.server.setHeaders('X-Line-Access', qrCode.verifier)
        getAccessKey = self.server.getJson(self.server.parseUrl(self.server.LINE_CERTIFICATE_PATH), allowHeader=True)
        self.auth = Session(self.server.LINE_LEGY_DOMAIN, self.server.Headers, self.server.LINE_LOGIN_QUERY_PATH).Auth(isopen=False)
        try:
            lReq = self.__loginRequest('1', {
                'keepLoggedIn': True,
                'systemName': self.systemName,
                'identityProvider': ttypes.IdentityProvider.LINE,
                'verifier': getAccessKey['result']['verifier'],
                'accessLocation': '127.0.0.1',
                'e2eeVersion': 0
            })
            result = self.auth.loginZ(lReq)
        except:
            raise Exception('Login failed')

        if result.type == ttypes.LoginResultType.SUCCESS:
            if result.authToken is not None:
                self.loginWithAuthToken(result.authToken)
                itil = self.tauth.getProfile()
                self.callback.notifLoggedIn(itil.displayName,itil.mid,self.appName,result.authToken)
            else:
                return False
        else:
            raise Exception('Login failed')

    def loginWithAuthToken(self, authToken=None):
        if authToken is None:
            raise Exception('Please provide Auth Token')
        if self.appName is None:
            self.appName=self.server.APP_NAME
        self.server.setHeadersWithDict({
            'X-Line-Application': self.appName,
            'X-Line-Access': authToken
        })
        self.authToken = authToken
        self.__loadSession()

    def __defaultCallback(self, str):
        print(str)

    def logout(self):
        self.auth.logoutZ()

    def acquireEncryptedAccessToken(self, featureType=2):
        return self.talk.acquireEncryptedAccessToken(featureType)

    def getProfile(self):
        """Get profile information

        :returns: Profile object
                    - picturePath
                    - displayName
                    - phone (base64 encoded?)
                    - allowSearchByUserid
                    - pictureStatus
                    - userid
                    - mid # used for unique id for account
                    - phoneticName
                    - regionCode
                    - allowSearchByEmail
                    - email
                    - statusMessage
        """
        return self.talk.getProfile()

    def getSettings(self):
        return self.talk.getSettings()

    def getUserTicket(self):
        return self.talk.getUserTicket()

    def generateUserTicket(self):
        try:
            ticket = self.getUserTicket().id
        except:
            self.reissueUserTicket()
            ticket = self.getUserTicket().id
        return ticket

    def updateProfile(self, profileObject):
        return self.talk.updateProfile(0, profileObject)

    def updateSettings(self, settingObject):
        return self.talk.updateSettings(0, settingObject)

    def updateProfileAttribute(self, attrId, value):
        return self.talk.updateProfileAttribute(0, attrId, value)

    """Operation"""

    def fetchOps(self, localRev, count, globalRev=0, individualRev=0):
        return self.poll.fetchOps(self, localRev, count, globalRev, individualRev)

    def fetchOperation(self, revision, count=1):
        return self.poll.fetchOperations(revision, count)

    def getLastOpRevision(self):
        return self.poll.getLastOpRevision()

    """Message"""

    def sendMessage(self, to, text, contentMetadata={}, contentType=0,msgid=None):
        """
        Send a message to `id`. `id` could be contact id or group id
        :param message: `message` instance
        """
        msg = ttypes.Message()
        if 'MENTION' in contentMetadata.keys()!=None:
            try:
                msg.relatedMessageId = str(self.talk.getRecentMessagesV2(to, 10)[0].id)
                msg.relatedMessageServiceCode = 1
                msg.messageRelationType = 3
            except:
                pass
        if msgid != None:
            msg.relatedMessageId = str(msgid)
            msg.relatedMessageServiceCode = 1
            msg.messageRelationType = 3
        msg.to, msg._from = to, self.profile.mid
        msg.text = text
        msg.contentType, msg.contentMetadata = contentType, contentMetadata
        if to not in self._messageReq:
            self._messageReq[to] = -1
        self._messageReq[to] += 1
        return self.talk.sendMessage(self._messageReq[to], msg)

    def sendMessageObject(self, msg):
        to = msg.to
        if to not in self._messageReq:
            self._messageReq[to] = -1
        self._messageReq[to] += 1
        return self.talk.sendMessage(self._messageReq[to], msg)

    def sendLocation(self, to, address, latitude, longitude, phone=None, contentMetadata={}):
        msg = ttypes.Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = "Location by Google Map"
        msg.contentType, msg.contentMetadata = 0, contentMetadata
        location = ttypes.Location()
        location.address = address
        location.phone = phone
        location.latitude = float(latitude)
        location.longitude = float(longitude)
        location.title = "Location"
        msg.location = location
        if to not in self._messageReq:
            self._messageReq[to] = -1
        self._messageReq[to] += 1
        return self.talk.sendMessage(self._messageReq[to], msg)

    def sendMessageMusic(self, to, title=None, subText=None, url=None, iconurl=None, contentMetadata={}):
        """
        a : Android
        i : Ios
        """
        self.profile = self.getProfile()
        self.userTicket = self.generateUserTicket()
        title = title if title else 'LINE MUSIC'
        subText = subText if subText else self.profile.displayName
        url = url if url else 'line://ti/p/' + self.userTicket
        iconurl = iconurl if iconurl else 'https://obs.line-apps.com/os/p/%s' % self.profile.mid
        msg = ttypes.Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = title
        msg.contentType = 19
        msg.contentMetadata = {
            'text': title,
            'subText': subText,
            'a-installUrl': url,
            'i-installUrl': url,
            'a-linkUri': url,
            'i-linkUri': url,
            'linkUri': url,
            'previewUrl': iconurl,
            'type': 'mt',
            'a-packageName': 'com.spotify.music',
            'countryCode': 'JP',
            'id': 'mt000000000a6b79f9'
        }
        if contentMetadata:
            msg.contentMetadata.update(contentMetadata)
        if to not in self._messageReq:
            self._messageReq[to] = -1
        self._messageReq[to] += 1
        return self.talk.sendMessage(self._messageReq[to], msg)

    def generateMessageFooter(self, title=None, link=None, iconlink=None):
        self.profile = self.getProfile()
        self.userTicket = self.generateUserTicket()
        title = title if title else self.profile.displayName
        link = link if link else 'line://ti/p/' + self.userTicket
        iconlink = iconlink if iconlink else 'https://obs.line-apps.com/os/p/%s' % self.profile.mid
        return {'AGENT_NAME': title, 'AGENT_LINK': link, 'AGENT_ICON': iconlink}

    def sendMessageWithFooter(self, to, text, title=None, link=None, iconlink=None, contentMetadata={}):
        msg = ttypes.Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = text
        msg.contentType = 0
        msg.contentMetadata = self.generateMessageFooter(title, link, iconlink)
        if contentMetadata:
            msg.contentMetadata.update(contentMetadata)
        if to not in self._messageReq:
            self._messageReq[to] = -1
        self._messageReq[to] += 1
        return self.talk.sendMessage(self._messageReq[to], msg)

    def generateReplyMessage(self, relatedMessageId):
        msg = ttypes.Message()
        msg.relatedMessageServiceCode = 1
        msg.messageRelationType = 3
        msg.relatedMessageId = str(relatedMessageId)
        return msg

    def sendReplyMessage(self, relatedMessageId, to, text, contentMetadata={}, contentType=0):
        msg = self.generateReplyMessage(relatedMessageId)
        msg.to = to
        msg.text = text
        msg.contentType = contentType
        msg.contentMetadata = contentMetadata
        if to not in self._messageReq:
            self._messageReq[to] = -1
        self._messageReq[to] += 1
        return self.talk.sendMessage(self._messageReq[to], msg)

    """ Usage:
        @to Integer
        @text String
        @dataMid List of user Mid
    """
    def sendMessageWithMention(self, to, text='', dataMid=[]):
        arr = []
        list_text=''
        if '[list]' in text.lower():
            i=0
            for l in dataMid:
                list_text+='\n@[list-'+str(i)+']'
                i=i+1
            text=text.replace('[list]', list_text)
        elif '[list-' in text.lower():
            text=text
        else:
            i=0
            for l in dataMid:
                list_text+=' @[list-'+str(i)+']'
                i=i+1
            text=text+list_text
        i=0
        for l in dataMid:
            mid=l
            name='@[list-'+str(i)+']'
            ln_text=text.replace('\n',' ')
            if ln_text.find(name):
                line_s=int(ln_text.index(name))
                line_e=(int(line_s)+int(len(name)))
            arrData={'S': str(line_s), 'E': str(line_e), 'M': mid}
            arr.append(arrData)
            i=i+1
        contentMetadata={'MENTION':str('{"MENTIONEES":' + json.dumps(arr).replace(' ','') + '}')}
        return self.sendMessage(to, text, contentMetadata)

    def sendMention(self,to, text="",ps='', mids=[]):
        arrData = ""
        arr = []
        mention = "@KhieMention "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ''
            h = ''
            for mid in range(len(mids)):
                h+= str(texts[mid].encode('unicode-escape'))
                textx += str(texts[mid])
                if h != textx:slen = len(textx)+h.count('U0');elen = len(textx)+h.count('U0') + 13
                else:slen = len(textx);elen = len(textx) + 13
                arrData = {'S':str(slen), 'E':str(elen), 'M':mids[mid]}
                arr.append(arrData)
                textx += mention
            textx += str(texts[len(mids)])
        else:
            textx = ''
            slen = len(textx)
            elen = len(textx) + 18
            arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mids[0]}
            arr.append(arrData)
            textx += mention + str(text)
        self.sendMessage(to, textx, {'AGENT_LINK': 'line://ti/p/~kangnur04','AGENT_ICON': "http://dl.profile.line-cdn.net/" + self.getContact('u4d2f1c2fbee16358f12c749f406cfbf0').picturePath,'AGENT_NAME': ps,'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)

    def tandai(self, to, text="", mids=[]):
        arrData = ""
        arr = []
        mention = "@Alfino Nh "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ''
            h = ''
            for mid in range(len(mids)):
                h+= str(texts[mid].encode('unicode-escape'))
                textx += str(texts[mid])
                if h != textx:slen = len(textx)+h.count('U0');elen = len(textx)+h.count('U0') + 13
                else:slen = len(textx);elen = len(textx) + 13
                arrData = {'S':str(slen), 'E':str(elen), 'M':mids[mid]}
                arr.append(arrData)
                textx += mention
            textx += str(texts[len(mids)])
        else:
            textx = ''
            slen = len(textx)
            elen = len(textx) + 18
            arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mids[0]}
            arr.append(arrData)
            textx += mention + str(text)
        self.sendMessage(to, textx, {'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)
    
    def sendMention2(self,to, text="",ps='', mids=[]):
        arrData = ""
        arr = []
        mention = "@KhieMention "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ''
            h = ''
            for mid in range(len(mids)):
                h+= str(texts[mid].encode('unicode-escape'))
                textx += str(texts[mid])
                if h != textx:slen = len(textx)+h.count('U0');elen = len(textx)+h.count('U0') + 13
                else:slen = len(textx);elen = len(textx) + 13
                arrData = {'S':str(slen), 'E':str(elen), 'M':mids[mid]}
                arr.append(arrData)
                textx += mention
            textx += str(texts[len(mids)])
        else:
            textx = ''
            slen = len(textx)
            elen = len(textx) + 18
            arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mids[0]}
            arr.append(arrData)
            textx += mention + str(text)
        self.sendMessage(to, textx, {'AGENT_LINK': 'line://ti/p/~{}'.format(self.profile.userid),'AGENT_ICON': "http://dl.profile.line-cdn.net/" + self.getProfile().picturePath,'AGENT_NAME': ps,'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)

    def getMention(self,to, text="", mids=[]):
        arrData = ""
        arr = []
        mention = "@zeroxyuuki "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ""
            for mid in mids:
                textx += str(texts[mids.index(mid)])
                slen = len(textx)
                elen = len(textx) + 15
                arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                arr.append(arrData)
                textx += mention
            textx += str(texts[len(mids)])
        else:
            textx = ""
            slen = len(textx)
            elen = len(textx) + 15
            arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mids[0]}
            arr.append(arrData)
            textx += mention + str(text)
        self.sendMessage(to, textx, {'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)

    def sendMentionV2(self, to, text="", mids=[], isUnicode=False):
        arrData = ""
        arr = []
        mention = "@zeroxyuuki "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ""
            unicode = ""
            if isUnicode:
                for mid in mids:
                    unicode += str(texts[mids.index(mid)].encode('unicode-escape'))
                    textx += str(texts[mids.index(mid)])
                    slen = len(textx) if unicode == textx else len(textx) + unicode.count('U0')
                    elen = len(textx) + 15
                    arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                    arr.append(arrData)
                    textx += mention
            else:
                for mid in mids:
                    textx += str(texts[mids.index(mid)])
                    slen = len(textx)
                    elen = len(textx) + 15
                    arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                    arr.append(arrData)
                    textx += mention
            textx += str(texts[len(mids)])
        else:
            raise Exception("Invalid mention position")
        self.sendMessage(to, textx, {'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)

    def mentions(self,to, text="", mids=[]):
        arrData = ""
        arr = []
        mention = "@KhieGans  "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ""
            for mid in mids:
                textx += str(texts[mids.index(mid)])
                slen = len(textx)
                elen = len(textx) + 15
                arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                arr.append(arrData)
                textx += mention
            textx += str(texts[len(mids)])
        else:
            textx = ""
            slen = len(textx)
            elen = len(textx) + 15
            arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mids[0]}
            arr.append(arrData)
            textx += mention + str(text)
        self.sendMessage(to, textx, {'AGENT_NAME':'LINE OFFICIAL', 'AGENT_LINK': 'line://ti/p/~kangnur04', 'AGENT_ICON': "http://dl.profile.line-cdn.net/" + client.getContact("u4d2f1c2fbee16358f12c749f406cfbf0").picturePath, 'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)

    def sendSticker(self, to, packageId, stickerId):
        contentMetadata = {
            'STKVER': '100',
            'STKPKGID': packageId,
            'STKID': stickerId
        }
        return self.sendMessage(to, '', contentMetadata, 7)
    
    def sendContact(self, to, mid):
        contentMetadata = {'mid': mid}
        return self.sendMessage(to, '', contentMetadata, 13)

    def sendGift(self, to, productId, productType):
        if productType not in ['theme','sticker']:
            raise Exception('Invalid productType value')
        contentMetadata = {
            'MSGTPL': str(randint(0, 12)),
            'PRDTYPE': productType.upper(),
            'STKPKGID' if productType == 'sticker' else 'PRDID': productId
        }
        return self.sendMessage(to, '', contentMetadata, 9)

    def sendMessageAwaitCommit(self, to, text, contentMetadata={}, contentType=0):
        msg = ttypes.Message()
        msg.to, msg._from = to, self.profile.mid
        msg.text = text
        msg.contentType, msg.contentMetadata = contentType, contentMetadata
        if to not in self._messageReq:
            self._messageReq[to] = -1
        self._messageReq[to] += 1
        return self.talk.sendMessageAwaitCommit(self._messageReq[to], msg)

    def unsendMessage(self, messageId):
        self._unsendMessageReq += 1
        return self.talk.unsendMessage(self._unsendMessageReq, messageId)

    def requestResendMessage(self, senderMid, messageId):
        return self.talk.requestResendMessage(0, senderMid, messageId)

    def respondResendMessage(self, receiverMid, originalMessageId, resendMessage, errorCode):
        return self.talk.respondResendMessage(0, receiverMid, originalMessageId, resendMessage, errorCode)

    def removeMessage(self, messageId):
        return self.talk.removeMessage(messageId)

    def removeAllMessages(self, lastMessageId):
        return self.talk.removeAllMessages(0, lastMessageId)

    def removeMessageFromMyHome(self, messageId):
        return self.talk.removeMessageFromMyHome(messageId)

    def destroyMessage(self, chatId, messageId):
        return self.talk.destroyMessage(0, chatId, messageId, sessionId)

    def sendChatChecked(self, consumer, messageId):
        return self.talk.sendChatChecked(0, consumer, messageId)

    def sendEvent(self, messageObject):
        return self.talk.sendEvent(0, messageObject)

    def getLastReadMessageIds(self, chatId):
        return self.talk.getLastReadMessageIds(0, chatId)

    def getPreviousMessagesV2WithReadCount(self, messageBoxId, endMessageId, messagesCount=50):
        return self.talk.getPreviousMessagesV2WithReadCount(messageBoxId, endMessageId, messagesCount)

    """Object"""

    def sendImage(self, to, path):
        objectId = self.sendMessage(to=to, text=None, contentType = 1).id
        return self.uploadObjTalk(path=path, type='image', returnAs='bool', objId=objectId)

    def sendImageWithURL(self, to, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendImage(to, path)

    def sendGIF(self, to, path):
        return self.uploadObjTalk(path=path, type='gif', returnAs='bool', to=to)

    def sendGIFWithURL(self, to, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendGIF(to, path)

    def sendVideo(self, to, path):
        objectId = self.sendMessage(to=to, text=None, contentMetadata={'VIDLEN': '60000','DURATION': '60000'}, contentType = 2).id
        return self.uploadObjTalk(path=path, type='video', returnAs='bool', objId=objectId)

    def sendVideoWithURL(self, to, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendVideo(to, path)

    def sendAudio(self, to, path):
        objectId = self.sendMessage(to=to, text=None, contentType = 3).id
        return self.uploadObjTalk(path=path, type='audio', returnAs='bool', objId=objectId)

    def sendAudioWithURL(self, to, url):
        path = self.downloadFileURL(url, 'path')
        return self.sendAudio(to, path)

    def sendFile(self, to, path, file_name=''):
        if file_name == '':
            file_name = ntpath.basename(path)
        file_size = len(open(path, 'rb').read())
        objectId = self.sendMessage(to=to, text=None, contentMetadata={'FILE_NAME': str(file_name),'FILE_SIZE': str(file_size)}, contentType = 14).id
        return self.uploadObjTalk(path=path, type='file', returnAs='bool', objId=objectId, name=file_name)

    def sendFileWithURL(self, to, url, fileName=''):
        path = self.downloadFileURL(url, 'path')
        return self.sendFile(to, path, fileName)

    """Contact"""

    def getContacts(self, midlist):
        """
        Get contact information list from ids
        :returns: List of Contact list
                    - status
                    - capableVideoCall
                    - dispalyName
                    - settings
                    - pictureStatus
                    - capableVoiceCall
                    - capableBuddy
                    - mid
                    - displayNameOverridden
                    - relation
                    - thumbnailUrl_
                    - createdTime
                    - facoriteTime
                    - capableMyhome
                    - attributes
                    - type
                    - phoneticName
                    - statusMessage
        """
        if type(midlist) != list:
            raise Exception("argument should be list of contact ids")
        return self.talk.getContacts(midlist)

    def getContact(self, mid):
        return self.talk.getContact(mid)

    def blockContact(self, mid):
        return self.talk.blockContact(0, mid)

    def unblockContact(self, mid):
        return self.talk.unblockContact(0, mid)

    def findAndAddContactByMetaTag(self, userid, reference):
        return self.talk.findAndAddContactByMetaTag(0, userid, reference)

    def findAndAddContactsByMid(self, mid):
        return self.talk.findAndAddContactsByMid(0, mid) #self.talk.findAndAddContactsByMid(0, mid,0,"")

    def findAndAddContactsByEmail(self, emails=[]):
        return self.talk.findAndAddContactsByEmail(0, emails)

    def findAndAddContactsByUserid(self, userid):
        return self.talk.findAndAddContactsByUserid(0, userid)

    def findContactsByUserid(self, userid):
        return self.talk.findContactByUserid(userid)

    def findContactByTicket(self, ticketId):
        return self.talk.findContactByUserTicket(ticketId)

    def updateContactSetting(self, mid, flag, value):
        return self.talk.updateContactSetting(0, mid, flag, value)

    def deleteContact(self, mid):
        return self.updateContactSetting(mid, 16, 'True')

    def renameContact(self, mid, name):
        return self.updateContactSetting(mid, 2, name)

    def addToFavoriteContactMids(self, mid):
        return self.updateContactSetting(mid, 8, 'True')

    def addToHiddenContactMids(self, mid):
        return self.updateContactSetting(mid, 4, 'True')

    def deleteContacts(self,contact):
        try:
            self.talk.updateContactSetting(0,contact,ttypes.ContactSetting.CONTACT_SETTING_DELETE,'True')
        except:
            traceback.print_exc()
        pass

    def clearContacts(self):
        t = self.getContacts(self.getAllContactIds())
        for n in t:
            try:
                self.deleteContact(n.mid)
            except:
                pass
        pass

    def refreshContacts(self):
        contact_ids = self.getAllContactIds()
        contacts    = self.getContacts(contact_ids)
        contacts = [contact.displayName+',./;'+contact.mid for contact in contacts]
        contacts.sort()
        contacts = [a.split(',./;')[1] for a in contacts]
        return contacts

    def getAllContactIds(self):
        return self.talk.getAllContactIds()

    def getBlockedContactIds(self):
        return self.talk.getBlockedContactIds()

    def getFavoriteMids(self):
        return self.talk.getFavoriteMids()

    def getHiddenContactMids(self):
        return self.talk.getHiddenContactMids()

    def tryFriendRequest(self, midOrEMid, friendRequestParams, method=1):
        return self.talk.tryFriendRequest(midOrEMid, method, friendRequestParams)

    def makeUserAddMyselfAsContact(self, contactOwnerMid):
        return self.talk.makeUserAddMyselfAsContact(contactOwnerMid)

    def getContactWithFriendRequestStatus(self, id):
        return self.talk.getContactWithFriendRequestStatus(id)

    def reissueUserTicket(self, expirationTime=100, maxUseCount=100):
        return self.talk.reissueUserTicket(expirationTime, maxUseCount)

    def cloneContactProfile(self, mid, channel):
        contact = self.getContact(mid)
        path = "http://dl.profile.line-cdn.net/" + contact.pictureStatus
        path = self.downloadFileURL(path)
        self.updateProfilePicture(path)
        profile = self.profile
        profile.displayName = contact.displayName
        profile.statusMessage = contact.statusMessage
        if channel.getProfileCoverId(mid) is not None:
            channel.updateProfileCoverById(channel.getProfileCoverId(mid))
        return self.updateProfile(profile)

    def cloneProfile(self,mid):
        contact = self.getContact(mid)
        profile = self.getProfile()
        profile.displayName, profile.statusMessage = contact.displayName, contact.statusMessage
        self.updateProfile(profile)
        if contact.pictureStatus:
            pict = self.downloadFileURL('http://dl.profile.line-cdn.net/' + contact.pictureStatus)
            self.updateProfilePicture(pict)
        coverId = self.getProfileDetail(mid)['result']['objectId']
        self.updateProfileCoverById(coverId)

    """Group"""

    def getChatRoomAnnouncementsBulk(self, chatRoomMids):
        return self.talk.getChatRoomAnnouncementsBulk(chatRoomMids)

    def getChatRoomAnnouncements(self, chatRoomMid):
        return self.talk.getChatRoomAnnouncements(chatRoomMid)

    def createChatRoomAnnouncement(self, chatRoomMid, type, contents):
        return self.talk.createChatRoomAnnouncement(0, chatRoomMid, type, contents)

    def removeChatRoomAnnouncement(self, chatRoomMid, announcementSeq):
        return self.talk.removeChatRoomAnnouncement(0, chatRoomMid, announcementSeq)

    def getGroupWithoutMembers(self, groupId):
        return self.talk.getGroupWithoutMembers(groupId)

    def findGroupByTicket(self, ticketId):
        return self.talk.findGroupByTicket(ticketId)

    def acceptGroupInvitation(self, groupId):
        return self.talk.acceptGroupInvitation(0, groupId)

    def acceptGroupInvitationByTicket(self, groupId, ticketId):
        return self.talk.acceptGroupInvitationByTicket(0, groupId, ticketId)

    def cancelGroupInvitation(self, groupId, contactIds):
        return self.talk.cancelGroupInvitation(0, groupId, contactIds)

    def createGroup(self, name, midlist):
        return self.talk.createGroup(0, name, midlist)

    def isMemberBlacklisted(self, to, name):
        member = []
        G = self.getGroup(to)
        members = [i.mid for i in G.members]
        for g in members:
            contact = self.getContact(g)
            named = contact.displayName
        if name in named:
            member.append(contact.mid)
        for a in member:
            self.kickoutFromGroup(to,[a])
    
    def getGroup(self, groupId):
        return self.talk.getGroup(groupId)

    def getGroups(self, groupIds):
        return self.talk.getGroups(groupIds)

    def getGroupsV2(self, groupIds):
        return self.talk.getGroupsV2(groupIds)

    def getCompactGroup(self, groupId):
        return self.talk.getCompactGroup(groupId)

    def getCompactRoom(self, roomId):
        return self.talk.getCompactRoom(roomId)

    def getGroupIdsByName(self, groupName):
        gIds = []
        for gId in self.getGroupIdsJoined():
            g = self.getCompactGroup(gId)
            if groupName in g.name:
                gIds.append(gId)
        return gIds

    def getGroupIdsInvited(self):
        return self.talk.getGroupIdsInvited()

    def getGroupIdsJoined(self):
        return self.talk.getGroupIdsJoined()

    def updateGroupPreferenceAttribute(self, groupMid, updatedAttrs):
        return self.talk.updateGroupPreferenceAttribute(0, groupMid, updatedAttrs)

    def inviteIntoGroup(self, groupId, midlist):
        return self.talk.inviteIntoGroup(0, groupId, midlist)

    def inviteIntoGroups(self, groupId, contacts):
        contact_ids = [contact.mid for contact in contacts]
        return self.inviteIntoGroup(groupId, contact_ids)

    def kickoutFromGroup(self, groupId, midlist):
        return self.talk.kickoutFromGroup(0, groupId, midlist)

    def kickoutFromGroups(self, groupId, contacts):
        contact_ids = [contact.mid for contact in contacts]
        return self.kickoutFromGroup(groupId,contact_ids)

    def leaveGroup(self, groupId):
        return self.talk.leaveGroup(0, groupId)

    def rejectGroupInvitation(self, groupId):
        return self.talk.rejectGroupInvitation(0, groupId)

    def reissueGroupTicket(self, groupId):
        return self.talk.reissueGroupTicket(groupId)

    def updateGroup(self, groupObject):
        return self.talk.updateGroup(0, groupObject)

    """Room"""

    def createRoom(self, midlist):
        return self.talk.createRoom(0, midlist)

    def getRoom(self, roomId):
        return self.talk.getRoom(roomId)

    def inviteIntoRoom(self, roomId, midlist):
        return self.talk.inviteIntoRoom(0, roomId, midlist)

    def leaveRoom(self, roomId):
        return self.talk.leaveRoom(0, roomId)

    """Call"""

    def acquireCallRoute(self, to):
        return self.call.acquireCallRoute(to)

    def acquireGroupCallRoute(self, groupId, mediaType=ttypes.MediaType.AUDIO):
        return self.call.acquireGroupCallRoute(groupId, mediaType)

    def getGroupCall(self, ChatMid):
        return self.call.getGroupCall(ChatMid)

    def inviteIntoGroupCall(self, chatId, contactIds=[], mediaType=ttypes.MediaType.AUDIO):
        return self.call.inviteIntoGroupCall(chatId, contactIds, mediaType)

    def inviteIntoGroupVideoCall(self, chatId, contactIds=[], mediaType=ttypes.MediaType.VIDEO):
        return self.call.inviteIntoGroupCall(chatId, contactIds, mediaType)

    """Report"""

    def reportSpam(self, chatMid, memberMids=[], spammerReasons=[], senderMids=[], spamMessageIds=[], spamMessages=[]):
        return self.talk.reportSpam(chatMid, memberMids, spammerReasons, senderMids, spamMessageIds, spamMessages)
    
    def reportSpammer(self, spammerMid, spammerReasons=[], spamMessageIds=[]):
        return self.talk.reportSpammer(spammerMid, spammerReasons, spamMessageIds)

    def sendtag(self, to, text="",eto="", mids=[], isUnicode=False):
        arrData = ""
        arr = []
        mention = "@Alfino Nh "
        if mids == []:
            raise Exception("Invalid mids")
        if "@!" in text:
            if text.count("@!") != len(mids):
                raise Exception("Invalid mids")
            texts = text.split("@!")
            textx = ""
            unicode = ""
            if isUnicode:
                for mid in mids:
                    unicode += str(texts[mids.index(mid)].encode('unicode-escape'))
                    textx += str(texts[mids.index(mid)])
                    slen = len(textx) if unicode == textx else len(textx) + unicode.count('U0')
                    elen = len(textx) + 15
                    arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                    arr.append(arrData)
                    textx += mention
            else:
                for mid in mids:
                    textx += str(texts[mids.index(mid)])
                    slen = len(textx)
                    elen = len(textx) + 15
                    arrData = {'S':str(slen), 'E':str(elen - 4), 'M':mid}
                    arr.append(arrData)
                    textx += mention
            textx += str(texts[len(mids)])
        else:
            raise Exception("Invalid mention position")
        self.sendMessage(to, textx, {'MENTION': str('{"MENTIONEES":' + json.dumps(arr) + '}')}, 0)

    def listdata(self,to,text='',ps='',data=[]):
        k = len(data)//20
        for aa in range(k+1):
            if aa == 0:dd = '{}'.format(text,ps);no=aa
            else:dd = '{}'.format(text,ps);no=aa*20
            msgas = dd
            for i in data[aa*20 : (aa+1)*20]:
                no+=1
                if no == len(data):msgas+='\n{}. @!'.format(no)
                else:msgas+='\n{}. @!'.format(no)
            if data == []:pass
            else:self.sendtag(to, msgas,'{}'.format(ps), data[aa*20: (aa+1)*20])

    def changeVideoAndPictureProfile(self, pict, vids):
        try:
            files = {'file': open(vids, 'rb')}
            obs_params = self.genOBSParams({'oid': self.profile.mid, 'ver': '2.0', 'type': 'video', 'cat': 'vp.mp4'})
            data = {'params': obs_params}
            r_vp = self.server.postContent('https://obs-sg.line-apps.com/talk/vp/upload.nhn', data=data, files=files)
            if r_vp.status_code != 201:
                return "Failed update profile"
            self.updateProfilePicture(pict, 'vp')
            return "Success update profile"
        except Exception as e:
            raise Exception("Error change video and picture profile {}".format(str(e)))

    def sendText(self, Tomid, text):
        msg = ttypes.Message()
        msg.to = Tomid
        msg.text = text
        return self.talk.sendMessage(0, msg)

    def getRecentMessages(self, chatId, count=1001):
        return self.talk.getRecentMessagesV2(chatId,count)

    def cek(self,to):
    	gmid = self.profile.mid
    	try:self.inviteIntoGroup(to, [gmid]);has = "OK"
    	except:has = "NOT"
    	try:self.kickoutFromGroup(to, [gmid]);has1 = "OK"
    	except:has1 = "NOT"
    	if has == "OK":sil = "WARAS"
    	else:sil = "GELO"
    	if has1 == "OK":sil1 = "WARAS"
    	else:sil1 = "GELO"
    	if has == "OK" and has1 == "OK":
    		hsl="WARAS CUK 100%"
    	elif has == "NOT" and has1 == "OK":
    		hsl="GELO CUK.... [50%]"
    	elif has1 == "NOT" and has == "OK":
    		hsl="GELO CUK..... [50%]"
    	else: hsl ="[ STATUS ]\n[0%]"
    	self.sendMessage(to, "[ STATUS ]\n {}\nFree kick : {} \nThrow in : {}".format(hsl,sil1,sil))

    def forward(self, m):
        if m.toType == 2:
            to = m.to
        else:
            to = m._from
        if m.contentType == 1:
            try:
                if m.contentMetadata != {}:
                    path = self.downloadObjectMsg(m.id,'path','dataSeen/m.gif',True)
                    a = threading.Thread(target=self.sendGIF, args=(to,path,)).start()
            except:
                self.sendImageWithURL(to,'https://obs-sg.line-apps.com/talk/m/download.nhn?oid='+m.id)
        if m.contentType == 2:
            self.sendVideoWithURL(to,'https://obs-sg.line-apps.com/talk/m/download.nhn?oid='+m.id)
        if m.contentType == 3:
            self.sendAudioWithURL(to,'https://obs-sg.line-apps.com/talk/m/download.nhn?oid='+m.id)

    def timer_timing(self):
        sd = ''
        if datetime.now().hour > 1 and datetime.now().hour <10:sd+= 'Good Morning'
        if datetime.now().hour > 10 and datetime.now().hour <15:sd+= 'Good Afternoon'
        if datetime.now().hour > 15 and datetime.now().hour <18:sd+= 'Good Evening'
        if datetime.now().hour >= 18:sd+= 'Good Night'
        return sd

    """Spliters"""

    def splitText(self,text,lp=''):
        separate = text.split(" ")
        if lp == '':
            is_text = text.replace(separate[0]+" ","")
        elif lp == 's':
            is_text = text.replace(separate[0]+" "+separate[1]+" ","")
        else:
            is_text = text.replace(separate[0]+" "+separate[1]+" "+separate[2]+" ","")
        return is_text

    """Shop"""

    def getProduct(self, packageID, language, country):
        return self.shop.getProduct(packageID, language, country)

    def getActivePurchases(self, start, size, language, country):
        return self.shop.getActivePurchases(start, size, language, country)

    """Liff"""


    def issueLiffView(self, request):
        return self.liff.issueLiffView(request)
    
    def revokeToken(self, request):
        return self.liff.revokeToken(request)

    def sendTemplate(self,group,data):
        n1 = LiffChatContext(group)
        n2 = LiffContext(chat = n1)
        view = LiffViewRequest('1604066537-dl9GVZzo', n2)
        token = self.issueLiffView(view)
        url = 'https://api.line.me/message/v3/share'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer %s' % token.accessToken
        }
        data = {"messages":[data]}
        return requests.post(url, headers=headers, data=json.dumps(data))

    def sendCarousel(self,group,datas):
        data = json.dumps(datas)
        Nh1 = LiffChatContext(group)
        Nh2 = LiffContext(chat = Nh1)
        view = LiffViewRequest('1604066537-dl9GVZzo', Nh2)
        token = self.issueLiffView(view)
        url = 'https://api.line.me/message/v3/share'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer %s' % token.accessToken
        }
        return requests.post(url, data=data, headers=headers)

    def prefixLiff(self,to,text,load=False,label=None):
        if load == True:
            limg = 'https://i.imgur.com/DPQvsdx.gif'
        else:
            limg = "https://i.imgur.com/hT4U9vs.png"
        if label is not None:
            labels = label
        else:
            labels = "AlfinoNH-Bots"
        data = {
            "type": "text",
            "text": "{}".format(text),
            "sentBy": {
                "label": "%s"%labels,
                "iconUrl": '%s'%limg,
                "linkUrl": "line://nv/profilePopup/mid=u0be3650c6619cc078452ce5ec11a86db"}
        }
        return self.sendTemplate(to,data)
