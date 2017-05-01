from . import crypto
from . import identity
from . import protocol
from . import session

class IWPServerProtocol(protocol.IWPProtocol):

    def __init__(self, keyfile, identfile, handler, loop):
        super().__init__(keyfile, loop)
        self._sessions = dict()
        self._cookies = dict()
        self._identfile = identfile
        self._handler = handler

    def connection_lost(self, exc):
        self.log.info("connection lost: {}".format(exc))

    def connection_made(self, transport):
        """
        transport initialized
        """
        self.tranport = transport
        sockname = transport.get_extra_info('sockname')
        self.log.info('server bound to {}'.format(sockname))
        self._sk, self._pk = self.ensureKeys(sockname[0], sockname[1])
        self.log.info('our pubkey is {}'.format(crypto.encodeKey(self._pk)))
        self.identity = identity.Identity(host=sockname[0], port=sockname[1], pk=self._pk)
        with open(self._identfile, 'w') as fd:
            self.identity.save(fd)

    def datagram_received(self, data, addr):
        """
        inbound datagram obtained
        """
        self.log.info("got {} bytes from {}".format(len(data), addr[0]))
        self._handlePacketFrom(data, addr)

    def _handlePacketFrom(self, pktdata, fromaddr):
        isnew = fromaddr not in self._sessions
        hascookie = fromaddr in self._cookies
        if isnew and not hascookie and len(pktdata) >= 128:
            them = pktdata[:32]
            cookie = crypto.rand(32)
            self._cookies[fromaddr] = (cookie, them)
            pkt = crypto.oneshotEncrypt(self._sk, them, cookie)
            self.tranport.sendto(pkt, fromaddr)
        elif isnew and len(pktdata) > 64:
            if fromaddr in self._cookies:
                cookie, them = self._cookies[fromaddr]
                plain = crypto.oneshotDecrypt(self._sk, them, pktdata)
                r = plain[0:32]
                h = plain[32:64]
                if crypto.verifyProofOfWork(cookie, r, h):
                    # inbound key
                    q1 = crypto.keyExchange(self._pk, them, cookie)
                    # outbound key
                    q2 = crypto.keyExchange(self._pk, them, r)
                    s = session.Session(lambda x : crypto.decrypt(q2, x), self._handler)
                    self._sessions[fromaddr] = s
                    s.start(self.loop, lambda x : self.tranport.sendto(crypto.encrypt(q1, x), fromaddr))
                    return
        if not isnew:
            s = self._sessions[fromaddr]
            s.got_data(pktdata)
