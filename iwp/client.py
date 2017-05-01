from . import crypto
from . import protocol
from . import session

class IWPClientProtocol(protocol.IWPProtocol):

    def __init__(self, remote, loop, handler, timeout=5):
        """
        :param remote: remote identity to connect to
        """
        super().__init__(None, loop)
        self._remote = remote
        self._transport = None
        self._timeout = timeout
        self._state = None
        self._handler = handler
        self._session = None

    def queueSend(self, msg):
        if self._session is not None:
            self._session.queue_send(msg)

    def connection_made(self, transport):
        """
        transport initialized
        """
        self._transport = transport
        self._resetAskForCookie()

    def datagram_received(self, data, addr):
        """
        inbound datagram obtained
        """
        remote = self._remote.addr()
        if addr != remote:
            self.log.info("drop from {}".format(addr))
            return
        self.log.info("got {} bytes from {}".format(len(data), addr[0]))
        if self._state == protocol.STATE_GET_COOKIE:
            self._state = protocol.STATE_GEN_COOKIE
            them = self._remote.pk()
            cookie = crypto.oneshotDecrypt(self._sk, them, data)
            r, h = crypto.genProofOfWork(cookie)
            pkt = crypto.oneshotEncrypt(self._sk, them, r+h)
            self._q1 = crypto.keyExchange(them, self._pk, cookie)
            self._q2 = crypto.keyExchange(them, self._pk, r)
            self._transport.sendto(pkt, addr)
            self._state = protocol.STATE_WAIT_START
            self.loop.call_later(self._timeout, self._resetAskForCookie)
        if self._state == protocol.STATE_WAIT_START:
            # got start reply
            self._state = protocol.STATE_ESTABLISHED
            self._session = session.Session(lambda x : crypto.decrypt(self._q1, x), self._handler)
            self._session.start(self.loop, lambda x : self._transport.sendto(crypto.encrypt(self._q2, x), addr))
            msg = crypto.rand(1024 * 8)
            self.loop.call_soon(self._session.queue_send, msg)
        elif self._state == protocol.STATE_ESTABLISHED:
            try:
                self._session.got_data(data)
            except ValueError:
                self.error_received('decrypt failed')

    def connection_lost(self, exc):
        """
        socket was closed
        """

    def error_received(self, exc):
        """
        socket got error
        """
        self.log.error(exc)

    def _resetAskForCookie(self):
        if self._state != protocol.STATE_ESTABLISHED:
            self._state = protocol.STATE_GET_COOKIE
            self._askForCookie()

    def _askForCookie(self):
        # generate ephemeral keypair
        self.log.info('generate key')
        self._sk, self._pk = crypto.genEphemeralKeys()
        # create hello packet
        pkt = self._pk + crypto.rand(128)
        remote = self._remote.addr()
        self.log.info('send hello to {}'.format(remote))
        self._transport.sendto(pkt, remote)
        self.loop.call_later(2, self._resetAskForCookie)
