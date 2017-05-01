from . import crypto
import logging
import os

class IWPProtocol:
    """
    base protocol for iwp sessions
    provides main logic after handshake is made
    """

    log = logging.getLogger("IWPProtocol")

    cookieSize = 32

    def __init__(self, keyfile, loop):
        self._keyfile = keyfile
        self.loop = loop

    def ensureKeys(self, host, port):
        keyfile = self._keyfile
        if not os.path.exists(keyfile):
            self.log.info("generating new keys at {}".format(keyfile))
            with open(keyfile, 'w') as fd:
                crypto.genKeys('{}:{}'.format(host,port), fd)

        with open(keyfile) as fd:
            self.log.info("loading keys from {}".format(keyfile))
            seed = crypto.loadKeys(fd)
        return crypto.keypair(seed)

    def queueSend(self, msg):
        pass


STATE_GET_COOKIE = 1
STATE_GEN_COOKIE = 2
STATE_WAIT_START = 3
STATE_ESTABLISHED = 4

PKT_INIT = 0
PKT_ACKS = 1 << 0
PKT_ASK = 1 << 1
PKT_GIVE = 1 << 2
PKT_NOPE = 1 << 3
PKT_DONE = 1 << 4
