
import logging
import struct

from . import bulk
from . import crypto
from . import protocol

class IWP0Session:
    """
    protocol version 0 session
    """
    log = logging.getLogger("IWPSession")

    timeout = 30

    mtu = 1248

    def __init__(self, decrypt, handler):
        self._decrypt = decrypt
        self._handler = handler

    def got_data(self, data):
        """
        handle data
        """
        data = self._decrypt(data)
        cmd = struct.unpack(">H", data[:2])[0]
        self.log.info("got {}B decrypted cmd={}".format(len(data), cmd))
        if cmd == protocol.PKT_INIT and len(data) == 72:
            mtu, frags, last = struct.unpack('>HHH', data[2:8])
            self._queue_recv(data[8:72], mtu, frags, last)
        elif cmd == protocol.PKT_ACKS and len(data) == 66:
            if self._pkt_sendask(self._queue_rx, data):
                self.log.info("sent ask")
            else:
                self.log.warn("missing sent ask")
        elif cmd == protocol.PKT_ASK and len(data) == 68:
            if self._pkt_recvask(self._queue_tx, data):
                self.log.info("recv ask")
            else:
                self.log.warn("missing recv ask")
        elif cmd == protocol.PKT_GIVE and len(data) > 72:
            if self._pkt_recvgive(self._queue_rx, data):
                pass


    def _pkt_sendask(self, q, data):
        h = data[2:]
        if h in q:
            s = q[h]
            for no in s.frags():
                pkt = s.askPkt(no)
                self.log.info("ask for {}:{}".format(crypto.encodeKey(h), no))
                self._reply(pkt)
            return True
        return False

    def _pkt_recvask(self, q, data):
        h = data[4:]
        if h in q:
            s = q[h]
            fragno = struct.unpack('>H', data[2:4])[0]
            pkt = s.givePkt(fragno)
            self._reply(pkt)
            return True
        return False

    def _pkt_recvgive(self, q, data):
        h = data[4:68]
        if h in q:
            s = q[h]
            fragno = struct.unpack('>H', data[2:4])[0]
            s.recvFrag(data[68:], fragno)
            if s.completed():
                self._reply(s.donePkt())
                self._handler(self, s.msg())
                s.removeUs(q)
            return True
        return False

    def _queue_recv(self, h, mtu, frags, last):
        f = bulk.Fragments(h=h, mtu=mtu, frags=frags, last=last)
        self._queue_rx[h] = f
        self.log.info("queued recv for {}".format(crypto.encodeKey(h)))
        self._loop.call_soon(self._ask_rx, self._queue_rx, f)

    def _ask_rx(self, q, f):
        if not f.completed():
            for no in f.frags():
                pkt = f.askPkt(no)
                self._reply(pkt)
            self._loop.call_later(0.1, self._ask_rx,q, f)

    def queue_send(self, data):
        """
        queue a transfer
        """
        h = crypto.blake2b(data).digest()
        f = bulk.Fragments(h=h, data=data, mtu=self.mtu)
        self._queue_tx[h] = f
        pkt = f.initPkt()
        self._reply(pkt)
        self.log.info("queue send of {}B".format(len(data)))

    def start(self, loop, reply):
        self.log.info("session start")
        self._loop = loop
        self._reply = reply
        self._queue_tx = dict()
        self._queue_rx = dict()

Session = IWP0Session
