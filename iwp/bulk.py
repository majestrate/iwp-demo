import logging
import struct
from . import crypto
from . import protocol

class Fragments:


    log = logging.getLogger("Fragments")

    def __init__(self, h, mtu, data=None, frags=None, last=None):
        """
        fragment list for bulk transfer
        """
        self._mtu = mtu
        self._h = h
        self._frags = list()
        if data:
            while len(data) > mtu:
                self._frags.append(data[:mtu])
                data = data[mtu:]
            self._frags.append(data)
            self._last = len(data)
        else:
            while frags > 1:
                self._frags.append(None)
                frags -= 1
            self._frags.append(None)
            self._last = last

    def removeUs(self, q):
        del q[self._h]

    def msg(self):
        msg = bytearray()
        h = crypto.blake2b()
        while len(self._frags) > 0:
            h.update(self._frags[0])
            msg += self._frags[0]
            self._frags.pop(0)
        if h.digest() == self._h:
            return msg

    def initPkt(self):
        return struct.pack('>HHHH', protocol.PKT_INIT, self._mtu, len(self._frags), len(self._frags[-1])) + self._h


    def ackPkt(self):
        return struct.pack('>H', protocol.PKT_ACKS) + self._h

    def askPkt(self, fragno):
        if fragno < len(self._frags):
            return struct.pack('>HH', protocol.PKT_ASK, fragno) + self._h

    def givePkt(self, fragno):
        if fragno < len(self._frags):
            return struct.pack('>HH', protocol.PKT_GIVE, fragno) + self._h + self._frags[fragno]
        else:
            return struct.pack('>HH', protocol.PKT_NOPE, fragno) + self._h

    def donePkt(self):
        return struct.pack(">H", protocol.PKT_DONE) + self._h

    def recvFrag(self, frag, no):
        fl = len(self._frags)
        if no < fl:
            self.log.info("recv frag {}".format(no))
            if self._frags[no] is None:
                if fl == 1 + no:
                    if len(frag) == self._last:
                        self._frags[no] = frag
                    else:
                        self.log.warn("last frag bad size {}B, expected: {}B".format(len(frag), self._last))
                elif len(frag) == self._mtu:
                    self._frags[no] = frag
                else:
                    self.log.warn("bad frag size: {}".format(len(frag)))

    def frags(self):
        for no in range(len(self._frags)):
            if not self.hasFrag(no):
                yield no

    def hasFrag(self,no):
        return no < len(self._frags) and self._frags[no] is not None

    def completed(self):
        for frag in self._frags:
            if frag is None:
                return False
        return True
