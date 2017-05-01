import logging
import time

log = logging.getLogger("IWP")

logging.basicConfig(level=logging.INFO)
log.info("starting up")

from iwp.client import IWPClientProtocol as ClientProtocol
from iwp.server import IWPServerProtocol as ServerProtocol
from iwp import crypto
from iwp.identity import Identity

#log.info("test proof of work")
#begin = time.time()
#powseed = 'test'.encode('ascii')
#r, h = crypto.genProofOfWork(powseed)
#assert crypto.verifyProofOfWork(powseed, r, h)
#log.info("proof of work took {}s".format(time.time() - begin))

import asyncio
import os
import socket
import sys

keyfile = "node.secret"
identfile = "node.public"
server = sys.argv[1].lower() == 'server'
pubaddr = server and sys.argv[2] or ''
pubport = 1488

loop = asyncio.get_event_loop()

global transport
global protocol


if server:
    def gotMessage(session, msg):
        session.queue_send(msg)

    ep = loop.create_datagram_endpoint(
        protocol_factory=lambda : ServerProtocol(keyfile, identfile, gotMessage, loop),
        local_addr=(pubaddr, pubport))
else:
    with open(sys.argv[1]) as fd:
        ident = Identity(fd)

    def gotMessage(session, msg):
        session.queue_send(msg)

    ep = loop.create_datagram_endpoint(
        protocol_factory=lambda : ClientProtocol(ident, loop, gotMessage),
        local_addr=(pubaddr, 0)
    )
transport, protocol= loop.run_until_complete(ep)

try:
    log.info("Running")
    loop.run_forever()
finally:
    transport.close()
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()
