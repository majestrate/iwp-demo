
from . import crypto

class Identity:

    def __init__(self, fd=None, host=None, port=None, pk=None):
        """
        load identity from file descriptor
        """
        if fd:
            while True:
                line = fd.readline()
                if len(line) == 0:
                    break
                if line.startswith('host:'):
                    self._host = line[5:].strip()
                elif line.startswith('port:'):
                    self._port = int(line[5:].strip())
                elif line.startswith('pk:'):
                    self._pk = crypto.decodeKey(line[3:].strip())
        else:
            self._host = host
            self._port = int(port)
            self._pk = pk

    def host(self):
        """
        return remote's host/ip
        """
        return self._host

    def port(self):
        """
        return remote's port
        """
        return self._port

    def addr(self):
        return self.host(), self.port()

    def pk(self):
        """
        return remote's pubkey as bytearray
        """
        return self._pk

    def save(self, fd):
        fd.write("host:")
        fd.write(self.host())
        fd.write('\n')
        fd.write('port:')
        fd.write('{}'.format(self.port()))
        fd.write('\n')
        fd.write('pk:')
        fd.write(crypto.encodeKey(self.pk()))
        fd.write('\n')
