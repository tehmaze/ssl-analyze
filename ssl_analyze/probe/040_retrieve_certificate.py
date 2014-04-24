import socket
import ssl

from ssl_analyze.probe.base import Probe
from ssl_analyze.crypto import parse_certificate


class RetrieveCertificate(Probe):
    timeout = 15

    def probe(self, address, certificates):
        if not address:
            # Nothing to do
            print 'Nothing to do'
            return

        connection = socket.create_connection(address, self.timeout)
        secured = ssl.wrap_socket(connection)
        certificates.add(parse_certificate(secured.getpeercert(True)))


PROBES = (
    RetrieveCertificate,
)
