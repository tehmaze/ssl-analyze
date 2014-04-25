import socket
import ssl

from ssl_analyze.probe.base import Probe
from ssl_analyze.crypto import parse_certificate, parse_pem
from ssl_analyze.log import log


class RetrieveCertificate(Probe):
    timeout = 15

    def probe(self, address, certificates):
        if not address:
            # Nothing to do
            log.debug('Nothing to do, no address provided')
            return
        else:
            log.info('Fetching certificate from %s:%d' % address)

        response = ssl.get_server_certificate(
            address,
            ssl_version=ssl.PROTOCOL_SSLv23,
        )
        log.debug('Got {} bytes of certificate data'.format(len(response)))
        log.debug('CERTIFICATE' in response)
        for substrate in parse_pem(response, 'CERTIFICATE'):
            certificate = parse_certificate(substrate)
            log.info('Retrieved {}'.format(certificate.get_subject_str()))
            certificates.add(certificate)


PROBES = (
    RetrieveCertificate,
)
