import ssl
import socket

from ssl_analyze.probe.base import Probe
from ssl_analyze.log import log
from ssl_analyze.network import (
    Connection,
    METHOD_NAME,
    SSLv2_METHOD,
    SSLv3_METHOD,
    SSLv23_METHOD,
    TLSv1_METHOD,
    TLSv1_1_METHOD,
    TLSv1_2_METHOD,
)


class CipherSupport(Probe):
    timeout = 15

    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        support = {}
        try:
            remote = Connection(address)
        except socket.error, e:
            raise Probe.Skip('network error: {}'.format(e))

        try:
            secure = remote.handshake(SSLv23_METHOD)
        except socket.error, e:
            raise Probe.Skip('network error: {}'.format(e))

        try:
            secure.renegotiate()
            secure.do_handshake(SSLv23_METHOD)
            support['secure_renegotiation'] = True
        except Exception, e:
            log.info('Secure renegotiation failed: {}'.format(e))
            support['secure_renegotiation'] = False

        try:
            support['servername'] = secure.get_servername()
        except Exception, e:
            log.info('Server name fetch failed: {}'.format(e))
            support['servername'] = False

        try:
            support['session'] = secure.get_session()
            print support['session']
        except Exception, e:
            log.info('Session fetch failed: {}'.format(e))
            support['session'] = False
        

        try:
            secure.close()
        except:
            pass

        self.merge(dict(analysis=dict(features=support)))

PROBES = (
    CipherSupport,
)
