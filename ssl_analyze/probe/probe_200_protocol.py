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


STATE_ERROR, STATE_OK = range(2)


SSL_PROTOCOL = (
    (TLSv1_2_METHOD, 'TLSv1.2', (
            dict(status='warning'),
            dict(status='good', reason='No known security issues'),
        )
    ),
    (TLSv1_1_METHOD, 'TLSv1.1', (
            dict(status='warning'),
            dict(status='ok', reason='No known security issues'),
        )
    ),
    (TLSv1_METHOD, 'TLSv1.0', (
            dict(status='warning'),
            dict(status='ok', reason='Largely still secure'),
        )
    ),
    (SSLv3_METHOD, 'SSLv3', (
            dict(status='good', reason='SSLv3 is obsolete'),
            dict(
                status='warning',
                reason='Obsolete, most clients supporting SSLv3 also support '
                       'TLSv1.0, consider disabling SSLv3'
            ),
        )
    ),
    (SSLv2_METHOD, 'SSLv2', (
            dict(status='ok'),
            dict(status='error', reason='Insecure protocol'),
        )
    ),
)


class ProtocolSupport(Probe):
    timeout = 15

    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        support = []
        for version, name, status in SSL_PROTOCOL:
            log.debug('Connecting to {}:{} using protocol {}'.format(
                address[0],
                address[1],
                METHOD_NAME[version],
            ))
            try:
                remote = Connection(address, self.timeout)
            except socket.error, e:
                raise Probe.Skip('connection error; {}'.format(e))

            try:
                secure = remote.handshake(version, hostname=address[0])
            except socket.error, e:
                log.debug('Socket error: {}'.format(e))
                state = status[STATE_ERROR].copy()
                state['available'] = False
                state['error'] = str(e)
                if not 'reason' in state:
                    state['reason'] = str(e[1])
            else:
                state = status[STATE_OK].copy()
                state['available'] = True
                secure.close()
            support.append({name: state})

        self.merge(dict(analysis=dict(protocols=support)))

PROBES = (
    ProtocolSupport,
)
