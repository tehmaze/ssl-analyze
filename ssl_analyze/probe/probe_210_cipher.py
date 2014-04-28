import ssl
import struct
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
from ssl_analyze.tls.connection import Connection
from ssl_analyze.tls.parameters import (
    dict_key,
    TLS_CIPHER_SUITE,
    TLS_CIPHER_SUITE_HEAD,
    TLS_CIPHER_SUITE_INFO,
    TLS_VERSION,
    AlertDescription,
    CipherSuite,
    ContentType,
    HandshakeType,
    Version,
)


def get_cipher_info(cipher):
    name = TLS_CIPHER_SUITE[cipher]
    info = dict(zip(TLS_CIPHER_SUITE_HEAD,
                    TLS_CIPHER_SUITE_INFO[cipher]))
    return (name, info)


class CipherSupport(Probe):
    timeout = 15

    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        support = []
        cipher_suites = []
        # Traverse all known ciphers bottom-up
        for cipher_suite in reversed(sorted(TLS_CIPHER_SUITE.keys())):
            try:
                remote = socket.create_connection(address)
            except socket.error, e:
                raise Probe.Skip('network error: {}'.format(e))

            try:
                secure = Connection(remote)
                # Construct accepted ciphers, also include a pseudo cipher
                cipher = [
                    cipher_suite,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                ]
                # Consume generator
                for result in secure.handshakeClientCert(address[0], cipher):
                    pass
            except Exception as e:
                log.debug('Cipher {} failed: {}'.format(
                    TLS_CIPHER_SUITE[cipher_suite],
                    e
                ))
            else:
                log.debug('Cipher {} accepted'.format(
                    TLS_CIPHER_SUITE[cipher_suite],
                ))
                cipher_suites.append(cipher_suite)
                remote.close()

        for cipher in cipher_suites:
            name, info = get_cipher_info(cipher)

            if info['encryption'] is None:
                info.update(dict(
                    status='error',
                    reason='Cipher offers no encryption'
                ))

            elif info['authentication'] is None:
                info.update(dict(
                    status='error',
                    reason='Cipher offers no authentication'
                ))

            elif info['encryption_bits'] < 112:
                info.update(dict(
                    status='error',
                    reason='Cipher offers weak encryption, only {} bits'.format(
                        info['encryption_bits'],
                    )
                ))

            elif info['encryption_bits'] < 128:
                info.update(dict(
                    status='warning',
                    reason='Cipher offers weak encryption, only {} bits'.format(
                        info['encryption_bits'],
                    )
                ))

            elif info['protocol'] == 'SSL':
                info.update(dict(
                    status='error',
                    reason='Cipher uses weak SSL implementation',
                ))

            elif info['encryption'].split('_')[0] == 'RC4':
                info.update(dict(
                    status='warning',
                    reason='RC4 encryption has known weaknesses',
                ))

            elif info['mac'] == 'MD5':
                info.update(dict(
                    status='error',
                    reason='MD5 macs are weak and easy to brute force',
                ))

            else:
                info['status'] = 'good'

            support.append({name: info})

        '''
        log.debug('Analyzing {} ciphers'.format(len(ciphers)))
        for cipher in ciphers:
            if cipher in CIPHERS:
                support.append({cipher: CIPHERS[cipher].status()})
            else:
                support.append({cipher: dict(
                    status='uknown',
                    reason='not supported')
                })

        try:
            secure.close()
        except:
            pass
        '''

        self.merge(dict(analysis=dict(ciphers=support)))

PROBES = (
    CipherSupport,
)
