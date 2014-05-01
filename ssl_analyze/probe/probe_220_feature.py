import socket

from ssl_analyze.probe.base import Probe
from ssl_analyze.log import log
from ssl_analyze.tls.connection import Connection
from ssl_analyze.tls.parameters import CipherSuite


class CipherSupport(Probe):
    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        support = {}
        support['session'] = False
        self._check_features(address, support)
        if support['session']:
            self._check_feature_session_resumption(address, support)

        self.merge(dict(analysis=dict(features=support)))

    def _connect(self, address):
        try:
            remote = socket.create_connection(address)
            return Connection(remote)
        except socket.error as error:
            raise Probe.Skip('network error: {}'.format(error))

    def _check_feature_session_resumption(self, address, support):
        log.debug('Testing session resumption')
        session_id = bytearray(support['session_id'].decode('hex'))
        secure = self._connect(address)

        try:
            cipher = CipherSuite.filter(key_exchange=('RSA', 'DH'))
            for result in secure.resume(
                    server_name=address[0],
                    cipher_suites=cipher,
                    session_id=session_id,
                ):
                pass

            if secure.server_hello.session_id == session_id:
                support['session_resumed'] = True
            else:
                support['session_resumed'] = False

            secure.close()

        except socket.error as error:
            raise Probe.Skip('network error: {}'.format(error))


    def _check_features(self, address, support):
        log.debug('Testing features')
        secure = self._connect(address)

        try:
            cipher = CipherSuite.filter(key_exchange=('RSA', 'DH'))
            cipher.append(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            for result in secure.handshake(
                    server_name=address[0],
                    cipher_suites=cipher,
                    compression_methods=[0, 1],
                ):
                pass

            # Test features from ServerHello report
            hello = secure.server_hello
            support['compression'] = hello.compression_method != 0
            support['secure_renegotiation'] = hello.secure_renegotiation
            support['session'] = bool(hello.session_id)
            if support['session']:
                support['session_id'] = str(hello.session_id).encode('hex')
            else:
                support['session_id'] = None
            support['session_ticket'] = bool(hello.session_ticket)

            secure.close()
        except socket.error as error:
            raise Probe.Skip('network error: {}'.format(error))


PROBES = (
    CipherSupport,
)
