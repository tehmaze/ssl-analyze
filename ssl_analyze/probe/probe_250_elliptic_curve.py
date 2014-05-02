import socket

from ssl_analyze.probe.base import Probe
from ssl_analyze.log import log
from ssl_analyze.tls.parameters import (
    CertificateStatusType,
    CipherSuite,
    ECCurveType,
    TLS_EC_CURVE_NAME,
    TLS_EC_CURVE_TYPE,
    TLS_EC_POINT_FORMAT,
)


class EllipticCurveSupport(Probe):
    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        support = {}
        self._check_elliptic_curves(address, support)
        self.merge(dict(analysis=dict(features=dict(elliptic_curves=support))))

    def _check_elliptic_curves(self, address, support):
        log.debug('Testing Elliptic Curves')
        ciphers = [getattr(CipherSuite, suite)
                   for suite in self.collected['ciphers']
                   if '_EC' in suite]

        if ciphers:
            log.debug('Discovered {} usable cipher suites using EC'.format(
                len(ciphers),
            ))
            elliptic_curves = TLS_EC_CURVE_NAME.keys()
            elliptic_curves.sort()
            ec_point_formats = TLS_EC_POINT_FORMAT.keys()
            ec_point_formats.sort()
        else:
            log.debug('Discovered no cipher suites using EC, skipping feature')
            raise Probe.Skip('no cipher suites supporting elliptic curves')

        try:
            secure = self._connect(address)
            for result in secure.handshake(
                    server_name=address[0],
                    cipher_suites=ciphers,
                    elliptic_curves=elliptic_curves,
                    ec_point_formats=ec_point_formats,
                ):
                pass

        except socket.error as error:
            raise Probe.Skip('Elliptic Curve Point Format handshake failed: {}'.format(
                error
            ))

        # Map out the names of the EC point formats supported by the server
        ec_point_formats = secure.server_hello.ec_point_formats
        support['point_format'] = filter(None, map(
            TLS_EC_POINT_FORMAT.get,
            ec_point_formats
        ))

        support['curve_name'] = []
        support['curve_type'] = None
        if secure.server_key_exchange is not None:
            support['curve_type'] = TLS_EC_CURVE_TYPE.get(
                secure.server_key_exchange.ec_curve_type,
                'unsupported',
            )

            if secure.server_key_exchange.ec_curve_type == ECCurveType.named_curve:
                # Find out what named curves the server supports
                self._probe_named_curves(address, ciphers, elliptic_curves, support)

    def _probe_named_curve(self, address, cipher_suites, elliptic_curve):
        log.debug('Testing Named Curve {} ({:04x})'.format(
            TLS_EC_CURVE_NAME.get(elliptic_curve, 'unknown'),
            elliptic_curve,
        ))
        secure = self._connect(address)
        ec_point_formats = TLS_EC_POINT_FORMAT.keys()
        for result in secure.handshake(
                server_name=address[0],
                cipher_suites=cipher_suites,
                elliptic_curves=[elliptic_curve],
                ec_point_formats=ec_point_formats,
            ):
            pass

        if secure.server_key_exchange.ec_curve_type != ECCurveType.named_curve:
            raise ValueError('Server did not select a named curve')

    def _probe_named_curves(self, address, cipher_suites, elliptic_curves, support):
        for elliptic_curve in elliptic_curves:
            try:
                self._probe_named_curve(address, cipher_suites, elliptic_curve)
            except Exception as error:
                log.debug('Elliptic Named Curve {} not supported: {}'.format(
                    TLS_EC_CURVE_NAME.get(elliptic_curve),
                    error,
                ))
            else:
                support['curve_name'].append(
                    TLS_EC_CURVE_NAME.get(elliptic_curve)
                )


PROBES = (
    EllipticCurveSupport,
)
