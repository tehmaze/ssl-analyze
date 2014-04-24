import json
import sys

from pyasn1.type import univ
from pyasn1.codec.der import decoder as der_decoder
import OpenSSL.crypto

from ssl_analyze.crypto import parse_pem, parse_certificate
from ssl_analyze.probe.loader import load_probes


class Analyzer(object):
    def __init__(self):
        self.probes = load_probes()

    def analyze_certificate(self, data, **kwargs):
        '''Analyze a single certificate.'''

        info = {}
        certificates = map(parse_certificate,
                           parse_pem(data.splitlines(), 'CERTIFICATE'))

        for Probe in self.probes:
            print('Running {!r}'.format(Probe))
            try:
                probe = Probe(info)
                probe.probe(None, certificates)
                probe.merge(dict(tests=[repr(Probe)]))
            except Exception, e:
                print('Oops: {}'.format(e))
                raise

        try:
            print json.dumps(
                info,
                default=self._json_handler,
                indent=2,
                sort_keys=True,
            )
        except UnicodeDecodeError:
            import pprint
            print pprint.pprint(info)

    def _json_handler(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()  # for datetime.* objects
        elif isinstance(obj, univ.ObjectIdentifier):
            return str(obj)
        else:
            raise TypeError(
                'Object of type {} with value {} is not supported'.format(
                    type(obj), repr(obj)
                )
            )
