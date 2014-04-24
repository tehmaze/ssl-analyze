from collections import defaultdict
from ssl_analyze.probe.base import Probe
from ssl_analyze.config import CONFIG


class AnalyzePubKey(Probe):
    def setup(self):
        self.config = CONFIG.get('analyze', {}).get('public_key', {})

    def probe(self, address, certificates):
        public_key = certificates[0].get_public_key()
        key_info = dict()
        warnings = defaultdict(list)
        errors   = defaultdict(list)

        key_bits = public_key.get_bits()
        key_type = public_key.get_type()
        key_conf = self.config.get('key_sizes', {}).get(key_type)

        if key_conf:
            key_info['type'] = dict(status='good')
            if key_bits < key_conf['bits']:
                key_info['bits'] = dict(
                    status='error',
                    reason='{} bits {} key is less than {}: {}'.format(
                        key_bits,
                        key_type,
                        key_conf['bits'],
                        key_conf['docs'],
                    )
                )

            else:
                key_info['bits'] = dict(status='good')

        else:
            key_info['type'] = dict(
                status='error',
                reason='Unsupported public key algorithm',
            )
            key_info['bits'] = dict(
                status='unknown',
                reason='Unsupported public key algorithm',
            )

        return self.merge(dict(
            analysis=dict(public_key=key_info),
            errors=errors,
            warnings=warnings,
        ))


PROBES = (
    AnalyzePubKey,
)
