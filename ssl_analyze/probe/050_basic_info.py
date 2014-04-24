import warnings

from ssl_analyze.probe.base import Probe


class BasicInfo(Probe):
    def probe(self, address, certificate, public_key):
        cert_info = dict(
            subject          = certificate.get_subject(),
            subject_hash     = certificate.get_subject_hash(),
            subject_hash_old = certificate.get_subject_hash_old(),
            issuer           = certificate.get_issuer(),
            issuer_hash      = certificate.get_issuer_hash(),
            issuer_hash_old  = certificate.get_issuer_hash_old(),
            serial           = certificate.get_serial_number(),
            not_after        = certificate.get_not_after(),
            not_before       = certificate.get_not_before(),
            extensions       = {},
            data             = certificate.to_pem(),
        )
        pkey_info = public_key.get_info()

        try:
            cert_info['signature_algorithm'] = certificate.get_signature_algorithm()
        except ValueError:
            pass

        for x in xrange(0, certificate.get_extension_count()):
            with warnings.catch_warnings():
                warnings.filterwarnings('error')
                try:
                    extension = certificate.get_extension(x)
                    cert_info['extensions'][extension.name] = extension.to_python()
                except Warning, w:
                    self.warning('certificate', str(w))
                except Exception, e:
                    print('Oops: {}'.format(e))

        return self.merge(dict(
            certificate=cert_info,
            public_key=pkey_info,
        ))


PROBES=(
    BasicInfo,
)
