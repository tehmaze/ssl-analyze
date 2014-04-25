import warnings

from ssl_analyze.probe.base import Probe


class BasicInfo(Probe):
    def probe(self, address, certificates):
        cert_infos = []
        for certificate in certificates:
            cert_info = dict(
                data                 = certificate.to_pem(),
                extensions           = {},
                extension_count      = certificate.get_extension_count(),
                issuer               = certificate.get_issuer(),
                issuer_hash          = certificate.get_issuer_hash(),
                issuer_hash_old      = certificate.get_issuer_hash_old(),
                issuer_str           = certificate.get_issuer_str(),
                not_after            = certificate.get_not_after(),
                not_before           = certificate.get_not_before(),
                serial               = certificate.get_serial_number(),
                signature            = certificate.get_signature().encode('hex'),
                signature_algorithm  = certificate.get_signature_algorithm(),
                subject              = certificate.get_subject(),
                subject_hash         = certificate.get_subject_hash(),
                subject_hash_old     = certificate.get_subject_hash_old(),
                subject_str          = certificate.get_subject_str(),
            )
            public_key = certificate.get_public_key()
            cert_info['public_key'] = public_key.get_info()

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

            cert_infos.append(cert_info)

        return self.merge(dict(
            certificates=cert_infos,
        ))


PROBES=(
    BasicInfo,
)
