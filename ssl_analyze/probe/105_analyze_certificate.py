from ssl_analyze.probe.base import Probe


class AnalyzeCertificate(Probe):
    def probe(self, address, certificates):
        cert_infos = []
        for certificate in certificates:
            cert_info = dict()

            # If this is a self-signed certificate, skip all the other checks
            if certificate.get_subject_hash() == certificate.get_issuer_hash():
                cert_info['trust'] = dict(
                    status='warning',
                    reason='Self-signed certificate',
                )

            else:
                pass

        return self.merge(dict(
            analysis=dict(certificate=cert_info),
        ))


PROBES = (
    AnalyzeCertificate,
)
