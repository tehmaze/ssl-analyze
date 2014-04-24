from ssl_analyze.probe.base import Probe
from ssl_analyze.trust import TRUST_STORE


class AnalyzeCertificate(Probe):
    def probe(self, address, certificates):
        cert_infos = []
        trusted_issuers = []

        # We walk the certificate chain in reverse order
        for i, certificate in enumerate(reversed(certificates)):
            cert_info = dict()

            # If this is a self-signed certificate, skip all the other checks
            if certificate.get_subject_hash() == certificate.get_issuer_hash():
                cert_info['trust'] = dict(
                    status='warning',
                    reason='Self-signed certificate in chain',
                )

            else:
                if i > 1:
                    # Check if the issuer hash matches with the next
                    # certificate in the chain
                    i_hash = certificates[i - 1].get_issuer_hash()
                    s_hash = certificates[i - 0].get_subject_hash()

                    if i_hash != s_hash:
                        cert_info['trust'] = dict(
                            status='error',
                            reason='Invalid chain, {} is signed by {}'.format(
                                certificate.get_subject(),
                                certificate.get_issuer(),
                            )
                        )
                        continue  # skip to next certificate in chain


                # Now validate the chain of trust
                # TODO validate signatures
                issuer_hash = certificate.get_issuer_hash()
                if cert_infos and cert_infos[-1]['trust']['status'] != 'good':
                    cert_info['trust'] = dict(
                        status='unknown',
                        reason='Invalid chain',
                    )

                elif issuer_hash in TRUST_STORE:
                    cert_info['trust'] = dict(
                        status='good',
                        reason='In trust store',
                    )

                    # TODO test if CA
                    trusted_issuers.append(certificate.get_subject_hash())

                elif issuer_hash in trusted_issuers:
                    cert_info['trust'] = dict(
                        status='good',
                        reason='Sent by server',
                    )

                else:
                    cert_info['trust'] = dict(
                        status='unknown',
                        reason='Not implemented',
                    )

            cert_infos.append(cert_info)

        return self.merge(dict(
            analysis=dict(certificates=cert_infos[::-1]),
        ))


PROBES = (
    AnalyzeCertificate,
)
