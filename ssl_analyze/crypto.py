import hashlib
import warnings

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ

from ssl_analyze.asn1_models import (
    dsa,
    rsa,
    x509,
    x509_extension,
)
from ssl_analyze.log import log
from ssl_analyze.oids import friendly_oid


def hash_name(name):
    hashed = hashlib.sha1()
    digest = hashed.digest()
    return '{:08x}'.format((
        ord(digest[0]) |
        ((ord(digest[1]) << 8))  |
        ((ord(digest[2]) << 16)) |
        ((ord(digest[4]) << 24))
        ) & 0xffffffffL
    )


def parse_pem(obj, marker):
    '''Retrieve all maching data blocks in a PEM formatted file.'''

    if isinstance(obj, basestring):
        obj = obj.splitlines()

    begin_marker = '-----BEGIN {}-----'.format(marker.upper())
    end_marker = '-----END {}-----'.format(marker.upper())
    keep = 0
    data = []
    for line in obj:
        line = line.strip()
        if keep:
            if line == end_marker:
                yield ''.join(data).decode('base64')
                data = []
                keep = 0
            else:
                data.append(line)

        elif line == begin_marker:
            keep = 1


def parse_certificate(substrate):
    decoded, leftover = der_decoder.decode(
        substrate,
        asn1Spec=x509.Certificate()
    )
    assert not leftover
    return Certificate(decoded)


class Sequence(object):
    spec = None

    def __init__(self, sequence):
        if isinstance(sequence, basestring):
            self.sequence = der_decoder.decode(sequence, asn1Spec=self.spec)
        else:
            self.sequence = sequence

    def to_pem(self, name=None):
        name = name or self.__class__.__name__.upper()
        data = []
        data.append('-----BEGIN {}-----'.format(name))
        data.append(der_encoder.encode(self.sequence).encode('base64').rstrip())
        data.append('-----END {}-----'.format(name))
        return '\n'.join(data)


class Certificate(Sequence):
    spec = x509.Certificate()

    def __init__(self, sequence):
        super(Certificate, self).__init__(sequence)
        self.tbsCertificate = self.sequence.getComponentByName('tbsCertificate')
        self.validity = self.tbsCertificate.getComponentByName('validity')
        self.extensions = self.get_extensions()

    def get_extension(self, index):
        return Extension(
            self.sequence['tbsCertificate']['extensions'][index]
        )

    def get_extensions(self):
        if hasattr(self, 'extensions'):
            return self.extensions
        else:
            extensions = {}
            for i in xrange(self.get_extension_count()):
                extension = self.get_extension(i)
                if extension is not None:
                    extensions[extension.name] = extension
            return extensions

    def get_extension_count(self):
        try:
            return len(self.tbsCertificate.getComponentByName('extensions'))
        except PyAsn1Error:
            return 0

    def get_issuer(self):
        return self.tbsCertificate.getComponentByName('issuer').to_python()

    def get_issuer_der(self):
        return der_encoder.encode(
            self.tbsCertificate.getComponentByName('issuer')
        )

    def get_issuer_hash(self):
        #return hash_name(self.get_issuer())
        return hashlib.sha1(self.get_issuer_der()).hexdigest()

    def get_issuer_hash_old(self):
        return hashlib.md5(self.get_issuer_der()).hexdigest()

    def get_issuer_str(self):
        return self.tbsCertificate.getComponentByName('issuer').to_rfc2253()

    def get_not_after(self):
        return self.validity.getComponentByName('notAfter').to_python()

    def get_not_before(self):
        return self.validity.getComponentByName('notBefore').to_python()

    def get_public_key(self):
        return PublicKey(
            self.tbsCertificate.getComponentByName('subjectPublicKeyInfo')
        )

    def get_serial_number(self):
        self.tbsCertificate.getComponentByName('serialNumber').to_python()

    def get_signature(self):
        return self.sequence.getComponentByName('signatureValue').to_bytes()

    def get_signature_algorithm(self):
        signature = self.sequence.getComponentByName('signatureAlgorithm')
        algorithm = signature['algorithm']
        return friendly_oid(algorithm)

    def get_subject(self):
        return self.tbsCertificate.getComponentByName('subject').to_python()

    def get_subject_der(self):
        return der_encoder.encode(
            self.tbsCertificate.getComponentByName('subject')
        )

    def get_subject_hash(self):
        return hashlib.sha1(self.get_subject_der()).hexdigest()

    def get_subject_hash_old(self):
        return hashlib.md5(self.get_subject_der()).hexdigest()

    def get_subject_str(self):
        return self.tbsCertificate.getComponentByName('subject').to_rfc2253()


class PublicKey(Sequence):
    spec = x509.SubjectPublicKeyInfo()

    def __init__(self, sequence):
        super(PublicKey, self).__init__(sequence)

        algorithm = self.sequence.getComponentByName('algorithm')['algorithm']
        self.algorithm = x509.ID_KA_MAP.get(algorithm)

        if self.algorithm is None:
            raise TypeError('Unable to handle {} keys'.format(str(algorithm)))

        key_bits = self.sequence.getComponentByName('subjectPublicKey')
        key_type = self.get_type()

        if key_type == 'DSA':
            self.key, _ = self._get_DSA_public_key(key_bits)
        elif key_type == 'RSA':
            self.key, _ = self._get_RSA_public_key(key_bits)

    def get_bits(self):
        return self.key.get_bits()

    def get_info(self):
        key_type = self.get_type()
        key_info = dict(
            bits=self.get_bits(),
            data=self.to_pem(),
            type=key_type,
        )

        if key_type == 'DSA':
            key_info.update(dict(
                modulus='{:x}'.format(self.key._value),
            ))

        elif key_type == 'RSA':
            key_info.update(dict(
                modulus=self.key.getComponentByName('modulus')._value.encode('hex'),
                exponent=self.key.getComponentByName('exponent')._value,
            ))

        return key_info

    def get_type(self):
        return self.algorithm.split('+')[0]

    def to_pem(self):
        return super(PublicKey, self).to_pem(
            '{} PUBLIC KEY'.format(
                self.get_type()
            )
        )

    def _get_DSA_public_key(self, key_bits):
        key = dsa.DSAPublicKey()
        pub = key_bits.to_bytes()
        return der_decoder.decode(pub, asn1Spec=key)

    def _get_RSA_public_key(self, key_bits):
        key = rsa.RSAPublicKey()
        pub = key_bits.to_bytes()
        return der_decoder.decode(pub, asn1Spec=key)


class Extension(Sequence):
    decoders = dict(
        authorityInfoAccess    = x509_extension.AuthorityInfoAccess(),
        authorityKeyIdentifier = x509_extension.AuthorityKeyIdentifier(),
        basicConstraints       = x509_extension.BasicConstraints(),
        certificatePolicies    = x509_extension.CertificatePolicies(),
        cRLDistributionPoints  = x509_extension.CRLDistributionPoints(),
        extKeyUsage            = x509_extension.ExtKeyUsageSyntax(),
        issuerAltName          = x509_extension.IssuerAltName(),
        keyUsage               = x509_extension.KeyUsage(),
        netscapeCertType       = x509_extension.NetscapeCertType(),
        netscapeComment        = x509_extension.NetscapeComment(),
        subjectAltName         = x509_extension.SubjectAltName(),
        subjectKeyIdentifier   = x509_extension.SubjectKeyIdentifier(),
    )

    def __init__(self, sequence):
        self.sequence = sequence

        self.name = friendly_oid(self.sequence['extnID'])
        self.critical = bool(self.sequence['critical']._value)

        log.debug('Parsing extension {}'.format(self.name))
        if self.name in self.decoders:
            self.encoded = self.sequence.getComponentByName('extnValue')._value
            self.decoded = der_decoder.decode(
                self.encoded,
                asn1Spec=self.decoders[self.name]
            )[0]

        else:
            warnings.warn('Not able to decode extension {}'.format(self.name))
            self.decoded = None

    def to_python(self):
        if self.decoded is None:
            return None
        else:
            try:
                return self.decoded.to_python()
            except AttributeError, e:
                log.error('Oops: {}'.format(e))
                return None
