import hashlib
import warnings

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ

from ssl_analyze.asn1_models import dsa, rsa, x509
from ssl_analyze.oids import friendly_oid
from ssl_analyze.util import asn1_to_python


def hash_name(name):
    hashed = hashlib.sha1()
    print name
    digest = hashed.digest()
    print digest
    return '{:08x}'.format((
        ord(digest[0]) |
        ((ord(digest[1]) << 8))  |
        ((ord(digest[2]) << 16)) |
        ((ord(digest[4]) << 24))
        ) & 0xffffffffL
    )


def parse_pem(obj, marker):
    '''Retrieve all maching data blocks in a PEM formatted file.'''
    keep = 0
    begin_marker = '-----BEGIN {}-----'.format(marker.upper())
    end_marker = '-----END {}-----'.format(marker.upper())
    data = []
    for line in obj:
        line = line.rstrip()
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

    def get_extension(self, index):
        return Extension(
            self.sequence['tbsCertificate']['extensions'][index]
        )

    def get_extension_count(self):
        try:
            return len(self.tbsCertificate.getComponentByName('extensions'))
        except PyAsn1Error:
            return 0

    def get_issuer(self):
        return asn1_to_python(
            self.tbsCertificate.getComponentByName('issuer')
        )

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
        return '/'.join('='.join([k, v])
                        for k, v in self.get_issuer().iteritems())

    def get_not_after(self):
        return asn1_to_python(
            self.validity.getComponentByName('notAfter')
        )

    def get_not_before(self):
        return asn1_to_python(
            self.validity.getComponentByName('notBefore')
        )

    def get_public_key(self):
        return PublicKey(
            self.tbsCertificate.getComponentByName('subjectPublicKeyInfo')
        )

    def get_serial_number(self):
        return asn1_to_python(
            self.tbsCertificate.getComponentByName('serialNumber')
        )

    def get_signature(self):
        return self.sequence.getComponentByName('signatureValue').to_bytes()

    def get_signature_algorithm(self):
        return asn1_to_python(
            self.sequence.getComponentByName('signatureAlgorithm')
        )

    def get_subject(self):
        return asn1_to_python(
            self.tbsCertificate.getComponentByName('subject')
        )

    def get_subject_der(self):
        return der_encoder.encode(
            self.tbsCertificate.getComponentByName('subject')
        )

    def get_subject_hash(self):
        #return hash_name(self.get_subject())
        return hashlib.sha1(self.get_subject_der()).hexdigest()

    def get_subject_hash_old(self):
        return hashlib.md5(self.get_subject_der()).hexdigest()

    def get_subject_str(self):
        return '/'.join('='.join([k, v])
                        for k, v in self.get_subject().iteritems())


class PublicKey(Sequence):
    #spec = univ.BitString()
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
    asn1Spec = dict(
        authorityInfoAccess    = x509.AuthorityInfoAccess(),
        authorityKeyIdentifier = x509.AuthorityKeyIdentifier(),
        basicConstraints       = x509.BasicConstraints(),
        certificatePolicies    = x509.CertificatePolicies(),
        cRLDistributionPoints  = x509.CRLDistributionPoints(),
        extKeyUsage            = x509.ExtKeyUsageSyntax(),
        issuerAltName          = x509.IssuerAltName(),
        keyUsage               = x509.KeyUsage(),
        subjectAltName         = x509.SubjectAltName(),
        subjectKeyIdentifier   = x509.SubjectKeyIdentifier(),
    )

    def __init__(self, sequence):
        self.sequence = sequence

        self.name = friendly_oid(self.sequence['extnID'])
        self.critical = bool(self.sequence['critical']._value)

        print 'parsing', self.name
        if self.asn1Spec.has_key(self.name):
            self.decoded = der_decoder.decode(
                self.get_data(),
                asn1Spec=self.asn1Spec[self.name],
            )[0]

        else:
            warnings.warn('Not able to decode extension {}'.format(self.name))
            self.decoded = None

    def get_data(self):
        return self.sequence['extnValue']._value

    def to_python(self):
        if self.name == 'authorityInfoAccess':
            access = dict()
            for info in self.decoded:
                access.update(asn1_to_python(info))
            return access

        elif self.name == 'authorityKeyIdentifier':
            return dict(
                keyIdentifier=asn1_to_python(
                    self.decoded.getComponentByName('keyIdentifier')
                ).encode('hex'),
                authorityCertIssuer=asn1_to_python(
                    self.decoded.getComponentByName('authorityCertIssuer')
                ),
                authorityCertSerialNumber=asn1_to_python(
                    self.decoded.getComponentByName('authorityCertSerialNumber')
                ),
            )

        elif self.name == 'basicConstraints':
            return dict(
                ca=bool(self.decoded.getComponentByName('cA')),
                path_len=self.decoded.getComponentByName('pathLenConstraint')._value,
            )

        elif self.name == 'certificatePolicies':
            return map(asn1_to_python, self.decoded)

        elif self.name == 'cRLDistributionPoints':
            return map(asn1_to_python, self.decoded)

        elif self.name == 'extKeyUsage':
            return map(asn1_to_python, self.decoded)

        elif self.name == 'issuerAltName':
            return map(asn1_to_python, self.decoded)

        elif self.name == 'keyUsage':
            usage = []
            for bit, enable in enumerate(self.decoded._value):
                if enable:
                    usage.append(self.decoded.namedValues[bit][0])
            return usage

        elif self.name == 'subjectAltName':
            return map(asn1_to_python, self.decoded)

        elif self.name == 'subjectKeyIdentifier':
            return asn1_to_python(self.decoded).encode('hex')
