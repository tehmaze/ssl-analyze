from collections import OrderedDict
import datetime

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import char, univ

from ssl_analyze.asn1_models import x509
from ssl_analyze.oids import friendly_oid

ASN1_GENERALIZEDTIME = (
    r'%Y%m%d%H%M%SZ',
    r'%Y%m%d%H%M%S%z',
)


def merge(a, b):
    '''Recursively merge two dictionaries.'''
    for key in set(a.keys()).union(b.keys()):
        if key in a and key in b:
            yield (key, dict(merge(a[key], b[key])))
        elif key in a:
            yield (key, a[key])
        else:
            yield (key, b[key])


def parse_asn1_time(date_string):
    print 'parse_time', date_string


def asn1_to_python(obj):
    # Basic values
    if obj is None:
        return None

    # X.520 ASN1 types
    elif isinstance(obj, x509.AccessDescription):
        method = obj['accessMethod']
        location = obj['accessLocation']
        return {
            friendly_oid(method): asn1_to_python(location)
        }

    elif isinstance(obj, x509.AlgorithmIdentifier):
        return x509.ID_KA_MAP.get(obj['algorithm'], obj['algorithm']._value)

    elif isinstance(obj, x509.AttributeValue):
        return asn1_to_python(obj.getComponent())

    elif isinstance(obj, x509.CertificateSerialNumber):
        return obj._value

    elif isinstance(obj, x509.DirectoryString):
        return obj.getComponent()._value

    elif isinstance(obj, x509.DistributionPoint):
        info = {}
        for attr in ('distributionPoint', 'reasons', 'cRLIssuer'):
            if obj[attr]:
                info[attr] = asn1_to_python(obj[attr])

        return info or None

    elif isinstance(obj, x509.GeneralName):
        names = [
            obj.componentType[x].getName()
            for x in xrange(len(obj.componentType))
        ]
        return dict(
            (name, asn1_to_python(obj.getComponentByName(name)))
            for name in names
            if obj.getComponentByName(name)  # Weed out empty values
        )

    elif isinstance(obj, x509.GeneralNames):
        return list(map(asn1_to_python, obj))

    elif isinstance(obj, x509.KeyIdentifier):
        return obj._value.encode('hex')

    elif isinstance(obj, x509.KeyPurposeId):
        return x509.ID_KP_MAP.get(obj._value)

    elif isinstance(obj, x509.Name):
        name = OrderedDict()
        for part in obj[0]:
            name.update(asn1_to_python(part))
        return name

    elif isinstance(obj, x509.PolicyInformation):
        return dict(
            policyIdentifier=str(obj['policyIdentifier']),
            policyQualifiers=map(asn1_to_python, obj['policyQualifiers']),
        )

    elif isinstance(obj, x509.PolicyQualifierInfo):
        return dict(
            policyQualifierId=str(obj['policyQualifierId']),
            qualifier=asn1_to_python(obj['qualifier']),
        )

    elif isinstance(obj, x509.RelativeDistinguishedName):
        atv = obj[0]  # AttributeTypeAndValue
        atv_type = atv['type']
        atv_value = atv['value']
        return {
            friendly_oid(atv_type): asn1_to_python(atv_value),
        }

    elif isinstance(obj, x509.Time):
        value = str(obj.getComponent())

        if obj.getName() == 'utcTime':
            # RFC5280 says: "For the purposes of this profile, UTCTime values
            # MUST be expressed in Greenwish Mean Time (Zulu) and MUST include
            # seconds (i.e., times are YYMMDDHHMMSSZ), even when the number of
            # seconds is zero.  Conforming systems MUST interpret the year
            # field (YY) as follows:
            #
            # Where YY is greater than or equal to 50, the year SHALL be
            # interpreted as 19YY; and
            #
            # Where YY is less than 50, the year SHALL be interpreted as 20YY."
            #
            # ... guess they have little trust in the current standard being
            # around for a longer period of time :-)
            year = int(value[:2])
            if 0 <= year < 50:
                century = '20'
            elif 50 <= year <= 99:
                century = '19'

            return datetime.datetime.strptime(century + value[:-1] + 'GMT',
                                              '%Y%m%d%H%M%S%Z')

        else:
            return datetime.datetime.strptime(value[:-1] + 'GMT',
                                              '%Y%m%d%H%M%S%Z')

    # Basic ASN1 types
    elif isinstance(obj, char.BMPString):
        return obj._value.decode('utf_16_be')

    elif isinstance(obj, char.UTF8String):
        return obj._value.decode('utf_8')

    elif isinstance(obj, univ.BitString):
        bits = list(obj)
        while len(bits) % 8:
            bits.append(0)

        return ''.join(
            chr(int(''.join(map(str, bits[i:i + 8])), 2))
            for i in xrange(0, len(bits))
        )

    elif isinstance(obj, univ.Choice):
        return asn1_to_python(obj.getComponent())

    elif isinstance(obj, univ.OctetString):
        return obj._value

    # Fallthrough
    else:
        print '???', obj
        return None
