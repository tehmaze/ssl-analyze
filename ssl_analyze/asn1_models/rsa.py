from pyasn1.type import namedtype, tag, univ


class Modulus(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x02)
    )


class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', Modulus()),
        namedtype.NamedType('exponent', univ.Integer()),
    )

    def get_bits(self):
        # The modulus is always padded with a NULL byte, so here we calculate
        # the number of data bytes and convert them to bits
        return 8 * (len(self.getComponentByName('modulus')._value) - 1)
