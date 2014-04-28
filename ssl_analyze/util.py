from collections import OrderedDict, MutableSet
import datetime
import os

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


def get_random_bytes(size):
    b = bytearray(os.urandom(size))
    assert len(b) == size
    return b


class OrderedSet(MutableSet):
    def __init__(self, iterable=None):
        self.end = end = []
        end += [None, end, end]  # sentinel
        self.map = {}

        if iterable is not None:
            self |= iterable

    def __len__(self):
        return len(self.map)

    def __contains__(self, key):
        return key in self.map

    def add(self, key):
        if key not in self.map:
            end = self.end
            cur = end[1]
            cur[2] = end[1] = self.map[key] = [key, cur, end]

    def discard(self, key):
        if key in self.map:
            key, prv, nxt = self.map.pop(key)
            prv[2] = nxt
            nxt[1] = prv

    def __iter__(self):
        end = self.end
        cur = end[2]
        while cur is not end:
            yield cur[0]
            cur = cur[2]

    def __reversed__(self):
        end = self.end
        cur = end[1]
        while cur is not end:
            yield cur[0]
            cur = cur[1]

    def pop(self, last=True):
        if not self:
            raise KeyError('Empty set')

        key = self.end[1][0] if last else self.end[2][0]
        self.discard(key)
        return key

    def __repr__(self):
        if not self:
            return '%s()' % (self.__class__.__name__,)
        else:
            return '%s(%r)' % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        else:
            return set(self) == set(other)
