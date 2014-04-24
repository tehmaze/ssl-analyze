from __future__ import print_function

import glob
import imp
import itertools
import os
import sys

import ssl_analyze.probe.base


PROBES = dict()


def load_probe(filename):
    global PROBES

    name = '.'.join([
        'ssl_analyze', 'probe',
        os.path.basename(os.path.splitext(filename)[0]),
    ])

    print('Loading {} from {}'.format(name, filename))
    try:
        module = imp.load_module(
            name,
            file(filename),
            filename,
            ('.py', 'U', imp.PY_SOURCE)
        )
        PROBES[name] = getattr(module, 'PROBES', [])
    except Exception, e:
        print('Loading {} failed "{}"'.format(name, e))


def load_probes(path=None):
    global PROBES

    base = sys.modules['ssl_analyze.probe.base'].__file__
    base = base.rstrip('co')  # .py[co] -> .py
    self = __file__.rstrip('co')
    path = path or os.path.dirname(base)

    for filename in glob.glob(os.path.join(path, '*.py')):
        if filename in [self, base]:
            continue
        elif os.path.basename(filename).startswith('_'):
            continue
        else:
            load_probe(filename)

    return list(itertools.chain(*(PROBES[name] for name in sorted(PROBES))))
