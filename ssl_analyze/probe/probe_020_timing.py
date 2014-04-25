import datetime
from ssl_analyze.probe.base import Probe


class Timing(Probe):
    def probe(self, address, certificates):
        return self.merge(dict(
            analysis=dict(timing=dict(start=datetime.datetime.now())),
        ))


PROBES = (
    Timing,
)
