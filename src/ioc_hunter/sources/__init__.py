"""Threat-intel source plugins.

Each source implements `Source.lookup(ioc_type, ioc_value)` and is composed
together by the async orchestrator in `engine.py`.
"""

from ioc_hunter.sources.base import Source, SourceResult, Verdict
from ioc_hunter.sources.threatfox import ThreatFoxSource
from ioc_hunter.sources.tor_exit import TorExitSource
from ioc_hunter.sources.urlhaus import URLhausSource

__all__ = [
    "Source",
    "SourceResult",
    "ThreatFoxSource",
    "TorExitSource",
    "URLhausSource",
    "Verdict",
]
