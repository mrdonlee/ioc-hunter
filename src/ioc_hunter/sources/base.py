"""Abstract threat-intel source and shared result model."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import httpx

from ioc_hunter.core.types import IOCType


class Verdict(StrEnum):
    """A source's qualitative judgement on an IOC."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SourceResult:
    """One source's response for one IOC.

    `score` is a 0.0-1.0 confidence on the verdict, normalized to the
    source's own scale. The scorer combines `score * source.weight` across
    sources.

    `raw` and `error` are excluded from equality to keep dedup on
    (source, ioc_type, ioc_value, verdict).
    """

    source: str
    ioc_type: IOCType
    ioc_value: str
    verdict: Verdict
    score: float = 0.0
    tags: tuple[str, ...] = ()
    first_seen: str | None = None
    last_seen: str | None = None
    references: tuple[str, ...] = ()
    raw: dict[str, Any] | None = field(default=None, compare=False, hash=False)
    error: str | None = field(default=None, compare=False, hash=False)


class Source(ABC):
    """Abstract base class for every TI source."""

    # Class-level metadata — set by subclasses.
    name: str
    weight: float
    supported_types: frozenset[IOCType]
    requires_key: bool = False

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        api_key: str | None = None,
    ) -> None:
        self._client = client
        self._api_key = api_key

    @property
    def is_configured(self) -> bool:
        """A source is configured when its key (if any) is present."""
        return not self.requires_key or bool(self._api_key)

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    @abstractmethod
    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        """Look up a single IOC. Errors return a result with `error` set."""

    def _unsupported(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=Verdict.UNKNOWN,
            error=f"{self.name} does not support {ioc_type}",
        )

    def _missing_key(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=Verdict.UNKNOWN,
            error=f"{self.name} is not configured (missing API key)",
        )

    def _error(self, ioc_type: IOCType, ioc_value: str, error: str) -> SourceResult:
        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=Verdict.UNKNOWN,
            error=error,
        )
