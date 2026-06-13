"""AlienVault OTX threat-intel source.

GET /api/v1/indicators/<section>/<value>/general
Header: X-OTX-API-KEY: <api_key>

OTX organizes intel into "pulses" (community-curated reports). The
`pulse_info.count` tells us how many pulses include the IOC; combined with
the per-indicator `reputation` it gives a solid signal.
"""

from __future__ import annotations

from typing import Any

import httpx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_BASE = "https://otx.alienvault.com/api/v1/indicators"

_SECTION: dict[IOCType, str] = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
    IOCType.CVE: "cve",
}


class OTXSource(Source):
    name = "otx"
    weight = 0.75
    supported_types = frozenset(_SECTION.keys())
    requires_key = True

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        if not self.is_configured:
            return self._missing_key(ioc_type, ioc_value)

        section = _SECTION[ioc_type]
        try:
            resp = await self._client.get(
                f"{_BASE}/{section}/{ioc_value}/general",
                headers={"X-OTX-API-KEY": self._api_key or ""},
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            return self._error(ioc_type, ioc_value, f"http error: {exc}")
        except ValueError as exc:
            return self._error(ioc_type, ioc_value, f"invalid JSON: {exc}")

        return self._interpret(ioc_type, ioc_value, payload)

    def _interpret(
        self,
        ioc_type: IOCType,
        ioc_value: str,
        payload: dict[str, Any],
    ) -> SourceResult:
        pulse_info = payload.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        pulse_count = int(pulse_info.get("count") or len(pulses))
        reputation = int(payload.get("reputation") or 0)

        tags: list[str] = []
        for pulse in pulses[:10]:
            for tag in pulse.get("tags") or ():
                if tag and tag not in tags:
                    tags.append(tag)

        if pulse_count >= 5 or reputation < -2:
            verdict = Verdict.MALICIOUS
            score = min(1.0, pulse_count / 10.0 + max(0.0, -reputation / 10.0))
        elif pulse_count >= 1:
            verdict = Verdict.SUSPICIOUS
            score = min(0.6, pulse_count / 10.0)
        else:
            verdict = Verdict.UNKNOWN
            score = 0.0

        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            score=score,
            tags=tuple(tags),
            references=(f"https://otx.alienvault.com/indicator/{_SECTION[ioc_type]}/{ioc_value}",),
            raw=payload,
        )
