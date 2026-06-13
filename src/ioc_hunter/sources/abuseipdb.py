"""AbuseIPDB threat-intel source — IP reputation.

GET /api/v2/check?ipAddress=<ip>&maxAgeInDays=90
Header: Key: <api_key>, Accept: application/json
"""

from __future__ import annotations

from typing import Any

import httpx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_URL = "https://api.abuseipdb.com/api/v2/check"
_MAX_AGE_DAYS = 90


class AbuseIPDBSource(Source):
    name = "abuseipdb"
    weight = 0.8
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})
    requires_key = True

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        if not self.is_configured:
            return self._missing_key(ioc_type, ioc_value)

        try:
            resp = await self._client.get(
                _URL,
                params={
                    "ipAddress": ioc_value,
                    "maxAgeInDays": str(_MAX_AGE_DAYS),
                },
                headers={
                    "Key": self._api_key or "",
                    "Accept": "application/json",
                },
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
        data = payload.get("data") or {}
        confidence = int(data.get("abuseConfidenceScore") or 0)
        is_whitelisted = bool(data.get("isWhitelisted"))

        tags: list[str] = []
        if country := data.get("countryCode"):
            tags.append(f"country:{country}")
        if usage := data.get("usageType"):
            tags.append(f"usage:{usage}")
        if isp := data.get("isp"):
            tags.append(f"isp:{isp}")

        if is_whitelisted:
            verdict = Verdict.BENIGN
            score = 0.0
        elif confidence >= 75:
            verdict = Verdict.MALICIOUS
            score = confidence / 100.0
        elif confidence > 0:
            verdict = Verdict.SUSPICIOUS
            score = confidence / 100.0
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
            last_seen=data.get("lastReportedAt"),
            references=(f"https://www.abuseipdb.com/check/{ioc_value}",),
            raw=payload,
        )
