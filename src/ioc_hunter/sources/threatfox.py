"""ThreatFox (abuse.ch) threat-intel source.

Single endpoint:
    POST /api/v1/   JSON body {"query": "search_ioc", "search_term": "<ioc>"}

Authentication (since June 2024) via header `Auth-Key: <key>`.

ThreatFox is the broadest abuse.ch feed — it covers domains, IPs, URLs,
hashes (MD5/SHA1/SHA256), and emails. Each hit carries a `confidence_level`
that we surface as the result `score`.
"""

from __future__ import annotations

from typing import Any

import httpx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxSource(Source):
    name = "threatfox"
    weight = 0.85
    supported_types = frozenset(
        {
            IOCType.URL,
            IOCType.DOMAIN,
            IOCType.IPV4,
            IOCType.IPV6,
            IOCType.MD5,
            IOCType.SHA1,
            IOCType.SHA256,
            IOCType.EMAIL,
        }
    )
    requires_key = True

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        if not self.is_configured:
            return self._missing_key(ioc_type, ioc_value)

        try:
            resp = await self._client.post(
                _URL,
                json={"query": "search_ioc", "search_term": ioc_value},
                headers={"Auth-Key": self._api_key or ""},
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
        if payload.get("query_status") != "ok":
            return SourceResult(
                source=self.name,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict=Verdict.UNKNOWN,
                raw=payload,
            )

        data = payload.get("data") or []
        if not isinstance(data, list) or not data:
            return SourceResult(
                source=self.name,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict=Verdict.UNKNOWN,
                raw=payload,
            )

        best_confidence = max((entry.get("confidence_level") or 0) for entry in data) / 100.0
        first = data[0]

        tags: list[str] = []
        for entry in data:
            for tag in entry.get("tags") or ():
                if tag and tag not in tags:
                    tags.append(tag)
            malware = entry.get("malware_printable") or entry.get("malware")
            if malware and malware not in tags:
                tags.append(malware)

        references = tuple(ref for entry in data if (ref := entry.get("reference")))

        verdict = Verdict.MALICIOUS if best_confidence >= 0.5 else Verdict.SUSPICIOUS

        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            score=best_confidence,
            tags=tuple(tags),
            first_seen=first.get("first_seen"),
            last_seen=first.get("last_seen"),
            references=references,
            raw=payload,
        )
