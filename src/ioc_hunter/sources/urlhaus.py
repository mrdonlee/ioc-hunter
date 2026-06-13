"""URLhaus (abuse.ch) threat-intel source.

Endpoints:
    POST /v1/url/      url=<url>
    POST /v1/host/     host=<domain|ip>
    POST /v1/payload/  sha256_hash=<h> | md5_hash=<h>

Authentication (since June 2024) via header `Auth-Key: <key>`.
"""

from __future__ import annotations

from typing import Any

import httpx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhausSource(Source):
    name = "urlhaus"
    weight = 0.85
    supported_types = frozenset(
        {
            IOCType.URL,
            IOCType.DOMAIN,
            IOCType.IPV4,
            IOCType.MD5,
            IOCType.SHA256,
        }
    )
    requires_key = True

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        if not self.is_configured:
            return self._missing_key(ioc_type, ioc_value)

        endpoint, data = self._build_request(ioc_type, ioc_value)
        try:
            resp = await self._client.post(
                f"{_BASE}/{endpoint}/",
                data=data,
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

    def _build_request(self, ioc_type: IOCType, ioc_value: str) -> tuple[str, dict[str, str]]:
        if ioc_type == IOCType.URL:
            return "url", {"url": ioc_value}
        if ioc_type in {IOCType.DOMAIN, IOCType.IPV4}:
            return "host", {"host": ioc_value}
        if ioc_type == IOCType.SHA256:
            return "payload", {"sha256_hash": ioc_value}
        if ioc_type == IOCType.MD5:
            return "payload", {"md5_hash": ioc_value}
        raise ValueError(ioc_type)

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

        tags = tuple(payload.get("tags") or ())
        first_seen = payload.get("date_added") or payload.get("firstseen")
        last_seen = payload.get("last_online") or payload.get("lastseen")
        reference = payload.get("urlhaus_reference")
        references = (reference,) if reference else ()

        url_status = payload.get("url_status")
        if url_status == "online":
            verdict, score = Verdict.MALICIOUS, 0.95
        elif url_status == "offline":
            verdict, score = Verdict.SUSPICIOUS, 0.7
        else:
            # host / payload responses don't carry url_status — presence is
            # enough to call it malicious.
            verdict, score = Verdict.MALICIOUS, 0.85

        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            score=score,
            tags=tags,
            first_seen=first_seen,
            last_seen=last_seen,
            references=references,
            raw=payload,
        )
