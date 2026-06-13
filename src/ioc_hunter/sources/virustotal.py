"""VirusTotal v3 threat-intel source.

GET /api/v3/<collection>/<id>
Header: x-apikey: <api_key>

VirusTotal's free tier is rate-limited (4 req/min, 500/day) so cache hits
are essential. URL IDs are url-safe base64 of the URL with padding stripped,
per VT v3 docs.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_BASE = "https://www.virustotal.com/api/v3"

_COLLECTION: dict[IOCType, str] = {
    IOCType.IPV4: "ip_addresses",
    IOCType.IPV6: "ip_addresses",
    IOCType.DOMAIN: "domains",
    IOCType.URL: "urls",
    IOCType.MD5: "files",
    IOCType.SHA1: "files",
    IOCType.SHA256: "files",
}


def _vt_url_id(url: str) -> str:
    """Return the URL identifier VT v3 expects (urlsafe-base64, no padding)."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode("ascii")


class VirusTotalSource(Source):
    name = "virustotal"
    weight = 0.9
    supported_types = frozenset(_COLLECTION.keys())
    requires_key = True

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        if not self.is_configured:
            return self._missing_key(ioc_type, ioc_value)

        collection = _COLLECTION[ioc_type]
        identifier = _vt_url_id(ioc_value) if ioc_type is IOCType.URL else ioc_value
        endpoint = f"{_BASE}/{collection}/{identifier}"

        try:
            resp = await self._client.get(
                endpoint,
                headers={"x-apikey": self._api_key or ""},
                timeout=15,
            )
            if resp.status_code == 404:
                # VT returns 404 for unknown indicators.
                return SourceResult(
                    source=self.name,
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    verdict=Verdict.UNKNOWN,
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
        attributes = (payload.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = malicious + suspicious + harmless + undetected

        tags = tuple(attributes.get("tags") or ())

        if total == 0:
            verdict = Verdict.UNKNOWN
            score = 0.0
        elif malicious >= 5:
            verdict = Verdict.MALICIOUS
            score = min(1.0, malicious / max(total, 1))
        elif malicious > 0 or suspicious > 0:
            verdict = Verdict.SUSPICIOUS
            score = (malicious + suspicious) / total
        else:
            verdict = Verdict.BENIGN
            score = 0.0

        first_seen = attributes.get("first_submission_date")
        last_seen = attributes.get("last_analysis_date")

        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            score=score,
            tags=tags,
            first_seen=str(first_seen) if first_seen else None,
            last_seen=str(last_seen) if last_seen else None,
            references=(f"https://www.virustotal.com/gui/search/{ioc_value}",),
            raw=payload,
        )
