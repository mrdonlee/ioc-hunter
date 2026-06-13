"""STIX 2.1 bundle exporter.

Produces a minimal but compliant Indicator object per IOC. Verdict + score
go to the OASIS-defined `confidence` field; tags become `labels`.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict

_PATTERN_BUILDERS: dict[IOCType, str] = {
    IOCType.IPV4: "[ipv4-addr:value = '{value}']",
    IOCType.IPV6: "[ipv6-addr:value = '{value}']",
    IOCType.DOMAIN: "[domain-name:value = '{value}']",
    IOCType.URL: "[url:value = '{value}']",
    IOCType.EMAIL: "[email-addr:value = '{value}']",
    IOCType.MD5: "[file:hashes.'MD5' = '{value}']",
    IOCType.SHA1: "[file:hashes.'SHA-1' = '{value}']",
    IOCType.SHA256: "[file:hashes.'SHA-256' = '{value}']",
}

_VERDICT_LABEL: dict[Verdict, str] = {
    Verdict.MALICIOUS: "malicious-activity",
    Verdict.SUSPICIOUS: "anomalous-activity",
    Verdict.BENIGN: "benign",
    Verdict.UNKNOWN: "unknown",
}


def _stix_pattern(ioc: IOC) -> str | None:
    template = _PATTERN_BUILDERS.get(ioc.type)
    if template is None:
        return None
    # STIX strings use single-quotes so escape any embedded ones.
    safe = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
    return template.format(value=safe)


def to_stix(verdicts: list[IOCVerdict]) -> str:
    """Serialize verdicts as a STIX 2.1 bundle JSON document."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"

    objects: list[dict] = []
    for v in verdicts:
        pattern = _stix_pattern(v.ioc)
        if pattern is None:
            continue
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": v.ioc.value,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "labels": [_VERDICT_LABEL[v.verdict], *list(v.tags[:20])],
            "confidence": round(v.confidence * 100),
        }
        if v.references:
            indicator["external_references"] = [
                {"source_name": "ioc-hunter", "url": ref} for ref in v.references[:10]
            ]
        objects.append(indicator)

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False)
