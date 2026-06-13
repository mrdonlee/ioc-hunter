"""MISP event JSON exporter.

Each verdict becomes an `Attribute` inside a single MISP `Event`. The
verdict + confidence ride along in the `comment`, tags become MISP tags.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ioc_hunter.core.types import IOCType
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict

_MISP_TYPE: dict[IOCType, tuple[str, str]] = {
    # (attribute type, category)
    IOCType.IPV4: ("ip-dst", "Network activity"),
    IOCType.IPV6: ("ip-dst", "Network activity"),
    IOCType.DOMAIN: ("domain", "Network activity"),
    IOCType.URL: ("url", "Network activity"),
    IOCType.EMAIL: ("email", "Network activity"),
    IOCType.MD5: ("md5", "Payload delivery"),
    IOCType.SHA1: ("sha1", "Payload delivery"),
    IOCType.SHA256: ("sha256", "Payload delivery"),
}

# MISP threat level: 1=High, 2=Medium, 3=Low, 4=Undefined
_THREAT_LEVEL: dict[Verdict, str] = {
    Verdict.MALICIOUS: "1",
    Verdict.SUSPICIOUS: "2",
    Verdict.BENIGN: "4",
    Verdict.UNKNOWN: "4",
}


def to_misp(verdicts: list[IOCVerdict], *, event_info: str = "IOC Hunter findings") -> str:
    """Serialize verdicts as a MISP event JSON document."""
    now = datetime.now(UTC)

    # Worst verdict drives the event-level threat level.
    worst = Verdict.UNKNOWN
    for v in verdicts:
        if v.verdict is Verdict.MALICIOUS:
            worst = Verdict.MALICIOUS
            break
        if v.verdict is Verdict.SUSPICIOUS and worst is not Verdict.MALICIOUS:
            worst = Verdict.SUSPICIOUS

    attributes: list[dict] = []
    for v in verdicts:
        mapping = _MISP_TYPE.get(v.ioc.type)
        if mapping is None:
            continue
        attr_type, category = mapping
        is_indicator = v.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
        attribute = {
            "type": attr_type,
            "category": category,
            "value": v.ioc.value,
            "to_ids": is_indicator,
            "comment": (f"verdict={v.verdict.value} confidence={round(v.confidence * 100)}%"),
        }
        if v.tags:
            attribute["Tag"] = [{"name": t} for t in v.tags[:20]]
        attributes.append(attribute)

    event = {
        "Event": {
            "info": event_info,
            "date": now.strftime("%Y-%m-%d"),
            "threat_level_id": _THREAT_LEVEL[worst],
            "analysis": "2",  # 2 = Completed
            "distribution": "0",  # 0 = Your organisation only
            "published": False,
            "Attribute": attributes,
        }
    }
    return json.dumps(event, indent=2, ensure_ascii=False)
