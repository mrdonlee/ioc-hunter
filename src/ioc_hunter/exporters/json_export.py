"""Plain JSON exporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ioc_hunter.scorer import IOCVerdict


def _result_dict(r) -> dict:
    return {
        "source": r.source,
        "verdict": str(r.verdict),
        "score": r.score,
        "tags": list(r.tags),
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
        "references": list(r.references),
        "error": r.error,
    }


def to_json(verdicts: list[IOCVerdict], *, pretty: bool = True) -> str:
    """Serialize a batch of verdicts to JSON."""
    payload = {
        "generator": "ioc-hunter",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "count": len(verdicts),
        "iocs": [
            {
                "value": v.ioc.value,
                "type": v.ioc.type.value,
                "verdict": str(v.verdict),
                "confidence": v.confidence,
                "tags": list(v.tags),
                "references": list(v.references),
                "sources": [_result_dict(r) for r in v.results],
            }
            for v in verdicts
        ],
    }
    indent = 2 if pretty else None
    return json.dumps(payload, indent=indent, ensure_ascii=False)
