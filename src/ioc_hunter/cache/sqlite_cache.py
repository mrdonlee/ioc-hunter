"""TTL-based SQLite cache for threat-intel source responses.

A single table keyed by `(source, ioc_type, ioc_value)` stores the raw JSON
response and an expiry timestamp. `get()` transparently skips expired rows;
`purge_expired()` removes them in bulk.

Design notes:

* stdlib `sqlite3` only — no extra runtime dependency.
* WAL mode + `synchronous=NORMAL` for safe concurrent reads from the async
  engine while a single writer (the orchestrator) inserts.
* `time.time()` is injected via `_now` so tests can fast-forward without
  monkey-patching the stdlib.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ioc_hunter.core.types import IOCType

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ti_cache (
    source     TEXT    NOT NULL,
    ioc_type   TEXT    NOT NULL,
    ioc_value  TEXT    NOT NULL,
    payload    TEXT    NOT NULL,
    cached_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (source, ioc_type, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_ti_cache_expires ON ti_cache(expires_at);
"""

DEFAULT_TTL_SECONDS = 86_400  # 24h


@dataclass(frozen=True, slots=True)
class CacheEntry:
    """A row returned from the cache."""

    source: str
    ioc_type: IOCType
    ioc_value: str
    payload: dict[str, Any]
    cached_at: int
    expires_at: int


class TICache:
    """SQLite-backed TTL cache for threat-intel responses."""

    def __init__(
        self,
        path: str | Path,
        *,
        default_ttl: int = DEFAULT_TTL_SECONDS,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.default_ttl = default_ttl
        self._now = now
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)

    def __enter__(self) -> TICache:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def get(
        self,
        source: str,
        ioc_type: IOCType,
        ioc_value: str,
    ) -> CacheEntry | None:
        """Return a fresh entry or `None` if absent/expired."""
        now = int(self._now())
        row = self._conn.execute(
            "SELECT payload, cached_at, expires_at FROM ti_cache "
            "WHERE source = ? AND ioc_type = ? AND ioc_value = ? "
            "AND expires_at > ?",
            (source, str(ioc_type), ioc_value, now),
        ).fetchone()
        if row is None:
            return None
        payload_json, cached_at, expires_at = row
        return CacheEntry(
            source=source,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            payload=json.loads(payload_json),
            cached_at=cached_at,
            expires_at=expires_at,
        )

    def set(
        self,
        source: str,
        ioc_type: IOCType,
        ioc_value: str,
        payload: dict[str, Any],
        *,
        ttl: int | None = None,
    ) -> None:
        """Insert or overwrite an entry."""
        now = int(self._now())
        ttl_value = self.default_ttl if ttl is None else ttl
        self._conn.execute(
            "INSERT INTO ti_cache(source, ioc_type, ioc_value, payload, "
            "cached_at, expires_at) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(source, ioc_type, ioc_value) DO UPDATE SET "
            "payload=excluded.payload, cached_at=excluded.cached_at, "
            "expires_at=excluded.expires_at",
            (
                source,
                str(ioc_type),
                ioc_value,
                json.dumps(payload, separators=(",", ":")),
                now,
                now + ttl_value,
            ),
        )

    def purge_expired(self) -> int:
        """Delete every expired row. Returns the number of rows removed."""
        cur = self._conn.execute(
            "DELETE FROM ti_cache WHERE expires_at <= ?",
            (int(self._now()),),
        )
        return cur.rowcount

    def stats(self) -> dict[str, int]:
        """Return total/fresh/expired counts."""
        now = int(self._now())
        total = self._conn.execute("SELECT COUNT(*) FROM ti_cache").fetchone()[0]
        fresh = self._conn.execute(
            "SELECT COUNT(*) FROM ti_cache WHERE expires_at > ?", (now,)
        ).fetchone()[0]
        return {"total": total, "fresh": fresh, "expired": total - fresh}
