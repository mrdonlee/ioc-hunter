"""Shared async fixtures for source tests."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio


@pytest_asyncio.fixture
async def http_client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as client:
        yield client
