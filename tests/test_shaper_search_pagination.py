"""Tests for traffic shaper search pagination helpers (BR-fix-c)."""

from __future__ import annotations

import pytest

from opnsense_mcp.tools.shaper_settings import (
    DEFAULT_SHAPER_SEARCH_ROW_COUNT,
    MAX_SHAPER_SEARCH_ROW_COUNT,
    fetch_shaper_search_rows,
    parse_shaper_search_options,
    search_shaper_pipes,
)


class _PagingMockClient:
    """Minimal client that slices rows by current/rowCount."""

    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows
        self.calls: list[dict[str, int]] = []

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs: object,
    ) -> dict[str, object]:
        _ = method, endpoint
        body = dict(kwargs.get("json") or {})
        self.calls.append(body)
        current = int(body.get("current", 1))
        row_count = int(body.get("rowCount", DEFAULT_SHAPER_SEARCH_ROW_COUNT))
        start = max(0, (current - 1) * row_count)
        page = self.rows[start : start + row_count]
        return {"rows": page, "rowCount": len(self.rows)}


def test_parse_shaper_search_options_defaults() -> None:
    row_count, fetch_all = parse_shaper_search_options()
    assert row_count == DEFAULT_SHAPER_SEARCH_ROW_COUNT
    assert fetch_all is True


def test_parse_shaper_search_options_caps_row_count() -> None:
    row_count, _ = parse_shaper_search_options(row_count=9999)
    assert row_count == MAX_SHAPER_SEARCH_ROW_COUNT


@pytest.mark.asyncio
async def test_fetch_shaper_search_rows_paginates_until_complete() -> None:
    rows = [
        {"uuid": f"pipe-{index}", "description": f"Pipe {index}"}
        for index in range(120)
    ]
    client = _PagingMockClient(rows)

    fetched = await fetch_shaper_search_rows(
        client,
        "/trafficshaper/settings/search_pipes",
        row_count=50,
        fetch_all=True,
    )

    assert len(fetched) == 120
    assert len(client.calls) == 3
    assert client.calls[0]["current"] == 1
    assert client.calls[-1]["current"] == 3


@pytest.mark.asyncio
async def test_fetch_shaper_search_rows_single_page_when_fetch_all_false() -> None:
    rows = [{"uuid": f"pipe-{index}"} for index in range(120)]
    client = _PagingMockClient(rows)

    fetched = await fetch_shaper_search_rows(
        client,
        "/trafficshaper/settings/search_pipes",
        row_count=50,
        fetch_all=False,
    )

    assert len(fetched) == 50
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_search_shaper_pipes_normalizes_paginated_rows() -> None:
    rows = [
        {
            "uuid": "pipe-1",
            "description": "Download pipe",
            "enabled": "1",
            "bandwidth": "1776",
            "bandwidthMetric": "Mbit",
            "scheduler": "fq_codel",
        }
    ]
    client = _PagingMockClient(rows)

    pipes = await search_shaper_pipes(client, row_count=50, fetch_all=True)

    assert len(pipes) == 1
    assert pipes[0]["scheduler"] == "fq_codel"
