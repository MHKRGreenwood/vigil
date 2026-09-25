"""Federation SIEM adapter: failures must reach the runner, cursors must not skip.

The runner records a failure and keeps the old cursor when ``adapter.fetch``
raises. The adapter used to swallow ``fetch_alerts`` errors and return a fresh
cursor, so a failing source silently skipped everything raised meanwhile.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.federation.adapters._siem_base import SIEMIngestionAdapter

pytestmark = pytest.mark.unit


def _adapter(service) -> SIEMIngestionAdapter:
    adapter = SIEMIngestionAdapter(
        name="azure_sentinel",
        integration_id="azure-sentinel",
        default_interval=300,
        service_factory=lambda: service,
        external_id_prefix="azure-sentinel",
    )
    adapter._service = service
    return adapter


def _service(alerts=()):
    svc = MagicMock()
    svc.fetch_alerts = AsyncMock(return_value=list(alerts))
    svc.enrich_alert = AsyncMock(side_effect=lambda a: {**a, "entities": ["e"]})
    svc.transform_alert_to_finding.side_effect = lambda a: {
        "finding_id": f"sentinel-{a['id']}",
        "entities": a.get("entities"),
    }
    return svc


@pytest.mark.asyncio
async def test_fetch_failure_reaches_the_runner():
    svc = _service()
    svc.fetch_alerts = AsyncMock(side_effect=PermissionError("403"))

    with pytest.raises(PermissionError):
        await _adapter(svc).fetch(since=None, cursor={}, max_items=10)


@pytest.mark.asyncio
async def test_cursor_is_taken_before_the_fetch():
    svc = _service()
    cursors = iter([{"last_poll_at": "before"}, {"last_poll_at": "after"}])

    with patch(
        "core.federation.adapters._siem_base.fresh_cursor",
        side_effect=lambda: next(cursors),
    ):
        result = await _adapter(svc).fetch(since=None, cursor={}, max_items=10)

    assert result.cursor == {"last_poll_at": "before"}


@pytest.mark.asyncio
async def test_alerts_are_enriched_before_transform():
    svc = _service([{"id": "a"}])

    result = await _adapter(svc).fetch(since=None, cursor={}, max_items=10)

    svc.enrich_alert.assert_awaited_once_with({"id": "a"})
    assert result.findings[0]["entities"] == ["e"]
    assert result.findings[0]["external_id"] == "sentinel-a"
