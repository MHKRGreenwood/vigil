"""Unit tests for Azure Sentinel incident ingestion.

Regressions covered: the incidents poller never produced a finding. The
client secret was read from the stripped stored config, the workspace fields
the management API needs were not on the descriptor, tz-aware SDK timestamps
were compared with naive ones, and two SDK attribute names had drifted
(``last_modified_time_utc``, ``alerts_count``).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import core.integrations._base.config as resolver
from core.integrations.azure_sentinel import ingestion as sentinel
from core.integrations.azure_sentinel.ingestion import AzureSentinelIngestion

pytestmark = pytest.mark.unit

_CONFIG = {
    "workspace_id": "00000000-0000-0000-0000-000000000000",
    "tenant_id": "tenant",
    "client_id": "client",
    "client_secret": "secret",
    "subscription_id": "sub",
    "resource_group": "rg",
    "workspace_name": "ws",
}


def _service(config=None) -> AzureSentinelIngestion:
    with patch(
        "core.integrations.azure_sentinel.ingestion.resolve",
        return_value=dict(_CONFIG if config is None else config),
    ):
        svc = AzureSentinelIngestion()
    svc.ingestion_service = MagicMock()
    return svc


def _incident(name="inc-1", created=None, **overrides):
    created = created or datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    fields = dict(
        name=name,
        incident_number=42,
        incident_url="https://portal.example/incident/42",
        title="EICAR test file prevented",
        description="Defender blocked a test file",
        severity="Informational",
        status="New",
        classification=None,
        created_time_utc=created,
        last_modified_time_utc=created + timedelta(minutes=5),
        first_activity_time_utc=created - timedelta(minutes=1),
        last_activity_time_utc=created,
        owner=SimpleNamespace(email=None, user_principal_name="analyst@example.com"),
        labels=[SimpleNamespace(label_name="poc")],
        additional_data=SimpleNamespace(
            tactics=["Execution"],
            alerts_count=2,
            alert_product_names=["Microsoft Defender for Endpoint"],
        ),
        additional_properties={},
    )
    fields.update(overrides)
    return SimpleNamespace(**fields)


class TestConfig:
    def test_secret_resolves_from_the_secrets_store(self, monkeypatch):
        stored = {k: v for k, v in _CONFIG.items() if k != "client_secret"}
        monkeypatch.setattr(resolver, "get_integration_config", lambda i: dict(stored))
        monkeypatch.setattr(
            resolver,
            "get_secret",
            lambda key, default=None: {
                "AZURE_SENTINEL_CLIENT_SECRET": "from-store"
            }.get(key, default),
        )

        svc = AzureSentinelIngestion()

        assert svc.config["client_secret"] == "from-store"
        assert svc.config["subscription_id"] == "sub"
        assert svc.config["resource_group"] == "rg"
        assert svc.config["workspace_name"] == "ws"

    def test_descriptor_declares_the_management_api_fields(self):
        from core.integrations.azure_sentinel.descriptor import AZURE_SENTINEL

        names = {f.name for f in AZURE_SENTINEL.fields}
        assert set(sentinel._REQUIRED_FIELDS) <= names

    @pytest.mark.asyncio
    async def test_incomplete_config_skips_the_sdk(self):
        svc = _service({**_CONFIG, "workspace_name": None})
        with patch.object(svc, "_list_incidents") as listing:
            assert await svc.fetch_alerts() == []
        listing.assert_not_called()


class TestIncidentMapping:
    def test_maps_current_sdk_attribute_names(self):
        data = sentinel._incident_to_dict(_incident())

        assert data["id"] == "inc-1"
        assert data["last_updated_time"] == "2026-09-25T12:05:00+00:00"
        assert data["alert_count"] == 2
        assert data["owner"] == "analyst@example.com"
        assert data["labels"] == ["poc"]
        assert data["tactics"] == ["Execution"]
        assert data["alert_product_names"] == ["Microsoft Defender for Endpoint"]

    def test_tolerates_missing_optional_blocks(self):
        data = sentinel._incident_to_dict(
            _incident(owner=None, labels=None, additional_data=None)
        )
        assert data["owner"] is None
        assert data["labels"] == []
        assert data["alert_count"] == 0

    def test_attribute_names_exist_on_the_sdk_models(self):
        models = pytest.importorskip("azure.mgmt.securityinsight.models")
        incident_attrs = set(models.Incident._attribute_map)
        for name in (
            "name",
            "incident_number",
            "incident_url",
            "title",
            "description",
            "severity",
            "status",
            "classification",
            "created_time_utc",
            "last_modified_time_utc",
            "first_activity_time_utc",
            "last_activity_time_utc",
            "owner",
            "labels",
            "additional_data",
        ):
            assert name in incident_attrs, name
        extra = set(models.IncidentAdditionalData._attribute_map)
        assert {"tactics", "alerts_count", "alert_product_names"} <= extra

    def test_transform_produces_an_underscore_sourced_finding(self):
        svc = _service()
        finding = svc.transform_alert_to_finding(
            sentinel._incident_to_dict(_incident())
        )
        assert finding["finding_id"] == "sentinel-inc-1"
        assert finding["data_source"] == "azure_sentinel"
        assert finding["metadata"]["alert_count"] == 2


class TestListIncidents:
    @pytest.mark.asyncio
    async def test_filters_server_side_and_accepts_naive_bounds(self):
        pytest.importorskip("azure.identity")
        pytest.importorskip("azure.mgmt.securityinsight")
        svc = _service()
        end = datetime(2026, 9, 25, 13, 0)  # naive, as core.time.utcnow() returns
        start = end - timedelta(hours=1)
        in_range = _incident(
            "in-range", datetime(2026, 9, 25, 12, 30, tzinfo=timezone.utc)
        )
        too_new = _incident(
            "too-new", datetime(2026, 9, 25, 13, 30, tzinfo=timezone.utc)
        )
        client = MagicMock()
        client.incidents.list.return_value = [too_new, in_range]

        with patch("azure.identity.ClientSecretCredential"), patch(
            "azure.mgmt.securityinsight.SecurityInsights", return_value=client
        ):
            incidents = await svc.fetch_alerts(start_time=start, end_time=end, limit=10)

        assert [i["id"] for i in incidents] == ["in-range"]
        kwargs = client.incidents.list.call_args.kwargs
        assert kwargs["resource_group_name"] == "rg"
        assert kwargs["workspace_name"] == "ws"
        assert kwargs["filter"] == "properties/createdTimeUtc ge 2026-09-25T12:00:00Z"
        assert kwargs["orderby"] == "properties/createdTimeUtc desc"

    @pytest.mark.asyncio
    async def test_stops_at_the_limit(self):
        pytest.importorskip("azure.identity")
        pytest.importorskip("azure.mgmt.securityinsight")
        svc = _service()
        client = MagicMock()
        client.incidents.list.return_value = [_incident(f"inc-{n}") for n in range(5)]

        with patch("azure.identity.ClientSecretCredential"), patch(
            "azure.mgmt.securityinsight.SecurityInsights", return_value=client
        ):
            incidents = await svc.fetch_alerts(
                start_time=datetime(2026, 9, 24),
                end_time=datetime(2026, 9, 26),
                limit=3,
            )

        assert len(incidents) == 3


def _make_poller():
    from services.daemon.config import PollingConfig
    from services.daemon.poller import DataPoller

    with (
        patch("services.daemon.poller.FederationRunner"),
        patch("services.daemon.poller.RedisDedupSet"),
    ):
        return DataPoller(PollingConfig())


class TestPoller:
    @pytest.mark.asyncio
    async def test_ingestion_sources_dedup_and_enqueue_for_triage(self):
        poller = _make_poller()
        poller._federation.is_active_for = MagicMock(return_value=False)

        service = MagicMock()
        service.fetch_alerts = AsyncMock(return_value=[{"id": "a"}, {"id": "b"}])
        service.transform_alert_to_finding.side_effect = lambda a: {
            "finding_id": f"sentinel-{a['id']}"
        }
        poller._azure_sentinel_service = service

        dedup = MagicMock()
        dedup.is_processed = AsyncMock(side_effect=lambda fid: fid == "sentinel-b")
        dedup.mark_processed = AsyncMock()
        poller._azure_sentinel_dedup = dedup
        poller._enqueue_finding = AsyncMock(return_value=True)

        await poller._poll_ingestion_source("azure_sentinel")

        service.ingest_alerts.assert_not_called()
        poller._enqueue_finding.assert_awaited_once_with(
            {"finding_id": "sentinel-a"}, "azure_sentinel"
        )
        dedup.mark_processed.assert_awaited_once_with("sentinel-a")
        assert poller.stats["azure_sentinel_findings"] == 1

    @pytest.mark.asyncio
    async def test_resumes_from_the_last_clean_poll(self):
        poller = _make_poller()
        poller._federation.is_active_for = MagicMock(return_value=False)
        service = MagicMock()
        service.fetch_alerts = AsyncMock(return_value=[])
        poller._azure_sentinel_service = service
        last = datetime(2026, 9, 25, 10, 0)
        poller._azure_sentinel_state.last_poll_time = last

        await poller._poll_ingestion_source("azure_sentinel")

        start = service.fetch_alerts.await_args.kwargs["start_time"]
        assert start == last - timedelta(minutes=1)
