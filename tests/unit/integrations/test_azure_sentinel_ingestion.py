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
from core.time import utcnow

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
    async def test_incomplete_config_raises_without_calling_the_sdk(self):
        svc = _service({**_CONFIG, "workspace_name": None})
        with patch.object(svc, "_list_incidents") as listing:
            with pytest.raises(RuntimeError, match="workspace_name"):
                await svc.fetch_alerts()
        listing.assert_not_called()

    @pytest.mark.asyncio
    async def test_api_failure_raises_instead_of_reading_as_empty(self):
        svc = _service()
        with patch.object(svc, "_list_incidents", side_effect=PermissionError("403")):
            with pytest.raises(PermissionError):
                await svc.fetch_alerts()


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

    def test_transform_emits_the_keys_ingest_finding_persists(self):
        svc = _service()
        finding = svc.transform_alert_to_finding(
            sentinel._incident_to_dict(_incident())
        )
        assert finding["finding_id"] == "sentinel-inc-1"
        assert finding["data_source"] == "azure_sentinel"
        assert finding["status"] == "new"
        assert finding["severity"] == "info"
        assert finding["mitre_predictions"] == {}
        ctx = finding["entity_context"]
        assert ctx["alert_count"] == 2
        assert ctx["tactics"] == ["Execution"]
        assert ctx["incident_number"] == 42
        assert finding["evidence_links"] == [
            {"type": "incident", "ref": "https://portal.example/incident/42"}
        ]

    def test_title_leads_the_description(self):
        # No title column in storage; the backfill re-triages from the row.
        svc = _service()
        finding = svc.transform_alert_to_finding(
            sentinel._incident_to_dict(_incident())
        )
        assert finding["title"] == "EICAR test file prevented"
        assert finding["description"] == (
            "EICAR test file prevented\n\nDefender blocked a test file"
        )

    def test_description_falls_back_to_title(self):
        svc = _service()
        for detail in ("", "   ", "EICAR test file prevented"):
            alert = sentinel._incident_to_dict(_incident(description=detail))
            finding = svc.transform_alert_to_finding(alert)
            assert finding["description"] == "EICAR test file prevented"


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
    async def test_reuses_one_client_across_polls(self):
        pytest.importorskip("azure.identity")
        pytest.importorskip("azure.mgmt.securityinsight")
        svc = _service()
        client = MagicMock()
        client.incidents.list.return_value = []

        with patch("azure.identity.ClientSecretCredential") as cred, patch(
            "azure.mgmt.securityinsight.SecurityInsights", return_value=client
        ):
            await svc.fetch_alerts()
            await svc.fetch_alerts()

        assert cred.call_count == 1

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


class TestEntities:
    _ENTITIES = [
        {"kind": "Host", "host_name": "mhk-rg-ws", "dns_domain": "corp.example"},
        {"kind": "Account", "account_name": "jsmith", "upn_suffix": "corp.example"},
        {"kind": "Account", "account_name": "svc", "nt_domain": "CORP"},
        {"kind": "Ip", "address": "198.51.100.42"},
        {"kind": "Url", "url": "https://www.eicar.org/"},
        {"kind": "DnsResolution", "domain_name": "evil.example"},
        {"kind": "FileHash", "hash_value": "275a02", "algorithm": "SHA256"},
        {"kind": "File", "file_name": "eicar.com"},
        {"kind": "Mailbox", "mailbox_primary_address": "tdoe@corp.example"},
        {
            "kind": "MailMessage",
            "recipient": "tdoe@corp.example",
            "p1_sender": "phish@example.net",
            "sender_ip": "203.0.113.9",
        },
        {"kind": "CloudApplication", "app_name": "Office 365"},
        {"kind": "MailCluster", "friendly_name": "urn:cluster"},
    ]

    def test_maps_entities_onto_triage_keys(self):
        ctx = sentinel._entity_context(self._ENTITIES)
        assert ctx["hostnames"] == ["mhk-rg-ws.corp.example"]
        assert ctx["usernames"] == [
            "jsmith@corp.example",
            "CORP\\svc",
            "tdoe@corp.example",
        ]
        assert ctx["src_ips"] == ["198.51.100.42", "203.0.113.9"]
        assert ctx["domains"] == ["https://www.eicar.org/", "evil.example"]
        assert ctx["file_hashes"] == ["275a02"]
        assert ctx["file_names"] == ["eicar.com"]
        assert ctx["email_senders"] == ["phish@example.net"]
        assert ctx["cloud_apps"] == ["Office 365"]

    def test_core_keys_always_present_and_empty_extras_dropped(self):
        ctx = sentinel._entity_context([])
        assert ctx == {
            "src_ips": [],
            "hostnames": [],
            "usernames": [],
            "domains": [],
            "file_hashes": [],
        }

    def test_lists_are_capped(self):
        many = [{"kind": "Ip", "address": f"10.0.0.{n}"} for n in range(200)]
        ctx = sentinel._entity_context(many)
        assert len(ctx["src_ips"]) == sentinel._MAX_ENTITIES_PER_KIND

    def test_transform_uses_enriched_entities(self):
        svc = _service()
        alert = {**sentinel._incident_to_dict(_incident()), "entities": self._ENTITIES}
        finding = svc.transform_alert_to_finding(alert)
        assert finding["entity_context"]["hostnames"] == ["mhk-rg-ws.corp.example"]

    def test_entity_fields_exist_on_the_sdk_models(self):
        models = pytest.importorskip("azure.mgmt.securityinsight.models")
        known = set()
        for name in dir(models):
            cls = getattr(models, name)
            if isinstance(cls, type) and name.endswith("Entity"):
                known |= set(getattr(cls, "_attribute_map", {}))
        missing_fields = [f for f in sentinel._ENTITY_FIELDS if f not in known]
        assert missing_fields == []

    @pytest.mark.asyncio
    async def test_enrich_attaches_entities(self):
        svc = _service()
        entity = MagicMock()
        entity.as_dict.return_value = {
            "kind": "Host",
            "host_name": "mhk-rg-ws",
            "sid": "S-1-5-21-noise",
        }
        client = MagicMock()
        client.incidents.list_entities.return_value = SimpleNamespace(entities=[entity])
        svc._client = client

        out = await svc.enrich_alert({"id": "inc-1", "title": "t"})

        assert out["entities"] == [{"kind": "Host", "host_name": "mhk-rg-ws"}]
        client.incidents.list_entities.assert_called_once_with("rg", "ws", "inc-1")

    @pytest.mark.asyncio
    async def test_enrich_failure_degrades_to_no_entities(self):
        svc = _service()
        client = MagicMock()
        client.incidents.list_entities.side_effect = PermissionError("403")
        svc._client = client
        alert = {"id": "inc-1", "title": "t"}

        assert await svc.enrich_alert(alert) == alert


def _make_poller(checkpoint=None):
    from services.daemon.config import PollingConfig
    from services.daemon.poller import DataPoller

    with (
        patch("services.daemon.poller.FederationRunner"),
        patch("services.daemon.poller.RedisDedupSet"),
    ):
        poller = DataPoller(PollingConfig())
    poller._federation.is_active_for = MagicMock(return_value=False)
    dedup = MagicMock()
    dedup.is_processed = AsyncMock(return_value=False)
    dedup.mark_processed = AsyncMock()
    dedup.load_checkpoint = AsyncMock(return_value=checkpoint)
    dedup.save_checkpoint = AsyncMock()
    poller._azure_sentinel_dedup = dedup
    poller._enqueue_finding = AsyncMock(return_value=True)
    return poller


def _sentinel_service(alerts=()):
    service = MagicMock()
    service.fetch_alerts = AsyncMock(return_value=list(alerts))
    service.enrich_alert = AsyncMock(side_effect=lambda a: {**a, "enriched": True})
    service.transform_alert_to_finding.side_effect = lambda a: {
        "finding_id": f"sentinel-{a['id']}"
    }
    return service


class TestPoller:
    @pytest.mark.asyncio
    async def test_ingestion_sources_dedup_and_enqueue_for_triage(self):
        poller = _make_poller()
        service = _sentinel_service([{"id": "a"}, {"id": "b"}])
        poller._azure_sentinel_service = service
        dedup = poller._azure_sentinel_dedup
        dedup.is_processed = AsyncMock(side_effect=lambda fid: fid == "sentinel-b")

        await poller._poll_ingestion_source("azure_sentinel")

        service.ingest_alerts.assert_not_called()
        # Only the new alert is enriched (one entities call per incident).
        service.enrich_alert.assert_awaited_once_with({"id": "a"})
        poller._enqueue_finding.assert_awaited_once_with(
            {"finding_id": "sentinel-a"}, "azure_sentinel"
        )
        dedup.mark_processed.assert_awaited_once_with("sentinel-a")
        assert poller.stats["azure_sentinel_findings"] == 1

    @pytest.mark.asyncio
    async def test_clean_poll_saves_the_checkpoint(self):
        poller = _make_poller()
        poller._azure_sentinel_service = _sentinel_service()

        await poller._poll_ingestion_source("azure_sentinel")

        saved = poller._azure_sentinel_dedup.save_checkpoint.await_args.args[0]
        assert poller._azure_sentinel_state.last_poll_time == saved

    @pytest.mark.asyncio
    async def test_resumes_from_the_last_clean_poll(self):
        poller = _make_poller()
        service = _sentinel_service()
        poller._azure_sentinel_service = service
        last = utcnow() - timedelta(hours=2)
        poller._azure_sentinel_state.last_poll_time = last

        await poller._poll_ingestion_source("azure_sentinel")

        start = service.fetch_alerts.await_args.kwargs["start_time"]
        assert start == last - timedelta(minutes=1)

    @pytest.mark.asyncio
    async def test_a_restart_resumes_from_the_saved_checkpoint(self):
        saved = utcnow() - timedelta(hours=3)
        poller = _make_poller(checkpoint=saved)
        service = _sentinel_service()
        poller._azure_sentinel_service = service

        await poller._poll_ingestion_source("azure_sentinel")

        start = service.fetch_alerts.await_args.kwargs["start_time"]
        assert start == saved - timedelta(minutes=1)

    @pytest.mark.asyncio
    async def test_resume_window_stays_inside_dedup_memory(self):
        from services.daemon.poller import _MAX_RESUME_WINDOW

        poller = _make_poller(checkpoint=utcnow() - timedelta(days=3))
        service = _sentinel_service()
        poller._azure_sentinel_service = service

        before = utcnow()
        await poller._poll_ingestion_source("azure_sentinel")

        start = service.fetch_alerts.await_args.kwargs["start_time"]
        assert start >= before - _MAX_RESUME_WINDOW

    @pytest.mark.asyncio
    async def test_failed_fetch_keeps_the_checkpoint_and_counts_an_error(self):
        poller = _make_poller()
        service = _sentinel_service()
        service.fetch_alerts = AsyncMock(side_effect=PermissionError("403"))
        poller._azure_sentinel_service = service
        last = utcnow() - timedelta(hours=1)
        poller._azure_sentinel_state.last_poll_time = last
        shutdown = MagicMock()
        shutdown.is_set.side_effect = [False, True]
        shutdown.wait = AsyncMock()

        await poller._poll_ingestion_loop("azure_sentinel", shutdown)

        assert poller._azure_sentinel_state.last_poll_time == last
        poller._azure_sentinel_dedup.save_checkpoint.assert_not_awaited()
        assert poller.stats["errors"] == 1

    @pytest.mark.asyncio
    async def test_refused_finding_keeps_the_checkpoint(self):
        from services.daemon.poller import IngestionError

        poller = _make_poller()
        poller._azure_sentinel_service = _sentinel_service([{"id": "a"}])
        poller._enqueue_finding = AsyncMock(return_value=False)

        with pytest.raises(IngestionError):
            await poller._poll_ingestion_source("azure_sentinel")

        poller._azure_sentinel_dedup.mark_processed.assert_not_awaited()
        poller._azure_sentinel_dedup.save_checkpoint.assert_not_awaited()
