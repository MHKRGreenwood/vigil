"""Unit tests for Microsoft Defender alert → finding transform."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.integrations.microsoft_defender.ingestion import MicrosoftDefenderIngestion

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"


@pytest.fixture
def sample_alerts():
    with open(FIXTURES_DIR / "defender_alerts.json") as f:
        return json.load(f)


@pytest.fixture
def ingestion():
    with patch(
        "core.integrations.microsoft_defender.ingestion.resolve",
        return_value={},
    ):
        svc = MicrosoftDefenderIngestion()
        svc.ingestion_service = MagicMock()
        yield svc


class TestTransformAlert:
    def test_emits_store_keys_from_title_and_evidence(self, ingestion, sample_alerts):
        finding = ingestion.transform_alert_to_finding(sample_alerts[0])
        assert finding is not None
        assert finding["finding_id"] == "defender-da637552173936382409"
        assert finding["data_source"] == "microsoft_defender"
        assert finding["severity"] == "high"
        # MDE left description empty; the text lives in title.
        assert finding["description"] == "Suspicious PowerShell command line"
        ctx = finding["entity_context"]
        assert "198.51.100.42" in ctx["src_ips"]
        assert "jsmith@corp.example" in ctx["usernames"]
        assert "WORKSTATION-01.corp.example" in ctx["hostnames"]
        assert (
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
            in ctx["file_hashes"]
        )
        assert "ip_addresses" not in ctx
        assert ctx["category"] == "Execution"
        assert ctx["threat_family"] == "Emotet"
        assert finding["mitre_predictions"] == {"T1059.001": 1.0, "T1204.002": 1.0}

    def test_keeps_a_nonempty_description(self, ingestion, sample_alerts):
        alert = dict(sample_alerts[0])
        alert["description"] = "Encoded PowerShell spawned from a macro."
        finding = ingestion.transform_alert_to_finding(alert)
        assert finding["description"] == "Encoded PowerShell spawned from a macro."

    def test_handles_missing_fields_gracefully(self, ingestion):
        finding = ingestion.transform_alert_to_finding({"id": "sparse-1"})
        assert finding is not None
        assert finding["finding_id"] == "defender-sparse-1"
        assert finding["description"] == "Microsoft Defender Alert"
        assert finding["mitre_predictions"] == {}

    def test_handles_transform_error(self, ingestion):
        assert ingestion.transform_alert_to_finding(None) is None


class TestFetchFailures:
    """A failed fetch must raise, not read as an empty poll (the poller keeps
    its checkpoint only when it can tell the two apart)."""

    @pytest.mark.asyncio
    async def test_no_token_raises(self, ingestion):
        with patch.object(ingestion, "_get_access_token", return_value=None):
            with pytest.raises(RuntimeError, match="access token"):
                await ingestion.fetch_alerts(limit=10)

    @pytest.mark.asyncio
    async def test_http_error_raises(self, ingestion):
        import httpx

        with patch.object(ingestion, "_get_access_token", return_value="tok"), patch(
            "core.integrations.microsoft_defender.ingestion.httpx.get",
            side_effect=httpx.ConnectError("down"),
        ):
            with pytest.raises(httpx.HTTPError):
                await ingestion.fetch_alerts(limit=10)


@pytest.mark.asyncio
async def test_default_enrich_alert_is_a_no_op(ingestion):
    alert = {"id": "x"}
    assert await ingestion.enrich_alert(alert) is alert
