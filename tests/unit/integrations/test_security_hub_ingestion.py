"""AWS Security Hub fetch failures must raise, not read as an empty poll."""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from core.integrations.aws_security_hub.ingestion import AWSSecurityHubIngestion

pytestmark = pytest.mark.unit


@pytest.fixture
def svc():
    with patch(
        "core.integrations.aws_security_hub.ingestion.resolve",
        return_value={"region": "us-east-1"},
    ):
        yield AWSSecurityHubIngestion()


@pytest.mark.asyncio
async def test_api_failure_raises(svc):
    client = MagicMock()
    client.get_paginator.side_effect = RuntimeError("AccessDenied")
    boto3 = types.SimpleNamespace(client=MagicMock(return_value=client))
    botocore = types.ModuleType("botocore")
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError = type("ClientError", (Exception,), {})
    botocore.exceptions = exceptions

    with patch.dict(
        sys.modules,
        {"boto3": boto3, "botocore": botocore, "botocore.exceptions": exceptions},
    ):
        with pytest.raises(RuntimeError, match="AccessDenied"):
            await svc.fetch_alerts(limit=10)


@pytest.mark.asyncio
async def test_clean_empty_result_returns_empty(svc):
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Findings": []}]
    client = MagicMock()
    client.get_paginator.return_value = paginator
    boto3 = types.SimpleNamespace(client=MagicMock(return_value=client))

    with patch.dict(sys.modules, {"boto3": boto3}):
        assert await svc.fetch_alerts(limit=10) == []
