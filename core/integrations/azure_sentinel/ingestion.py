"""
Azure Sentinel Ingestion Service - Ingest incidents from Azure Sentinel.

Fetches security incidents from Microsoft Sentinel (Azure Sentinel) and converts them to findings.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from core.ingestion.siem_ingestion_service import SIEMIngestionService
from core.integrations._base.config import missing, resolve
from core.integrations.azure_sentinel.descriptor import AZURE_SENTINEL
from core.time import utcnow

logger = logging.getLogger(__name__)

# What the incidents API needs. ``workspace_id`` (the Log Analytics GUID) is
# the MCP server's query target; the management API addresses the workspace
# by subscription, resource group and name instead.
_REQUIRED_FIELDS = (
    "tenant_id",
    "client_id",
    "client_secret",
    "subscription_id",
    "resource_group",
    "workspace_name",
)


def _as_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime.

    ``core.time.utcnow()`` is naive while the Azure SDK returns aware
    timestamps, and comparing the two raises ``TypeError``.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _odata_time(value: datetime) -> str:
    return _as_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _incident_to_dict(incident: Any) -> Dict[str, Any]:
    additional = incident.additional_data
    owner = incident.owner
    return {
        "id": incident.name,
        "incident_number": incident.incident_number,
        "incident_url": incident.incident_url,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "classification": incident.classification,
        "created_time": _iso(incident.created_time_utc),
        "last_updated_time": _iso(incident.last_modified_time_utc),
        "first_activity_time": _iso(incident.first_activity_time_utc),
        "last_activity_time": _iso(incident.last_activity_time_utc),
        "owner": (owner.email or owner.user_principal_name) if owner else None,
        "labels": [label.label_name for label in incident.labels or []],
        "tactics": list(additional.tactics or []) if additional else [],
        "alert_count": (additional.alerts_count or 0) if additional else 0,
        "alert_product_names": (
            list(additional.alert_product_names or []) if additional else []
        ),
        "properties": incident.additional_properties or {},
    }


class AzureSentinelIngestion(SIEMIngestionService):
    """Azure Sentinel ingestion service."""

    def __init__(self):
        """Initialize Azure Sentinel ingestion."""
        super().__init__()
        self.siem_name = "Azure Sentinel"
        self.config = resolve(AZURE_SENTINEL)

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Fetch incidents from Azure Sentinel.

        Args:
            start_time: Start time for incident query
            end_time: End time for incident query
            limit: Maximum number of incidents to fetch

        Returns:
            List of raw incident dictionaries, newest first
        """
        absent = missing(self.config, *_REQUIRED_FIELDS)
        if absent:
            logger.error(
                "Azure Sentinel configuration incomplete, missing: %s",
                ", ".join(absent),
            )
            return []

        end_time = _as_utc(end_time or utcnow())
        start_time = _as_utc(start_time or end_time - timedelta(hours=24))

        try:
            # The Azure SDK is synchronous; keep it off the event loop.
            incidents = await asyncio.to_thread(
                self._list_incidents, start_time, end_time, limit
            )
        except ImportError:
            logger.error(
                "Azure SDK not installed. Install: pip install azure-mgmt-securityinsight azure-identity"
            )
            return []
        except Exception as e:
            logger.error(f"Error fetching Azure Sentinel incidents: {e}")
            return []

        logger.info(f"Fetched {len(incidents)} incidents from Azure Sentinel")
        return incidents

    def _list_incidents(
        self, start_time: datetime, end_time: datetime, limit: int
    ) -> List[Dict[str, Any]]:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.securityinsight import SecurityInsights

        credential = ClientSecretCredential(
            tenant_id=self.config["tenant_id"],
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
        )
        client = SecurityInsights(credential, self.config["subscription_id"])

        # Filter and order server-side; listing every incident in the
        # workspace on each poll grows without bound.
        pages = client.incidents.list(
            resource_group_name=self.config["resource_group"],
            workspace_name=self.config["workspace_name"],
            filter=f"properties/createdTimeUtc ge {_odata_time(start_time)}",
            orderby="properties/createdTimeUtc desc",
            top=min(limit, 1000),
        )

        incidents: List[Dict[str, Any]] = []
        for incident in pages:
            created = incident.created_time_utc
            if created and _as_utc(created) > end_time:
                continue
            incidents.append(_incident_to_dict(incident))
            if len(incidents) >= limit:
                break
        return incidents

    def transform_alert_to_finding(
        self, alert: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Transform Azure Sentinel incident to finding format.

        Args:
            alert: Raw incident from Azure Sentinel

        Returns:
            Finding dictionary
        """
        try:
            # Generate finding ID
            finding_id = f"sentinel-{alert.get('id', uuid.uuid4().hex[:12])}"

            # Extract entities
            entities = self.extract_entities(alert.get("properties", {}))

            # Build finding
            finding = {
                "finding_id": finding_id,
                "title": alert.get("title", "Azure Sentinel Incident"),
                "description": alert.get("description", ""),
                "severity": self.normalize_severity(alert.get("severity")),
                "data_source": "azure_sentinel",
                "timestamp": alert.get("created_time", utcnow().isoformat()),
                "raw_data": alert,
                "metadata": {
                    "incident_id": alert.get("id"),
                    "status": alert.get("status"),
                    "owner": alert.get("owner"),
                    "labels": alert.get("labels", []),
                    "tactics": alert.get("tactics", []),
                    "alert_count": alert.get("alert_count", 0),
                    "last_updated": alert.get("last_updated_time"),
                },
                "entities": entities,
                "mitre_attack": {
                    "tactics": alert.get("tactics", []),
                    "techniques": [],
                },
            }

            return finding

        except Exception as e:
            logger.error(f"Error transforming Azure Sentinel incident: {e}")
            return None
