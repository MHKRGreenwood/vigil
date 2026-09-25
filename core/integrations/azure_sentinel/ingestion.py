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


# Entity properties worth keeping; the rest (fingerprints, GUIDs, SIDs) only
# bloat the stored row and the triage prompt.
_ENTITY_FIELDS = (
    "friendly_name",
    "host_name",
    "dns_domain",
    "nt_domain",
    "account_name",
    "upn_suffix",
    "address",
    "url",
    "domain_name",
    "hash_value",
    "algorithm",
    "file_name",
    "directory",
    "mailbox_primary_address",
    "upn",
    "recipient",
    "p1_sender",
    "p2_sender",
    "sender_ip",
    "subject",
    "app_name",
)

# Per-list cap in entity_context; an incident can carry hundreds of entities.
_MAX_ENTITIES_PER_KIND = 50


def _entity_to_dict(entity: Any) -> Dict[str, Any]:
    data = entity.as_dict()
    kept = {k: data[k] for k in _ENTITY_FIELDS if data.get(k)}
    kept["kind"] = str(data.get("kind") or "")
    return kept


def _push(values: List[str], value: Any) -> None:
    if value and value not in values and len(values) < _MAX_ENTITIES_PER_KIND:
        values.append(str(value))


def _entity_context(entities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Map Sentinel entities onto the entity_context keys triage reads
    (src_ips / hostnames / usernames), plus the ones Defender also fills."""
    ctx: Dict[str, List[str]] = {
        "src_ips": [],
        "hostnames": [],
        "usernames": [],
        "domains": [],
        "file_hashes": [],
        "file_names": [],
        "email_senders": [],
        "cloud_apps": [],
    }
    for e in entities:
        kind = e.get("kind", "").lower()
        if kind == "host":
            host = e.get("host_name")
            if host and e.get("dns_domain"):
                host = f"{host}.{e['dns_domain']}"
            _push(ctx["hostnames"], host)
        elif kind == "account":
            name = e.get("account_name")
            if name and e.get("upn_suffix"):
                name = f"{name}@{e['upn_suffix']}"
            elif name and e.get("nt_domain"):
                name = f"{e['nt_domain']}\\{name}"
            _push(ctx["usernames"], name)
        elif kind == "ip":
            _push(ctx["src_ips"], e.get("address"))
        elif kind == "url":
            _push(ctx["domains"], e.get("url"))
        elif kind == "dnsresolution":
            _push(ctx["domains"], e.get("domain_name"))
        elif kind == "filehash":
            _push(ctx["file_hashes"], e.get("hash_value"))
        elif kind == "file":
            _push(ctx["file_names"], e.get("file_name"))
        elif kind == "mailbox":
            _push(ctx["usernames"], e.get("mailbox_primary_address") or e.get("upn"))
        elif kind == "mailmessage":
            _push(ctx["usernames"], e.get("recipient"))
            _push(ctx["email_senders"], e.get("p1_sender"))
            _push(ctx["email_senders"], e.get("p2_sender"))
            _push(ctx["src_ips"], e.get("sender_ip"))
        elif kind == "cloudapplication":
            _push(ctx["cloud_apps"], e.get("app_name") or e.get("friendly_name"))
    # Keep the keys every consumer expects; drop empty extras.
    core = ("src_ips", "hostnames", "usernames", "domains", "file_hashes")
    return {k: v for k, v in ctx.items() if k in core or v}


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
    }


class AzureSentinelIngestion(SIEMIngestionService):
    """Azure Sentinel ingestion service."""

    def __init__(self):
        """Initialize Azure Sentinel ingestion."""
        super().__init__()
        self.siem_name = "Azure Sentinel"
        self.config = resolve(AZURE_SENTINEL)
        self._client = None

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

        Raises:
            RuntimeError: the configuration is incomplete.
            Exception: the SDK is missing or the API call failed. Raising, not
                returning ``[]``, is what lets the poller tell a failed poll
                from an empty one and keep its checkpoint.
        """
        absent = missing(self.config, *_REQUIRED_FIELDS)
        if absent:
            raise RuntimeError(
                f"Azure Sentinel configuration incomplete, missing: {', '.join(absent)}"
            )

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
            raise
        except Exception as e:
            logger.error(f"Error fetching Azure Sentinel incidents: {e}")
            raise

        logger.info(f"Fetched {len(incidents)} incidents from Azure Sentinel")
        return incidents

    def _get_client(self):
        # One credential for the service's lifetime, so its token is cached
        # across polls instead of re-issued every interval.
        if self._client is None:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.securityinsight import SecurityInsights

            credential = ClientSecretCredential(
                tenant_id=self.config["tenant_id"],
                client_id=self.config["client_id"],
                client_secret=self.config["client_secret"],
            )
            self._client = SecurityInsights(credential, self.config["subscription_id"])
        return self._client

    def _list_incidents(
        self, start_time: datetime, end_time: datetime, limit: int
    ) -> List[Dict[str, Any]]:
        client = self._get_client()

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
            if len(incidents) >= limit:
                # Newest first, so what is dropped is the oldest of the window.
                logger.warning(
                    "Azure Sentinel: more than %d incidents since %s; the oldest "
                    "were not fetched this poll",
                    limit,
                    _odata_time(start_time),
                )
                break
            incidents.append(_incident_to_dict(incident))
        return incidents

    async def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Attach the incident's entities (hosts, accounts, IPs, files, ...).

        The incidents list does not carry them, and they are what triage and
        enrichment work from. One call per incident, so the poller only asks
        for incidents that passed dedup. A failure degrades to an incident
        without entities rather than failing the poll: the incident itself
        still matters more than the detail.
        """
        incident_id = alert.get("id")
        if not incident_id:
            return alert
        try:
            entities = await asyncio.to_thread(self._list_entities, incident_id)
        except Exception as e:
            logger.warning(
                "Azure Sentinel: entities for incident %s unavailable: %s",
                incident_id,
                e,
            )
            return alert
        return {**alert, "entities": entities}

    def _list_entities(self, incident_id: str) -> List[Dict[str, Any]]:
        result = self._get_client().incidents.list_entities(
            self.config["resource_group"], self.config["workspace_name"], incident_id
        )
        return [_entity_to_dict(e) for e in result.entities or []]

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
            finding_id = f"sentinel-{alert.get('id', uuid.uuid4().hex[:12])}"

            # The findings table has no title column, and Sentinel's
            # description is usually the analytics rule's generic text. Lead
            # with the incident title so it survives storage and reaches
            # triage on the backfill path too.
            title = alert.get("title") or "Azure Sentinel Incident"
            detail = (alert.get("description") or "").strip()
            description = (
                title if not detail or detail == title else f"{title}\n\n{detail}"
            )

            entity_context: Dict[str, Any] = _entity_context(
                alert.get("entities") or []
            )
            for key, value in (
                ("incident_number", alert.get("incident_number")),
                ("sentinel_status", alert.get("status")),
                ("owner", alert.get("owner")),
                ("labels", alert.get("labels")),
                ("tactics", alert.get("tactics")),
                ("alert_count", alert.get("alert_count")),
                ("alert_products", alert.get("alert_product_names")),
            ):
                if value:
                    entity_context[key] = value

            incident_url = alert.get("incident_url")
            evidence_links = (
                [{"type": "incident", "ref": incident_url}] if incident_url else None
            )

            return {
                "finding_id": finding_id,
                "data_source": "azure_sentinel",
                "timestamp": alert.get("created_time") or utcnow().isoformat(),
                "severity": self.normalize_severity(alert.get("severity")),
                "status": "new",
                "title": title,
                "description": description,
                "entity_context": entity_context,
                "evidence_links": evidence_links,
                # Incidents carry tactics, not technique IDs.
                "mitre_predictions": {},
            }

        except Exception as e:
            logger.error(f"Error transforming Azure Sentinel incident: {e}")
            return None
