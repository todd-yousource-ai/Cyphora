"""
Cyphora-S1 — Production Log Ingestion Adapters
===============================================
Real-world connectors for cloud, identity, endpoint, and network sources.
Each adapter implements BaseSourceAdapter from acda.runtime.data_collector
and can be registered into _ADAPTER_MAP to replace simulated adapters.

Supported sources
─────────────────
  aws_cloudtrail    → AWS CloudTrail Lake / S3 via boto3
  azure_ad          → Microsoft Entra ID (Azure AD) via Graph API
  okta              → Okta System Log REST API
  crowdstrike       → CrowdStrike Falcon Data Replicator / Event Streams
  palo_alto         → Palo Alto Networks PAN-OS Syslog / Cortex XSOAR API
  github            → GitHub Audit Log REST API (Org-level)
  gcp_audit         → Google Cloud Audit Logs via Cloud Logging API

Usage
─────
    from cyphora_s1.cyphora_ingest import register_all_adapters
    register_all_adapters(config)          # call before any DataCollector

Configuration is loaded from environment variables (see CyphoraIngestConfig).
All adapters are async, paged, and rate-limit-aware.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
import structlog

from acda.runtime.data_collector import BaseSourceAdapter, _ADAPTER_MAP
from acda.models.schemas import SecurityEvent

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────


class CyphoraIngestConfig:
    """
    Reads all integration credentials from environment variables.
    Never hard-code credentials — use .env locally, K8s secrets in prod.
    """

    # AWS
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    aws_access_key_id: Optional[str] = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_cloudtrail_log_group: str = os.getenv(
        "AWS_CLOUDTRAIL_LOG_GROUP", "/aws/cloudtrail"
    )

    # Azure AD / Microsoft Entra
    azure_tenant_id: Optional[str] = os.getenv("AZURE_TENANT_ID")
    azure_client_id: Optional[str] = os.getenv("AZURE_CLIENT_ID")
    azure_client_secret: Optional[str] = os.getenv("AZURE_CLIENT_SECRET")

    # Okta
    okta_domain: Optional[str] = os.getenv("OKTA_DOMAIN")  # e.g. corp.okta.com
    okta_api_token: Optional[str] = os.getenv("OKTA_API_TOKEN")

    # CrowdStrike Falcon
    crowdstrike_client_id: Optional[str] = os.getenv("CROWDSTRIKE_CLIENT_ID")
    crowdstrike_client_secret: Optional[str] = os.getenv("CROWDSTRIKE_CLIENT_SECRET")
    crowdstrike_base_url: str = os.getenv(
        "CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com"
    )

    # Palo Alto Networks
    pan_base_url: Optional[str] = os.getenv(
        "PAN_BASE_URL"
    )  # e.g. https://panorama.corp:443
    pan_api_key: Optional[str] = os.getenv("PAN_API_KEY")

    # GitHub
    github_org: Optional[str] = os.getenv("GITHUB_ORG")
    github_token: Optional[str] = os.getenv("GITHUB_TOKEN")

    # GCP
    gcp_project_id: Optional[str] = os.getenv("GCP_PROJECT_ID")
    gcp_service_account_json: Optional[str] = os.getenv("GCP_SERVICE_ACCOUNT_JSON")

    # ── CEF Log File Paths (new in v2.3) ──────────────────────────
    # Set these to point Cyphora at exported CEF log files on disk.
    # When set, the CEF-based adapters replace the live API adapters
    # for the corresponding vendor — no API credentials required.
    #
    # CYPHORA_CEF_LOG              path to a single mixed-vendor CEF file
    # CYPHORA_CEF_CROWDSTRIKE      path to a CrowdStrike-only CEF file
    # CYPHORA_CEF_CORTEX_XDR      path to a Palo Alto Cortex XDR CEF file
    # CYPHORA_CEF_OKTA             path to an Okta-only CEF file
    cef_log_mixed: Optional[str] = os.getenv("CYPHORA_CEF_LOG")
    cef_crowdstrike: Optional[str] = os.getenv("CYPHORA_CEF_CROWDSTRIKE")
    cef_cortex_xdr: Optional[str] = os.getenv("CYPHORA_CEF_CORTEX_XDR")
    cef_okta: Optional[str] = os.getenv("CYPHORA_CEF_OKTA")


_cfg = CyphoraIngestConfig()


# ─────────────────────────────────────────────────────────────
# AWS CloudTrail Adapter
# ─────────────────────────────────────────────────────────────


class AWSCloudTrailAdapter(BaseSourceAdapter):
    """
    Queries AWS CloudTrail via CloudWatch Logs Insights.
    Requires: boto3, AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    IAM policy needed: logs:StartQuery, logs:GetQueryResults, logs:DescribeQueries
    """

    def __init__(
        self,
        log_group: str = _cfg.aws_cloudtrail_log_group,
        region: str = _cfg.aws_region,
        access_key: Optional[str] = _cfg.aws_access_key_id,
        secret_key: Optional[str] = _cfg.aws_secret_access_key,
    ) -> None:
        self._log_group = log_group
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 1000,
    ) -> List[Dict[str, Any]]:
        try:
            import boto3  # optional dep
        except ImportError:
            logger.warning("boto3_not_installed_aws_cloudtrail_unavailable")
            return []

        loop = asyncio.get_event_loop()
        client = boto3.client(
            "logs",
            region_name=self._region,
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
        )

        # Build query — filter by user or source IP if available
        filters = []
        if event.user:
            filters.append(f'| filter userIdentity.userName = "{event.user}"')
        if event.source_ip:
            filters.append(f'| filter sourceIPAddress = "{event.source_ip}"')
        filter_str = " ".join(filters) if filters else ""

        query_str = (
            f"fields @timestamp, eventName, eventSource, userIdentity.userName, "
            f"sourceIPAddress, errorCode, requestParameters "
            f"{filter_str} "
            f"| sort @timestamp desc | limit {min(max_records, 10000)}"
        )

        try:
            # Start query (async-compatible via executor)
            start_resp = await loop.run_in_executor(
                None,
                lambda: client.start_query(
                    logGroupName=self._log_group,
                    startTime=int(since.timestamp()),
                    endTime=int(until.timestamp()),
                    queryString=query_str,
                ),
            )
            query_id = start_resp["queryId"]

            # Poll until complete (max 30s)
            for _ in range(30):
                await asyncio.sleep(1)
                result = await loop.run_in_executor(
                    None,
                    lambda: client.get_query_results(queryId=query_id),
                )
                if result["status"] in ("Complete", "Failed", "Cancelled"):
                    break

            records = []
            for row in result.get("results", []):
                record = {field["field"]: field["value"] for field in row}
                record["source"] = "aws_cloudtrail"
                records.append(record)

            logger.info("aws_cloudtrail_query_complete", count=len(records))
            return records

        except Exception as exc:
            logger.error("aws_cloudtrail_query_failed", error=str(exc))
            return []


# ─────────────────────────────────────────────────────────────
# Azure AD / Microsoft Entra Adapter
# ─────────────────────────────────────────────────────────────


class AzureADAdapter(BaseSourceAdapter):
    """
    Queries Microsoft Entra ID (Azure AD) Sign-in and Audit logs via Graph API.
    Requires: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
    App permissions: AuditLog.Read.All, Directory.Read.All
    """

    _TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    _GRAPH_SIGNIN = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    _GRAPH_AUDIT = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"

    def __init__(
        self,
        tenant_id: Optional[str] = _cfg.azure_tenant_id,
        client_id: Optional[str] = _cfg.azure_client_id,
        client_secret: Optional[str] = _cfg.azure_client_secret,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    async def _get_token(self) -> Optional[str]:
        """Fetch or refresh OAuth2 client-credentials token."""
        import time

        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        if not all([self._tenant_id, self._client_id, self._client_secret]):
            logger.warning("azure_ad_credentials_missing")
            return None
        url = self._TOKEN_URL.format(tenant_id=self._tenant_id)
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data["access_token"]
            import time as t

            self._token_expiry = t.time() + data.get("expires_in", 3600)
            return self._token

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 500,
    ) -> List[Dict[str, Any]]:
        token = await self._get_token()
        if not token:
            return []

        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        until_str = until.strftime("%Y-%m-%dT%H:%M:%SZ")

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        filters = [f"createdDateTime ge {since_str}", f"createdDateTime le {until_str}"]
        if event.user:
            filters.append(f"userPrincipalName eq '{event.user}'")
        filter_param = " and ".join(filters)

        records: List[Dict[str, Any]] = []
        next_url: Optional[str] = (
            f"{self._GRAPH_SIGNIN}?$filter={filter_param}&$top={min(max_records, 999)}"
        )

        async with httpx.AsyncClient(timeout=30) as client:
            fetched = 0
            while next_url and fetched < max_records:
                try:
                    resp = await client.get(next_url, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
                    page = data.get("value", [])
                    for item in page:
                        item["source"] = "azure_ad"
                        records.append(item)
                    fetched += len(page)
                    next_url = data.get("@odata.nextLink")
                except Exception as exc:
                    logger.error("azure_ad_page_fetch_failed", error=str(exc))
                    break

        logger.info("azure_ad_query_complete", count=len(records))
        return records[:max_records]


# ─────────────────────────────────────────────────────────────
# Okta System Log Adapter
# ─────────────────────────────────────────────────────────────


class OktaAdapter(BaseSourceAdapter):
    """
    Queries Okta System Log API.
    Requires: OKTA_DOMAIN (e.g. corp.okta.com), OKTA_API_TOKEN
    Okta API permission: okta.logs.read
    """

    def __init__(
        self,
        domain: Optional[str] = _cfg.okta_domain,
        api_token: Optional[str] = _cfg.okta_api_token,
    ) -> None:
        self._domain = domain
        self._api_token = api_token

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 1000,
    ) -> List[Dict[str, Any]]:
        if not self._domain or not self._api_token:
            logger.warning("okta_credentials_missing")
            return []

        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        until_str = until.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        base_url = f"https://{self._domain}/api/v1/logs"
        params: Dict[str, Any] = {
            "since": since_str,
            "until": until_str,
            "limit": min(max_records, 1000),
        }
        if event.user:
            params["filter"] = f'actor.alternateId eq "{event.user}"'

        headers = {
            "Authorization": f"SSWS {self._api_token}",
            "Accept": "application/json",
        }

        records: List[Dict[str, Any]] = []
        next_url: Optional[str] = base_url

        async with httpx.AsyncClient(timeout=30) as client:
            fetched = 0
            while next_url and fetched < max_records:
                try:
                    resp = await client.get(
                        next_url,
                        headers=headers,
                        params=params if next_url == base_url else None,
                    )
                    resp.raise_for_status()
                    page = resp.json()
                    for item in page:
                        item["source"] = "okta"
                        records.append(item)
                    fetched += len(page)
                    # Okta returns next link in Link header
                    link_header = resp.headers.get("Link", "")
                    next_url = None
                    for part in link_header.split(","):
                        if 'rel="next"' in part:
                            next_url = part.split(";")[0].strip().strip("<>")
                            break
                except Exception as exc:
                    logger.error("okta_page_fetch_failed", error=str(exc))
                    break

        logger.info("okta_query_complete", count=len(records))
        return records[:max_records]


# ─────────────────────────────────────────────────────────────
# CrowdStrike Falcon Adapter
# ─────────────────────────────────────────────────────────────


class CrowdStrikeAdapter(BaseSourceAdapter):
    """
    Queries CrowdStrike Falcon via the Detections and Events Stream APIs.
    Requires: CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET
    Scope needed: detections:read, event-streams:read
    """

    _TOKEN_URL = "{base}/oauth2/token"
    _DETECTIONS_URL = "{base}/detects/queries/detects/v1"
    _DETECTION_DETAIL_URL = "{base}/detects/entities/summaries/GET/v1"

    def __init__(
        self,
        base_url: str = _cfg.crowdstrike_base_url,
        client_id: Optional[str] = _cfg.crowdstrike_client_id,
        client_secret: Optional[str] = _cfg.crowdstrike_client_secret,
    ) -> None:
        self._base = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    async def _get_token(self) -> Optional[str]:
        import time

        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        if not self._client_id or not self._client_secret:
            logger.warning("crowdstrike_credentials_missing")
            return None
        url = self._TOKEN_URL.format(base=self._base)
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                url,
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("access_token")
            import time as t

            self._token_expiry = t.time() + data.get("expires_in", 1799)
            return self._token

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 500,
    ) -> List[Dict[str, Any]]:
        token = await self._get_token()
        if not token:
            return []

        headers = {"Authorization": f"Bearer {token}"}
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        params = {
            "filter": f"first_behavior:>'{since_str}'",
            "limit": min(max_records, 500),
            "sort": "first_behavior.desc",
        }
        if event.source_host:
            params["filter"] += f"+device.hostname:'{event.source_host}'"

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                # Step 1: Get detection IDs
                resp = await client.get(
                    self._DETECTIONS_URL.format(base=self._base),
                    headers=headers,
                    params=params,
                )
                resp.raise_for_status()
                detection_ids = resp.json().get("resources", [])

                if not detection_ids:
                    return []

                # Step 2: Fetch detection details
                detail_resp = await client.post(
                    self._DETECTION_DETAIL_URL.format(base=self._base),
                    headers={**headers, "Content-Type": "application/json"},
                    json={"ids": detection_ids[:max_records]},
                )
                detail_resp.raise_for_status()
                detections = detail_resp.json().get("resources", [])
                for d in detections:
                    d["source"] = "crowdstrike_falcon"
                logger.info("crowdstrike_query_complete", count=len(detections))
                return detections

            except Exception as exc:
                logger.error("crowdstrike_query_failed", error=str(exc))
                return []


# ─────────────────────────────────────────────────────────────
# Palo Alto Networks Adapter
# ─────────────────────────────────────────────────────────────


class PaloAltoAdapter(BaseSourceAdapter):
    """
    Queries Palo Alto Networks PAN-OS threat and traffic logs via XML API.
    Requires: PAN_BASE_URL (Panorama or firewall), PAN_API_KEY
    Role needed: superreader (or custom with Log Viewing)
    """

    def __init__(
        self,
        base_url: Optional[str] = _cfg.pan_base_url,
        api_key: Optional[str] = _cfg.pan_api_key,
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 500,
    ) -> List[Dict[str, Any]]:
        if not self._base_url or not self._api_key:
            logger.warning("palo_alto_credentials_missing")
            return []

        # Build PAN-OS log query expression
        time_filter = (
            f"(receive_time geq '{since.strftime('%Y/%m/%d %H:%M:%S')}') and "
            f"(receive_time leq '{until.strftime('%Y/%m/%d %H:%M:%S')}')"
        )
        if event.source_ip:
            time_filter += f" and (src eq '{event.source_ip}')"

        params = {
            "type": "log",
            "log-type": "threat",
            "query": time_filter,
            "nlogs": str(min(max_records, 5000)),
            "key": self._api_key,
        }

        url = f"{self._base_url}/api/"

        try:
            async with httpx.AsyncClient(
                timeout=30, verify=False
            ) as client:  # corp certs vary
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                # PAN-OS returns XML — parse it
                import xml.etree.ElementTree as ET

                root = ET.fromstring(resp.text)
                records = []
                for entry in root.iter("entry"):
                    record = {child.tag: child.text for child in entry}
                    record["source"] = "palo_alto"
                    records.append(record)
                logger.info("palo_alto_query_complete", count=len(records))
                return records
        except Exception as exc:
            logger.error("palo_alto_query_failed", error=str(exc))
            return []


# ─────────────────────────────────────────────────────────────
# GitHub Audit Log Adapter
# ─────────────────────────────────────────────────────────────


class GitHubAuditAdapter(BaseSourceAdapter):
    """
    Queries GitHub Organization Audit Log API.
    Requires: GITHUB_ORG, GITHUB_TOKEN (personal or GitHub App token)
    Permission: audit_log:read (org-level)
    """

    _AUDIT_URL = "https://api.github.com/orgs/{org}/audit-log"

    def __init__(
        self,
        org: Optional[str] = _cfg.github_org,
        token: Optional[str] = _cfg.github_token,
    ) -> None:
        self._org = org
        self._token = token

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 300,
    ) -> List[Dict[str, Any]]:
        if not self._org or not self._token:
            logger.warning("github_credentials_missing")
            return []

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {
            "per_page": min(max_records, 100),
            "phrase": f"created:{since.strftime('%Y-%m-%d')}..{until.strftime('%Y-%m-%d')}",
        }
        if event.user:
            params["phrase"] += f" actor:{event.user}"

        url = self._AUDIT_URL.format(org=self._org)
        records: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=30) as client:
            next_url: Optional[str] = url
            fetched = 0
            while next_url and fetched < max_records:
                try:
                    resp = await client.get(
                        next_url,
                        headers=headers,
                        params=params if next_url == url else None,
                    )
                    resp.raise_for_status()
                    page = resp.json()
                    for item in page:
                        item["source"] = "github_audit"
                        records.append(item)
                    fetched += len(page)
                    # Parse Link header for next page
                    link = resp.headers.get("Link", "")
                    next_url = None
                    for part in link.split(","):
                        if 'rel="next"' in part:
                            next_url = part.split(";")[0].strip().strip("<>")
                            break
                except Exception as exc:
                    logger.error("github_audit_page_failed", error=str(exc))
                    break

        logger.info("github_audit_query_complete", count=len(records))
        return records[:max_records]


# ─────────────────────────────────────────────────────────────
# GCP Cloud Audit Logs Adapter
# ─────────────────────────────────────────────────────────────


class GCPAuditAdapter(BaseSourceAdapter):
    """
    Queries Google Cloud Audit Logs via Cloud Logging API.
    Requires: GCP_PROJECT_ID, GOOGLE_APPLICATION_CREDENTIALS (or GCP_SERVICE_ACCOUNT_JSON)
    IAM role: roles/logging.viewer
    """

    def __init__(
        self,
        project_id: Optional[str] = _cfg.gcp_project_id,
    ) -> None:
        self._project_id = project_id

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 500,
    ) -> List[Dict[str, Any]]:
        if not self._project_id:
            logger.warning("gcp_project_id_missing")
            return []
        try:
            from google.cloud import logging as gcp_logging  # type: ignore
        except ImportError:
            logger.warning("google_cloud_logging_not_installed")
            return []

        loop = asyncio.get_event_loop()

        def _fetch() -> List[Dict[str, Any]]:
            client = gcp_logging.Client(project=self._project_id)
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            until_str = until.strftime("%Y-%m-%dT%H:%M:%SZ")
            filter_str = (
                f'logName="projects/{self._project_id}/logs/cloudaudit.googleapis.com%2Factivity" '
                f'timestamp>="{since_str}" timestamp<="{until_str}"'
            )
            if event.user:
                filter_str += (
                    f' protoPayload.authenticationInfo.principalEmail="{event.user}"'
                )

            entries = client.list_entries(
                filter_=filter_str,
                max_results=max_records,
                order_by=gcp_logging.DESCENDING,
            )
            records = []
            for entry in entries:
                record = {
                    "source": "gcp_audit",
                    "timestamp": (
                        entry.timestamp.isoformat() if entry.timestamp else None
                    ),
                    "severity": str(entry.severity),
                    "log_name": entry.log_name,
                    "payload": str(entry.payload)[:2000],
                    "resource_type": entry.resource.type if entry.resource else None,
                }
                records.append(record)
            return records

        try:
            records = await loop.run_in_executor(None, _fetch)
            logger.info("gcp_audit_query_complete", count=len(records))
            return records
        except Exception as exc:
            logger.error("gcp_audit_query_failed", error=str(exc))
            return []


# ─────────────────────────────────────────────────────────────
# Registration Helper
# ─────────────────────────────────────────────────────────────


def register_all_adapters(config: Optional[CyphoraIngestConfig] = None) -> None:
    """
    Register all Cyphora-S1 production adapters into the global _ADAPTER_MAP.
    Call this once at startup, before creating any DataCollector instances.

    Adapters with missing credentials are silently skipped and the existing
    simulated adapter (if any) remains in place.

    Example
    -------
        from cyphora_s1.cyphora_ingest import register_all_adapters
        register_all_adapters()
    """
    cfg = config or _cfg
    registered = []

    adapters_to_register = {
        "aws_cloudtrail": (
            AWSCloudTrailAdapter,
            lambda: AWSCloudTrailAdapter(
                log_group=cfg.aws_cloudtrail_log_group,
                region=cfg.aws_region,
                access_key=cfg.aws_access_key_id,
                secret_key=cfg.aws_secret_access_key,
            ),
            [cfg.aws_access_key_id, cfg.aws_secret_access_key],
        ),
        "azure_ad": (
            AzureADAdapter,
            lambda: AzureADAdapter(
                tenant_id=cfg.azure_tenant_id,
                client_id=cfg.azure_client_id,
                client_secret=cfg.azure_client_secret,
            ),
            [cfg.azure_tenant_id, cfg.azure_client_id, cfg.azure_client_secret],
        ),
        "okta": (
            OktaAdapter,
            lambda: OktaAdapter(domain=cfg.okta_domain, api_token=cfg.okta_api_token),
            [cfg.okta_domain, cfg.okta_api_token],
        ),
        "crowdstrike": (
            CrowdStrikeAdapter,
            lambda: CrowdStrikeAdapter(
                base_url=cfg.crowdstrike_base_url,
                client_id=cfg.crowdstrike_client_id,
                client_secret=cfg.crowdstrike_client_secret,
            ),
            [cfg.crowdstrike_client_id, cfg.crowdstrike_client_secret],
        ),
        "palo_alto": (
            PaloAltoAdapter,
            lambda: PaloAltoAdapter(base_url=cfg.pan_base_url, api_key=cfg.pan_api_key),
            [cfg.pan_base_url, cfg.pan_api_key],
        ),
        "github_audit": (
            GitHubAuditAdapter,
            lambda: GitHubAuditAdapter(org=cfg.github_org, token=cfg.github_token),
            [cfg.github_org, cfg.github_token],
        ),
        "gcp_audit": (
            GCPAuditAdapter,
            lambda: GCPAuditAdapter(project_id=cfg.gcp_project_id),
            [cfg.gcp_project_id],
        ),
    }

    for key, (_, factory, creds) in adapters_to_register.items():
        if all(creds):
            try:
                _ADAPTER_MAP[key] = factory()
                registered.append(key)
            except Exception as exc:
                logger.warning(
                    "adapter_registration_failed", adapter=key, error=str(exc)
                )
        else:
            logger.debug("adapter_skipped_missing_credentials", adapter=key)

    logger.info("cyphora_ingest_adapters_registered", adapters=registered)

    # ── Auto-register CEF file adapters if paths are configured ──
    cef_paths = {}
    if cfg.cef_crowdstrike:
        cef_paths["crowdstrike"] = cfg.cef_crowdstrike
    if cfg.cef_cortex_xdr:
        cef_paths["cortex_xdr"] = cfg.cef_cortex_xdr
    if cfg.cef_okta:
        cef_paths["okta"] = cfg.cef_okta

    if cef_paths or cfg.cef_log_mixed:
        try:
            from cyphora_s1.cef_adapters import register_cef_adapters

            cef_stats = register_cef_adapters(
                log_paths=cef_paths if cef_paths else None,
                mixed_file=cfg.cef_log_mixed if not cef_paths else None,
            )
            logger.info("cef_adapters_auto_registered", stats=cef_stats)
        except Exception as exc:
            logger.warning("cef_adapter_auto_registration_failed", error=str(exc))
