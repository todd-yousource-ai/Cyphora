"""
Cyphora-S1 — Microsoft Sentinel SIEM Connector

BUG 1 FIX: Polls Sentinel Incidents via the Microsoft Security
Graph API and normalises them to SecurityEvent.

Configuration (environment variables):
    AZURE_TENANT_ID      — Azure AD tenant ID
    AZURE_CLIENT_ID      — App registration client ID
    AZURE_CLIENT_SECRET  — App registration client secret
    CYPHORA_SENTINEL_WORKSPACE_ID — Log Analytics workspace ID
    CYPHORA_SENTINEL_SUB_ID       — Azure subscription ID
    CYPHORA_SENTINEL_RG           — Resource group name

Required Microsoft Graph API permissions:
    SecurityIncident.ReadWrite.All
    SecurityAlert.ReadWrite.All
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
import structlog

from acda.models.schemas import SecurityEvent
from cyphora_s1.siem_connectors.base import SIEMConnector

logger = structlog.get_logger(__name__)

_TENANT_ID   = os.getenv("AZURE_TENANT_ID",     "")
_CLIENT_ID   = os.getenv("AZURE_CLIENT_ID",     "")
_CLIENT_SEC  = os.getenv("AZURE_CLIENT_SECRET", "")
_WORKSPACE   = os.getenv("CYPHORA_SENTINEL_WORKSPACE_ID", "")
_SUB_ID      = os.getenv("CYPHORA_SENTINEL_SUB_ID", "")
_RG          = os.getenv("CYPHORA_SENTINEL_RG",  "")

_SEVERITY_MAP = {
    "Critical": "critical", "High": "high",
    "Medium": "medium",     "Low": "low", "Informational": "low",
}


class SentinelConnector(SIEMConnector):
    """
    Connects to Microsoft Sentinel via the Security Incidents REST API.
    Uses OAuth2 client_credentials flow for authentication.
    """

    _TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    _INCIDENTS_URL = (
        "https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{rg}/"
        "providers/Microsoft.OperationalInsights/workspaces/{workspace}/"
        "providers/Microsoft.SecurityInsights/incidents"
        "?api-version=2023-11-01&$filter=properties/status ne 'Closed'&$top={limit}"
    )

    def __init__(
        self,
        tenant_id:    str = _TENANT_ID,
        client_id:    str = _CLIENT_ID,
        client_secret:str = _CLIENT_SEC,
        workspace_id: str = _WORKSPACE,
        sub_id:       str = _SUB_ID,
        rg:           str = _RG,
    ) -> None:
        self._tenant    = tenant_id
        self._client_id = client_id
        self._secret    = client_secret
        self._workspace = workspace_id
        self._sub_id    = sub_id
        self._rg        = rg
        self._access_token: Optional[str] = None

    def _is_configured(self) -> bool:
        return all([self._tenant, self._client_id, self._secret,
                    self._workspace, self._sub_id, self._rg])

    async def _get_token(self) -> str:
        url = self._TOKEN_URL.format(tenant_id=self._tenant)
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(url, data={
                "grant_type":    "client_credentials",
                "client_id":     self._client_id,
                "client_secret": self._secret,
                "scope":         "https://management.azure.com/.default",
            })
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            return self._access_token

    async def _headers(self) -> Dict[str, str]:
        token = self._access_token or await self._get_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def poll(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self._is_configured():
            logger.warning("sentinel_connector_not_configured")
            return []
        url = self._INCIDENTS_URL.format(
            sub_id=self._sub_id, rg=self._rg,
            workspace=self._workspace, limit=limit)
        try:
            headers = await self._headers()
            async with httpx.AsyncClient(timeout=30) as c:
                resp = await c.get(url, headers=headers)
                if resp.status_code == 401:
                    self._access_token = None
                    headers = await self._headers()
                    resp = await c.get(url, headers=headers)
                resp.raise_for_status()
                incidents = resp.json().get("value", [])
                logger.info("sentinel_poll_complete", incidents=len(incidents))
                return incidents
        except Exception as exc:
            logger.error("sentinel_poll_error", error=str(exc))
            return []

    async def acknowledge(self, alert_id: str) -> bool:
        """Update Sentinel incident status to In Progress."""
        if not self._is_configured():
            return False
        url = (f"https://management.azure.com/subscriptions/{self._sub_id}/"
               f"resourceGroups/{self._rg}/providers/Microsoft.OperationalInsights/"
               f"workspaces/{self._workspace}/providers/Microsoft.SecurityInsights/"
               f"incidents/{alert_id}?api-version=2023-11-01")
        try:
            headers = await self._headers()
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.patch(url, headers=headers,
                                     json={"properties": {"status": "Active"}})
                return resp.status_code < 400
        except Exception as exc:
            logger.warning("sentinel_acknowledge_failed", alert_id=alert_id, error=str(exc))
            return False

    async def is_available(self) -> bool:
        if not self._is_configured():
            return False
        try:
            await self._get_token()
            return True
        except Exception:
            return False

    def normalise(self, raw: Dict[str, Any]) -> SecurityEvent:
        props  = raw.get("properties", {})
        name   = raw.get("name", str(uuid.uuid4()))
        sev    = props.get("severity", "Medium")
        title  = props.get("title", "Sentinel Alert")
        status = props.get("status", "New")

        # Extract entities for host/user/IP
        entities = props.get("relatedEntities", [])
        src_ip   = next((e.get("properties", {}).get("address")
                         for e in entities if e.get("kind") == "Ip"), None)
        src_host = next((e.get("properties", {}).get("hostName")
                         for e in entities if e.get("kind") == "Host"), None)
        user     = next((e.get("properties", {}).get("accountName")
                         for e in entities if e.get("kind") == "Account"), None)

        event_type = self._infer_event_type(title, props.get("tactics", []))

        return SecurityEvent(
            event_id    = name,
            event_type  = event_type,
            severity    = _SEVERITY_MAP.get(sev, "medium"),
            timestamp   = props.get("createdTimeUtc",
                                    datetime.now(tz=timezone.utc).isoformat()),
            source_ip   = src_ip,
            source_host = src_host,
            user        = user,
            raw_data    = {"source": "microsoft_sentinel", "title": title,
                           "status": status, **props},
        )

    @staticmethod
    def _infer_event_type(title: str, tactics: List[str]) -> str:
        lower   = title.lower()
        tactics_lower = [t.lower() for t in tactics]
        if any(t in tactics_lower for t in ["credentialaccess", "credential access"]):
            return "credential_dump"
        if any(t in tactics_lower for t in ["lateralmovement", "lateral movement"]):
            return "lateral_movement"
        if any(t in tactics_lower for t in ["exfiltration"]):
            return "data_exfiltration"
        if any(t in tactics_lower for t in ["impact"]):
            return "abnormal_file_encryption"
        if any(t in tactics_lower for t in ["privilegeescalation", "privilege escalation"]):
            return "privilege_escalation"
        if any(k in lower for k in ["login", "sign-in", "authentication", "password"]):
            return "suspicious_login"
        if any(k in lower for k in ["process", "execution", "script"]):
            return "abnormal_process_execution"
        return "anomaly_detected"
