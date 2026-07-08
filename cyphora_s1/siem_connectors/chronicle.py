"""
Cyphora-S1 — Google Chronicle SIEM Connector

BUG 1 FIX: Connects to Google Chronicle SOAR API.

Configuration (environment variables):
    CYPHORA_CHRONICLE_HOST           — Chronicle SOAR host
    CYPHORA_CHRONICLE_API_TOKEN      — Chronicle API token
    CYPHORA_CHRONICLE_VERIFY_SSL     — 'true'/'false'
Or use GCP service account (preferred):
    GCP_PROJECT_ID                   — GCP project ID
    GCP_SERVICE_ACCOUNT_JSON         — Service account JSON key
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
import structlog

from acda.models.schemas import SecurityEvent
from cyphora_s1.siem_connectors.base import SIEMConnector

logger = structlog.get_logger(__name__)

_HOST       = os.getenv("CYPHORA_CHRONICLE_HOST",      "")
_TOKEN      = os.getenv("CYPHORA_CHRONICLE_API_TOKEN", "")
_VERIFY_SSL = os.getenv("CYPHORA_CHRONICLE_VERIFY_SSL","true").lower() != "false"

_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFORMATIONAL": "low",
}


class ChronicleConnector(SIEMConnector):
    """Chronicle SOAR case/alert connector."""

    def __init__(self, host=_HOST, token=_TOKEN, verify_ssl=_VERIFY_SSL) -> None:
        self._base    = host.rstrip("/")
        self._headers = {"AppKey": token, "Content-Type": "application/json"}
        self._verify  = verify_ssl

    def _is_configured(self) -> bool:
        return bool(self._base and self._headers.get("AppKey"))

    async def poll(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self._is_configured():
            logger.warning("chronicle_connector_not_configured")
            return []
        url = f"{self._base}/api/external/v1/cases/GetCasesFilteredByPage"
        payload = {"searchRequest": {"filter": {"status": ["OPEN", "IN_PROGRESS"]},
                                     "paging": {"pageSize": limit}}}
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=30) as c:
                resp = await c.post(url, json=payload)
                resp.raise_for_status()
                cases = resp.json().get("cases", [])
                logger.info("chronicle_poll_complete", cases=len(cases))
                return cases
        except Exception as exc:
            logger.error("chronicle_poll_error", error=str(exc))
            return []

    async def acknowledge(self, alert_id: str) -> bool:
        if not self._is_configured():
            return False
        url = f"{self._base}/api/external/v1/cases/{alert_id}/UpdateCaseStatus"
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=15) as c:
                resp = await c.post(url, json={"caseStatus": "IN_PROGRESS"})
                return resp.status_code < 400
        except Exception:
            return False

    async def is_available(self) -> bool:
        if not self._is_configured():
            return False
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=5) as c:
                resp = await c.get(f"{self._base}/api/external/v1/settings/GlobalSettings")
                return resp.status_code == 200
        except Exception:
            return False

    def normalise(self, raw: Dict[str, Any]) -> SecurityEvent:
        case_id   = str(raw.get("id", uuid.uuid4()))
        title     = raw.get("name", raw.get("title", ""))
        priority  = raw.get("priority", "MEDIUM")
        entities  = raw.get("entities", [])

        src_ip   = next((e.get("identifier") for e in entities
                         if e.get("entityType") == "ADDRESS"), None)
        src_host = next((e.get("identifier") for e in entities
                         if e.get("entityType") == "HOSTNAME"), None)
        user     = next((e.get("identifier") for e in entities
                         if e.get("entityType") == "USERNAME"), None)

        return SecurityEvent(
            event_id    = f"chronicle:{case_id}",
            event_type  = self._infer_event_type(title),
            severity    = _SEVERITY_MAP.get(priority.upper(), "medium"),
            timestamp   = raw.get("creationTime",
                                  datetime.now(tz=timezone.utc).isoformat()),
            source_ip   = src_ip,
            source_host = src_host,
            user        = user,
            raw_data    = {"source": "google_chronicle", "case_id": case_id,
                           "title": title, **raw},
        )

    @staticmethod
    def _infer_event_type(title: str) -> str:
        lower = title.lower()
        if any(k in lower for k in ["lateral","psexec","wmi"]):    return "lateral_movement"
        if any(k in lower for k in ["credential","password","lsass"]): return "credential_dump"
        if any(k in lower for k in ["exfil","transfer","upload"]):  return "data_exfiltration"
        if any(k in lower for k in ["ransom","encrypt"]):           return "abnormal_file_encryption"
        if any(k in lower for k in ["escalat","privilege"]):        return "privilege_escalation"
        if any(k in lower for k in ["login","auth","sign"]):        return "suspicious_login"
        if any(k in lower for k in ["process","script","execution"]): return "abnormal_process_execution"
        return "anomaly_detected"
