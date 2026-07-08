"""
Cyphora-S1 — Splunk SIEM Connector

BUG 1 FIX: Polls Splunk Enterprise/ES for Notable Events via the
REST API and normalises them to SecurityEvent.

Configuration (environment variables):
    CYPHORA_SPLUNK_HOST        — Splunk host (e.g. splunk.corp.com:8089)
    CYPHORA_SPLUNK_TOKEN       — Splunk REST API token (Bearer)
    CYPHORA_SPLUNK_SEARCH_NAME — Saved search name for notable events
                                 (default: Cyphora_Notable_Events)
    CYPHORA_SPLUNK_VERIFY_SSL  — 'true'/'false' (default: true)

Splunk API permissions required:
    search — run saved searches and retrieve results
    indexes_list_all — list available indexes (for health check)
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

_SPLUNK_HOST   = os.getenv("CYPHORA_SPLUNK_HOST", "")
_SPLUNK_TOKEN  = os.getenv("CYPHORA_SPLUNK_TOKEN", "")
_SEARCH_NAME   = os.getenv("CYPHORA_SPLUNK_SEARCH_NAME", "Cyphora_Notable_Events")
_VERIFY_SSL    = os.getenv("CYPHORA_SPLUNK_VERIFY_SSL", "true").lower() != "false"

# Mapping of Splunk urgency → Cyphora severity
_URGENCY_MAP = {
    "critical": "critical", "high": "high",
    "medium": "medium", "low": "low", "informational": "low",
}

# Mapping of Splunk rule_name keywords → Cyphora event_type
_RULE_EVENT_TYPE_HINTS = {
    "credential":   "suspicious_login",    "password":     "suspicious_login",
    "lateral":      "lateral_movement",    "psexec":       "lateral_movement",
    "ransomware":   "abnormal_file_encryption",
    "exfil":        "data_exfiltration",   "exfiltration": "data_exfiltration",
    "escalat":      "privilege_escalation","mimikatz":     "credential_dump",
    "lsass":        "credential_dump",     "process":      "abnormal_process_execution",
}


class SplunkConnector(SIEMConnector):
    """
    Connects to Splunk Enterprise or Splunk ES via the REST API.

    Polls the configured saved search for new Notable Events,
    normalises each result to a SecurityEvent, and acknowledges
    processed events by updating the notable_statuses endpoint.
    """

    def __init__(
        self,
        host:         str  = _SPLUNK_HOST,
        token:        str  = _SPLUNK_TOKEN,
        search_name:  str  = _SEARCH_NAME,
        verify_ssl:   bool = _VERIFY_SSL,
    ) -> None:
        self._base    = f"https://{host}" if host and not host.startswith("http") else host
        self._token   = token
        self._search  = search_name
        self._verify  = verify_ssl
        self._headers = {"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"}

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers=self._headers, verify=self._verify, timeout=30)

    # ── Interface implementation ──────────────────────────────────

    async def poll(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self._base or not self._token:
            logger.warning("splunk_connector_not_configured")
            return []
        url = (f"{self._base}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/"
               f"saved/searches/{self._search}/results?output_mode=json&count={limit}")
        try:
            async with self._client() as c:
                resp = await c.get(url)
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", [])
                logger.info("splunk_poll_complete", alerts=len(results))
                return results
        except httpx.HTTPStatusError as exc:
            logger.error("splunk_poll_http_error", status=exc.response.status_code,
                         url=url)
            return []
        except Exception as exc:
            logger.error("splunk_poll_error", error=str(exc))
            return []

    async def acknowledge(self, alert_id: str) -> bool:
        """Mark notable event as reviewed in Splunk ES."""
        if not self._base or not self._token:
            return False
        url = f"{self._base}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/notable_update"
        try:
            async with self._client() as c:
                resp = await c.post(url, json={
                    "ruleUIDs": [alert_id],
                    "status":   "4",   # 4 = In Progress (prevents re-fetch)
                    "comment":  "Acknowledged by Cyphora-S1",
                })
                return resp.status_code < 400
        except Exception as exc:
            logger.warning("splunk_acknowledge_failed", alert_id=alert_id, error=str(exc))
            return False

    async def is_available(self) -> bool:
        if not self._base or not self._token:
            return False
        try:
            async with self._client() as c:
                resp = await c.get(f"{self._base}/services/server/info?output_mode=json",
                                   timeout=5)
                return resp.status_code == 200
        except Exception:
            return False

    def normalise(self, raw: Dict[str, Any]) -> SecurityEvent:
        """Convert a Splunk Notable Event result row to a SecurityEvent."""
        rule_name  = raw.get("rule_name", raw.get("search_name", ""))
        urgency    = raw.get("urgency", "medium").lower()
        src_ip     = raw.get("src", raw.get("src_ip", raw.get("source", None)))
        dest_host  = raw.get("dest", raw.get("dest_host", None))
        user       = raw.get("user", raw.get("src_user", None))
        event_time = raw.get("_time", datetime.now(tz=timezone.utc).isoformat())

        event_type = self._infer_event_type(rule_name, raw)

        return SecurityEvent(
            event_id    = raw.get("event_id", str(uuid.uuid4())),
            event_type  = event_type,
            severity    = _URGENCY_MAP.get(urgency, "medium"),
            timestamp   = event_time,
            source_ip   = src_ip,
            source_host = dest_host,
            user        = user,
            raw_data    = {"source": "splunk", "rule_name": rule_name, **raw},
        )

    @staticmethod
    def _infer_event_type(rule_name: str, raw: Dict) -> str:
        lower = rule_name.lower()
        for keyword, etype in _RULE_EVENT_TYPE_HINTS.items():
            if keyword in lower:
                return etype
        tag = raw.get("tag", "")
        if "authentication" in str(tag).lower():
            return "suspicious_login"
        return "anomaly_detected"
