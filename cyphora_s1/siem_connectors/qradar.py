"""
Cyphora-S1 — IBM QRadar SIEM Connector

BUG 1 FIX: Polls QRadar Offenses via the REST API.

Configuration (environment variables):
    CYPHORA_QRADAR_HOST    — QRadar Console host (e.g. qradar.corp.com)
    CYPHORA_QRADAR_TOKEN   — QRadar SEC token (Authorization: SEC <token>)
    CYPHORA_QRADAR_VERIFY_SSL — 'true'/'false'

API permissions required: ADMIN or OFFENSE_MANAGER role.
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

_HOST       = os.getenv("CYPHORA_QRADAR_HOST",  "")
_TOKEN      = os.getenv("CYPHORA_QRADAR_TOKEN", "")
_VERIFY_SSL = os.getenv("CYPHORA_QRADAR_VERIFY_SSL", "true").lower() != "false"

_SEVERITY_MAP = {10: "critical", 9: "critical", 8: "high", 7: "high",
                 6: "medium",    5: "medium",   4: "low",  3: "low",
                 2: "low",       1: "low",       0: "low"}
_TYPE_MAP = {
    "Authentication": "suspicious_login",
    "Exploit":        "abnormal_process_execution",
    "Recon":          "anomaly_detected",
    "DoS":            "anomaly_detected",
    "Policy":         "anomaly_detected",
    "SuspiciousActivity": "anomaly_detected",
    "CommandAndControl":  "anomaly_detected",
    "User":               "suspicious_login",
}


class QRadarConnector(SIEMConnector):
    def __init__(self, host=_HOST, token=_TOKEN, verify_ssl=_VERIFY_SSL) -> None:
        self._base    = f"https://{host}" if host and not host.startswith("http") else host
        self._headers = {"SEC": token, "Accept": "application/json",
                         "Content-Type": "application/json", "Version": "19.0"}
        self._verify  = verify_ssl

    def _is_configured(self) -> bool:
        return bool(self._base and self._headers.get("SEC"))

    async def poll(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self._is_configured():
            logger.warning("qradar_connector_not_configured")
            return []
        url = (f"{self._base}/api/siem/offenses"
               f"?filter=status%3DOPEN&fields=id,description,offense_type,"
               f"source_address_ids,local_destination_address_ids,username_count,"
               f"magnitude,severity,offense_source,category_count,start_time,"
               f"last_updated_time,event_count&sort=%2Blast_updated_time"
               f"&Range=items%3D0-{limit-1}")
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=30) as c:
                resp = await c.get(url)
                resp.raise_for_status()
                offenses = resp.json()
                logger.info("qradar_poll_complete", offenses=len(offenses))
                return offenses if isinstance(offenses, list) else []
        except Exception as exc:
            logger.error("qradar_poll_error", error=str(exc))
            return []

    async def acknowledge(self, alert_id: str) -> bool:
        if not self._is_configured():
            return False
        url = f"{self._base}/api/siem/offenses/{alert_id}"
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=15) as c:
                resp = await c.post(url, json={"status": "OPEN",
                                               "assigned_to": "cyphora-s1"})
                return resp.status_code < 400
        except Exception as exc:
            logger.warning("qradar_acknowledge_failed", alert_id=alert_id, error=str(exc))
            return False

    async def is_available(self) -> bool:
        if not self._is_configured():
            return False
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=5) as c:
                resp = await c.get(f"{self._base}/api/system/about")
                return resp.status_code == 200
        except Exception:
            return False

    def normalise(self, raw: Dict[str, Any]) -> SecurityEvent:
        offense_id  = str(raw.get("id", uuid.uuid4()))
        description = raw.get("description", "")
        severity    = int(raw.get("severity", 5))
        magnitude   = int(raw.get("magnitude", 5))
        offense_type= raw.get("offense_type", "")
        source      = raw.get("offense_source", "")
        ts_ms       = raw.get("last_updated_time", raw.get("start_time", 0))
        if ts_ms:
            ts = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat()
        else:
            ts = datetime.now(tz=timezone.utc).isoformat()

        event_type = _TYPE_MAP.get(offense_type, "anomaly_detected")
        cyphora_sev = _SEVERITY_MAP.get(max(0, min(10, severity)), "medium")

        return SecurityEvent(
            event_id    = f"qradar:{offense_id}",
            event_type  = event_type,
            severity    = cyphora_sev,
            timestamp   = ts,
            source_ip   = source if source and "." in source else None,
            source_host = None,
            user        = None,
            raw_data    = {"source": "ibm_qradar", "offense_id": offense_id,
                           "description": description, "magnitude": magnitude,
                           "offense_type": offense_type, **raw},
        )
