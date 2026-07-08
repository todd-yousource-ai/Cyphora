"""
Cyphora-S1 — Elastic SIEM Connector

BUG 1 FIX: Queries Elastic Security detection signals via the
Kibana Detection Engine API.

Configuration (environment variables):
    CYPHORA_ELASTIC_HOST    — Kibana host (e.g. https://kibana.corp.com)
    CYPHORA_ELASTIC_API_KEY — Elastic API key (base64 id:api_key)
    CYPHORA_ELASTIC_SPACE   — Kibana space (default: default)
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

_HOST    = os.getenv("CYPHORA_ELASTIC_HOST",    "")
_API_KEY = os.getenv("CYPHORA_ELASTIC_API_KEY", "")
_SPACE   = os.getenv("CYPHORA_ELASTIC_SPACE",   "default")

_SEVERITY_MAP = {"critical": "critical", "high": "high",
                 "medium": "medium",     "low": "low"}


class ElasticConnector(SIEMConnector):
    def __init__(self, host=_HOST, api_key=_API_KEY, space=_SPACE) -> None:
        self._base    = host.rstrip("/")
        self._headers = {"Authorization": f"ApiKey {api_key}",
                         "Content-Type": "application/json", "kbn-xsrf": "true"}
        self._space   = space

    def _is_configured(self) -> bool:
        return bool(self._base and self._headers.get("Authorization") != "ApiKey ")

    def _signals_url(self) -> str:
        return f"{self._base}/s/{self._space}/api/detection_engine/signals/search"

    async def poll(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self._is_configured():
            logger.warning("elastic_connector_not_configured")
            return []
        query = {
            "query": {"bool": {"must": [{"term": {"signal.status": "open"}}]}},
            "size": limit,
            "sort": [{"signal.original_event.created": {"order": "desc"}}],
        }
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=30) as c:
                resp = await c.post(self._signals_url(), json=query)
                resp.raise_for_status()
                hits = resp.json().get("hits", {}).get("hits", [])
                logger.info("elastic_poll_complete", signals=len(hits))
                return hits
        except Exception as exc:
            logger.error("elastic_poll_error", error=str(exc))
            return []

    async def acknowledge(self, alert_id: str) -> bool:
        if not self._is_configured():
            return False
        url = f"{self._base}/s/{self._space}/api/detection_engine/signals/status"
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=15) as c:
                resp = await c.post(url, json={"signal_ids": [alert_id],
                                               "status": "acknowledged"})
                return resp.status_code < 400
        except Exception:
            return False

    async def is_available(self) -> bool:
        if not self._is_configured():
            return False
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=5) as c:
                resp = await c.get(f"{self._base}/api/status")
                return resp.status_code == 200
        except Exception:
            return False

    def normalise(self, raw: Dict[str, Any]) -> SecurityEvent:
        src     = raw.get("_source", {})
        signal  = src.get("signal", {})
        rule    = signal.get("rule", {})
        orig    = signal.get("original_event", {})

        rule_name = rule.get("name", "")
        severity  = rule.get("severity", "medium").lower()
        risk      = rule.get("risk_score", 50)

        # Try to extract entity information from the original event
        src_ip   = (src.get("source", {}).get("ip")
                    or orig.get("source", {}).get("ip"))
        src_host = (src.get("host", {}).get("name")
                    or orig.get("host", {}).get("name"))
        user     = (src.get("user", {}).get("name")
                    or orig.get("user", {}).get("name"))

        # Infer event type from MITRE tactics if present
        tactics  = rule.get("threat", [{}])
        tactic   = tactics[0].get("tactic", {}).get("name", "") if tactics else ""
        event_type = self._infer_event_type(rule_name, tactic)

        return SecurityEvent(
            event_id    = raw.get("_id", str(uuid.uuid4())),
            event_type  = event_type,
            severity    = _SEVERITY_MAP.get(severity, "medium"),
            timestamp   = (signal.get("original_event", {}).get("created")
                           or datetime.now(tz=timezone.utc).isoformat()),
            source_ip   = src_ip,
            source_host = src_host,
            user        = user,
            raw_data    = {"source": "elastic_siem", "rule_name": rule_name,
                           "risk_score": risk, **signal},
        )

    @staticmethod
    def _infer_event_type(rule_name: str, tactic: str) -> str:
        lower   = rule_name.lower()
        ttactic = tactic.lower()
        if ttactic == "credential access" or any(k in lower for k in ["credential","lsass","mimikatz"]):
            return "credential_dump"
        if ttactic == "lateral movement" or any(k in lower for k in ["lateral","psexec"]):
            return "lateral_movement"
        if ttactic == "exfiltration" or "exfil" in lower:
            return "data_exfiltration"
        if ttactic == "impact" or any(k in lower for k in ["ransomware","encrypt"]):
            return "abnormal_file_encryption"
        if ttactic == "privilege escalation" or "escalat" in lower:
            return "privilege_escalation"
        if any(k in lower for k in ["login","auth","password","sign-in"]):
            return "suspicious_login"
        if any(k in lower for k in ["process","script","powershell","execution"]):
            return "abnormal_process_execution"
        return "anomaly_detected"
