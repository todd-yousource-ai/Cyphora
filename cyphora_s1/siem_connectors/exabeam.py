"""
Cyphora-S1 — Exabeam SIEM Connector

BUG 1 FIX: Polls Exabeam Advanced Analytics for high-risk sessions.

Configuration:
    CYPHORA_EXABEAM_HOST      — Exabeam host (e.g. https://exabeam.corp.com)
    CYPHORA_EXABEAM_API_KEY   — Exabeam API key
    CYPHORA_EXABEAM_MIN_RISK  — Minimum risk score to fetch (default: 90)
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

_HOST     = os.getenv("CYPHORA_EXABEAM_HOST",    "")
_API_KEY  = os.getenv("CYPHORA_EXABEAM_API_KEY", "")
_MIN_RISK = int(os.getenv("CYPHORA_EXABEAM_MIN_RISK", "90"))


class ExabeamConnector(SIEMConnector):
    def __init__(self, host=_HOST, api_key=_API_KEY, min_risk=_MIN_RISK) -> None:
        self._base     = host.rstrip("/")
        self._headers  = {"Authorization": f"ExaJWT {api_key}",
                          "Content-Type": "application/json"}
        self._min_risk = min_risk

    def _is_configured(self) -> bool:
        return bool(self._base and self._headers.get("Authorization") != "ExaJWT ")

    async def poll(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self._is_configured():
            logger.warning("exabeam_connector_not_configured")
            return []
        url = f"{self._base}/uba/api/users/scores"
        params = {"unit": "day", "numberOfResults": limit,
                  "minRiskScore": self._min_risk}
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=30) as c:
                resp = await c.get(url, params=params)
                resp.raise_for_status()
                sessions = resp.json().get("users", [])
                logger.info("exabeam_poll_complete", high_risk_users=len(sessions))
                return sessions
        except Exception as exc:
            logger.error("exabeam_poll_error", error=str(exc))
            return []

    async def acknowledge(self, alert_id: str) -> bool:
        # Exabeam doesn't have an acknowledge endpoint; return True to suppress re-poll
        return True

    async def is_available(self) -> bool:
        if not self._is_configured():
            return False
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=5) as c:
                resp = await c.get(f"{self._base}/uba/api/status")
                return resp.status_code == 200
        except Exception:
            return False

    def normalise(self, raw: Dict[str, Any]) -> SecurityEvent:
        username  = raw.get("username", raw.get("userId", "unknown"))
        risk      = float(raw.get("riskScore", 0))
        reasons   = raw.get("riskReasons", [])
        sequences = raw.get("sequences", [])

        sev = "critical" if risk >= 95 else ("high" if risk >= 85 else "medium")

        # Determine event type from risk reasons
        reason_text = " ".join(str(r) for r in reasons).lower()
        event_type = self._infer_from_reasons(reason_text)

        ts = raw.get("lastActivityTime", datetime.now(tz=timezone.utc).isoformat())

        return SecurityEvent(
            event_id    = f"exabeam:{username}:{uuid.uuid4().hex[:8]}",
            event_type  = event_type,
            severity    = sev,
            timestamp   = ts,
            source_ip   = None,
            source_host = None,
            user        = username,
            raw_data    = {"source": "exabeam", "risk_score": risk,
                           "risk_reasons": reasons, "sequences": sequences[:5]},
        )

    @staticmethod
    def _infer_from_reasons(text: str) -> str:
        if any(k in text for k in ["lateral","remote","psexec"]): return "lateral_movement"
        if any(k in text for k in ["credential","password","privileged"]): return "suspicious_login"
        if any(k in text for k in ["exfil","upload","transfer"]):  return "data_exfiltration"
        if any(k in text for k in ["escalat","admin","privilege"]): return "privilege_escalation"
        if any(k in text for k in ["login","auth","sign"]):        return "suspicious_login"
        return "anomaly_detected"
