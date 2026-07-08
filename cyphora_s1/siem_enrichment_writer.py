"""
Cyphora-S1 — SIEM Enrichment Writer

BUG 5 FIX: Writes Cyphora AI investigation findings back to the
originating SIEM alert so analysts see enrichment inside their existing
workflow without switching to a separate Cyphora interface.

Fields written back to each SIEM alert:
    cyphora_confidence_score  — consensus score (0.0–1.0)
    cyphora_mitre_ttps        — comma-separated MITRE technique IDs
    cyphora_kill_chain_steps  — number of kill chain stages identified
    cyphora_severity          — Cyphora severity assessment
    cyphora_case_url          — link to Cyphora investigation
    cyphora_recommended_actions — list of recommended actions
    cyphora_analyst_report    — plain-English executive summary (first 500 chars)

One writer class per SIEM platform:
    SplunkEnrichmentWriter
    SentinelEnrichmentWriter
    QRadarEnrichmentWriter
    ElasticEnrichmentWriter
    ChronicleEnrichmentWriter
    ExabeamEnrichmentWriter (log-only — no write-back API)
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)

_CYPHORA_APP_URL = os.getenv("CYPHORA_APP_URL", "https://app.cyphora-s1.io")


# ─────────────────────────────────────────────
# Enrichment payload helper
# ─────────────────────────────────────────────

def build_enrichment_fields(
    event_id:         str,
    consensus_score:  float,
    mitre_ttps:       List[str],
    kill_chain_steps: int,
    severity:         str,
    recommended_actions: List[str],
    analyst_report:   str = "",
) -> Dict[str, Any]:
    """
    Build the standard Cyphora enrichment payload that is written back
    to SIEM alerts.  All fields use the 'cyphora_' prefix to avoid
    collisions with native SIEM fields.
    """
    return {
        "cyphora_confidence_score":   round(consensus_score, 4),
        "cyphora_mitre_ttps":         ", ".join(mitre_ttps[:10]),
        "cyphora_kill_chain_steps":   kill_chain_steps,
        "cyphora_severity":           severity,
        "cyphora_case_url":           f"{_CYPHORA_APP_URL}/investigations/{event_id}",
        "cyphora_recommended_actions":"; ".join(recommended_actions[:6]),
        "cyphora_analyst_report":     analyst_report[:500],
        "cyphora_enriched":           True,
    }


# ─────────────────────────────────────────────
# Base
# ─────────────────────────────────────────────

class BaseSIEMEnrichmentWriter(ABC):
    """Write Cyphora findings back to the originating SIEM alert."""

    @abstractmethod
    async def write_enrichment(
        self,
        alert_id:         str,
        enrichment_fields: Dict[str, Any],
    ) -> bool:
        """
        Write enrichment_fields to the SIEM alert identified by alert_id.
        Returns True on success.
        """
        ...

    async def enrich(
        self,
        event_id:         str,
        consensus_score:  float,
        mitre_ttps:       List[str],
        kill_chain_steps: int,
        severity:         str,
        recommended_actions: List[str],
        analyst_report:   str = "",
    ) -> bool:
        """Convenience method: build fields and write back in one call."""
        fields = build_enrichment_fields(
            event_id=event_id,
            consensus_score=consensus_score,
            mitre_ttps=mitre_ttps,
            kill_chain_steps=kill_chain_steps,
            severity=severity,
            recommended_actions=recommended_actions,
            analyst_report=analyst_report,
        )
        success = await self.write_enrichment(event_id, fields)
        logger.info(
            "siem_enrichment_written",
            siem=type(self).__name__,
            event_id=event_id,
            success=success,
            ttps=len(mitre_ttps),
            confidence=round(consensus_score, 3),
        )
        return success


# ─────────────────────────────────────────────
# Splunk
# ─────────────────────────────────────────────

class SplunkEnrichmentWriter(BaseSIEMEnrichmentWriter):
    """
    Updates a Splunk notable event with Cyphora enrichment fields
    via the Splunk REST API notable update endpoint.
    """

    def __init__(self, host: str = "", token: str = "", verify_ssl: bool = True) -> None:
        self._base    = f"https://{host}" if host and not host.startswith("http") else host
        self._headers = {"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"}
        self._verify  = verify_ssl

    async def write_enrichment(self, alert_id: str, fields: Dict[str, Any]) -> bool:
        if not self._base:
            logger.warning("splunk_enrichment_writer_not_configured")
            return False
        url = (f"{self._base}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/"
               f"notable_update")
        payload = {"ruleUIDs": [alert_id], "comment": str(fields), "status": "2"}
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=15) as c:
                resp = await c.post(url, json=payload)
                return resp.status_code < 400
        except Exception as exc:
            logger.error("splunk_enrichment_write_failed", alert_id=alert_id, error=str(exc))
            return False


# ─────────────────────────────────────────────
# Microsoft Sentinel
# ─────────────────────────────────────────────

class SentinelEnrichmentWriter(BaseSIEMEnrichmentWriter):
    """
    Patches a Sentinel Incident with Cyphora enrichment as labels and comments.
    """

    def __init__(self, tenant_id: str = "", client_id: str = "",
                 client_secret: str = "", sub_id: str = "",
                 rg: str = "", workspace_id: str = "") -> None:
        self._tenant   = tenant_id
        self._client   = client_id
        self._secret   = client_secret
        self._sub      = sub_id
        self._rg       = rg
        self._ws       = workspace_id
        self._token: Optional[str] = None

    def _is_configured(self) -> bool:
        return all([self._tenant, self._client, self._secret, self._sub, self._rg, self._ws])

    async def _get_token(self) -> str:
        url = f"https://login.microsoftonline.com/{self._tenant}/oauth2/v2.0/token"
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(url, data={
                "grant_type": "client_credentials", "client_id": self._client,
                "client_secret": self._secret, "scope": "https://management.azure.com/.default"})
            resp.raise_for_status()
            self._token = resp.json()["access_token"]
            return self._token

    async def write_enrichment(self, alert_id: str, fields: Dict[str, Any]) -> bool:
        if not self._is_configured():
            logger.warning("sentinel_enrichment_writer_not_configured")
            return False
        base_url = (f"https://management.azure.com/subscriptions/{self._sub}/"
                    f"resourceGroups/{self._rg}/providers/Microsoft.OperationalInsights/"
                    f"workspaces/{self._ws}/providers/Microsoft.SecurityInsights")
        token   = self._token or await self._get_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Add a comment with the enrichment JSON
        comment_url = f"{base_url}/incidents/{alert_id}/comments?api-version=2023-11-01"
        comment_body = {"properties": {"message": (
            f"Cyphora-S1 AI Enrichment\n"
            f"Confidence: {fields.get('cyphora_confidence_score')}\n"
            f"MITRE TTPs: {fields.get('cyphora_mitre_ttps')}\n"
            f"Kill Chain: {fields.get('cyphora_kill_chain_steps')} steps\n"
            f"Case: {fields.get('cyphora_case_url')}\n"
            f"Actions: {fields.get('cyphora_recommended_actions')}\n"
            f"Summary: {fields.get('cyphora_analyst_report', '')}"
        )}}
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.post(comment_url, headers=headers, json=comment_body)
                if resp.status_code == 401:
                    self._token = None
                    token   = await self._get_token()
                    headers["Authorization"] = f"Bearer {token}"
                    resp = await c.post(comment_url, headers=headers, json=comment_body)
                return resp.status_code < 400
        except Exception as exc:
            logger.error("sentinel_enrichment_write_failed", alert_id=alert_id, error=str(exc))
            return False


# ─────────────────────────────────────────────
# QRadar
# ─────────────────────────────────────────────

class QRadarEnrichmentWriter(BaseSIEMEnrichmentWriter):
    """Adds Cyphora enrichment as a QRadar offense note."""

    def __init__(self, host: str = "", token: str = "", verify_ssl: bool = True) -> None:
        self._base    = f"https://{host}" if host and not host.startswith("http") else host
        self._headers = {"SEC": token, "Accept": "application/json",
                         "Content-Type": "application/json", "Version": "19.0"}
        self._verify  = verify_ssl

    async def write_enrichment(self, alert_id: str, fields: Dict[str, Any]) -> bool:
        if not self._base:
            logger.warning("qradar_enrichment_writer_not_configured")
            return False
        url  = f"{self._base}/api/siem/offenses/{alert_id}/notes"
        note = (f"Cyphora-S1 AI Enrichment\n"
                f"Confidence Score: {fields.get('cyphora_confidence_score')}\n"
                f"MITRE TTPs: {fields.get('cyphora_mitre_ttps')}\n"
                f"Kill Chain Steps: {fields.get('cyphora_kill_chain_steps')}\n"
                f"Case URL: {fields.get('cyphora_case_url')}\n"
                f"Recommended Actions: {fields.get('cyphora_recommended_actions')}")
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=15) as c:
                resp = await c.post(url, json={"note_text": note})
                return resp.status_code < 400
        except Exception as exc:
            logger.error("qradar_enrichment_write_failed", alert_id=alert_id, error=str(exc))
            return False


# ─────────────────────────────────────────────
# Elastic
# ─────────────────────────────────────────────

class ElasticEnrichmentWriter(BaseSIEMEnrichmentWriter):
    """Updates an Elastic Security signal with Cyphora enrichment tags and metadata."""

    def __init__(self, host: str = "", api_key: str = "", space: str = "default") -> None:
        self._base    = host.rstrip("/")
        self._headers = {"Authorization": f"ApiKey {api_key}",
                         "Content-Type": "application/json", "kbn-xsrf": "true"}
        self._space   = space

    async def write_enrichment(self, alert_id: str, fields: Dict[str, Any]) -> bool:
        if not self._base:
            logger.warning("elastic_enrichment_writer_not_configured")
            return False
        url  = (f"{self._base}/s/{self._space}/api/detection_engine/signals/tags")
        tags = [
            f"cyphora:confidence={fields.get('cyphora_confidence_score')}",
            f"cyphora:ttps={fields.get('cyphora_mitre_ttps', '')[:50]}",
            f"cyphora:case={fields.get('cyphora_case_url')}",
        ]
        payload = {"signal_ids": [alert_id], "tags": {"add": tags, "remove": []}}
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=15) as c:
                resp = await c.post(url, json=payload)
                return resp.status_code < 400
        except Exception as exc:
            logger.error("elastic_enrichment_write_failed", alert_id=alert_id, error=str(exc))
            return False


# ─────────────────────────────────────────────
# Chronicle
# ─────────────────────────────────────────────

class ChronicleEnrichmentWriter(BaseSIEMEnrichmentWriter):
    """Adds a Cyphora comment to a Chronicle SOAR case."""

    def __init__(self, host: str = "", token: str = "", verify_ssl: bool = True) -> None:
        self._base    = host.rstrip("/")
        self._headers = {"AppKey": token, "Content-Type": "application/json"}
        self._verify  = verify_ssl

    async def write_enrichment(self, alert_id: str, fields: Dict[str, Any]) -> bool:
        if not self._base:
            logger.warning("chronicle_enrichment_writer_not_configured")
            return False
        url  = f"{self._base}/api/external/v1/cases/{alert_id}/AddComment"
        body = {"comment": (
            f"Cyphora-S1 AI Enrichment\n"
            f"Confidence: {fields.get('cyphora_confidence_score')}\n"
            f"MITRE TTPs: {fields.get('cyphora_mitre_ttps')}\n"
            f"Case: {fields.get('cyphora_case_url')}\n"
            f"Actions: {fields.get('cyphora_recommended_actions')}"
        )}
        try:
            async with httpx.AsyncClient(headers=self._headers,
                                         verify=self._verify, timeout=15) as c:
                resp = await c.post(url, json=body)
                return resp.status_code < 400
        except Exception as exc:
            logger.error("chronicle_enrichment_write_failed", alert_id=alert_id, error=str(exc))
            return False


# ─────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────

class SIEMEnrichmentWriterFactory:
    """
    Returns the appropriate enrichment writer for the given SIEM type.

    Usage:
        writer = SIEMEnrichmentWriterFactory.get_writer(
            siem_type="splunk",
            host=os.getenv("CYPHORA_SPLUNK_HOST"),
            token=os.getenv("CYPHORA_SPLUNK_TOKEN"),
        )
        await writer.enrich(event_id=..., consensus_score=0.93, ...)
    """

    @staticmethod
    def get_writer(siem_type: str, **kwargs) -> BaseSIEMEnrichmentWriter:
        siem = siem_type.lower().replace("-", "_").replace(" ", "_")
        writers = {
            "splunk":              SplunkEnrichmentWriter,
            "microsoft_sentinel":  SentinelEnrichmentWriter,
            "sentinel":            SentinelEnrichmentWriter,
            "ibm_qradar":          QRadarEnrichmentWriter,
            "qradar":              QRadarEnrichmentWriter,
            "elastic":             ElasticEnrichmentWriter,
            "elastic_siem":        ElasticEnrichmentWriter,
            "google_chronicle":    ChronicleEnrichmentWriter,
            "chronicle":           ChronicleEnrichmentWriter,
        }
        cls = writers.get(siem)
        if cls is None:
            raise ValueError(
                f"Unknown SIEM type '{siem_type}'. "
                f"Supported: {list(writers.keys())}"
            )
        return cls(**{k: v for k, v in kwargs.items()
                     if v is not None and v != ""})
