"""
Cyphora-S1 — CEF Log Adapters
==============================
DataCollector adapters that serve CEF log records as investigation
telemetry, and a factory that builds SecurityEvent objects directly
from parsed CEF records.

Three adapter classes (one per vendor):
  CrowdStrikeCEFAdapter  — serves CrowdStrike Falcon CEF records
  CortexXDRCEFAdapter    — serves Palo Alto Cortex XDR CEF records
  OktaCEFAdapter         — serves Okta CEF records

All three share a common base (BaseCEFAdapter) that:
  - Holds an in-memory list of CEFRecord objects loaded at startup
  - Filters by time window and optionally by source IP / user
  - Returns records in the exact format the LLM reasoning ensemble expects

Registration
------------
Call register_cef_adapters(log_paths) once at startup to replace
the generic simulated adapters with real CEF-sourced data.

    from cyphora_s1.cef_adapters import (
        register_cef_adapters, SecurityEventFactory,
    )

    # Point to one or more CEF log files
    register_cef_adapters({
        "crowdstrike": "/var/log/crowdstrike.cef",
        "cortex_xdr":  "/var/log/cortex.cef",
        "okta":        "/var/log/okta.cef",
    })

    # Or load a single mixed-vendor file
    register_cef_adapters(mixed_file="/path/to/combined.cef")

    # Build SecurityEvent objects from a CEF file
    events = SecurityEventFactory.from_file("/path/to/logs.cef")
    for event in events:
        await orchestrator.dispatch(event)
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import structlog

from acda.runtime.data_collector import BaseSourceAdapter, _ADAPTER_MAP
from acda.models.schemas import SecurityEvent
from cyphora_s1.cef_parser import (
    CEFParser,
    CEFRecord,
    CEFVendor,
    parse_cef_file,
    parse_cef_text,
)

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Base CEF DataCollector Adapter
# ─────────────────────────────────────────────────────────────


class BaseCEFAdapter(BaseSourceAdapter):
    """
    Serves pre-loaded CEF records as investigation telemetry.

    Records are filtered by the time window [since, until] using the
    parsed CEF timestamp.  If the window contains no records (e.g. the
    log file is from a different time period), ALL records are returned
    so demos and tests always have data to reason about.

    Additionally filters by source IP and/or user when available on
    the triggering SecurityEvent, to return contextually relevant logs.
    """

    #: Override in subclass with the CEFVendor constant to filter
    VENDOR: str = CEFVendor.UNKNOWN

    def __init__(self, records: List[CEFRecord]):
        self._records = records
        logger.info(
            "cef_adapter_loaded",
            vendor=self.VENDOR,
            records=len(records),
        )

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "BaseCEFAdapter":
        parser = CEFParser()
        all_records = parser.parse_file(path)
        vendor_records = (
            [r for r in all_records if r.vendor == cls.VENDOR]
            if cls.VENDOR != CEFVendor.UNKNOWN
            else all_records
        )
        return cls(vendor_records)

    @classmethod
    def from_text(cls, text: str) -> "BaseCEFAdapter":
        parser = CEFParser()
        all_records = parser.parse_text(text)
        vendor_records = (
            [r for r in all_records if r.vendor == cls.VENDOR]
            if cls.VENDOR != CEFVendor.UNKNOWN
            else all_records
        )
        return cls(vendor_records)

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 1000,
    ) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.01)  # non-blocking yield

        # Filter by time window
        window_records = [
            r for r in self._records if self._in_window(r.timestamp, since, until)
        ]

        # Fall back to all records if window is empty
        # (common when replaying historical log files in demos)
        if not window_records:
            window_records = self._records

        # Contextual filter: prefer records related to the triggering event
        contextual = self._contextual_filter(window_records, event)
        if contextual:
            window_records = contextual

        result = [r.to_dict() for r in window_records[:max_records]]
        logger.debug(
            "cef_adapter_query_complete",
            vendor=self.VENDOR,
            returned=len(result),
        )
        return result

    # ── helpers ───────────────────────────────────────────────

    @staticmethod
    def _in_window(ts: str, since: datetime, until: datetime) -> bool:
        try:
            t = datetime.fromisoformat(ts)
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            return since <= t <= until
        except Exception:
            return False

    @staticmethod
    def _contextual_filter(
        records: List[CEFRecord], event: SecurityEvent
    ) -> List[CEFRecord]:
        """
        Return records that share the triggering event's source IP or user.
        Returns empty list if neither filter produces results (caller falls back).
        """
        matches = []
        for r in records:
            src_match = event.source_ip and r.fields.get("src") == event.source_ip
            host_match = (
                event.source_host and r.fields.get("dvchost") == event.source_host
            )
            user_match = event.user and r.fields.get("suser") == event.user
            if src_match or host_match or user_match:
                matches.append(r)
        return matches


# ─────────────────────────────────────────────────────────────
# Vendor-specific adapters
# ─────────────────────────────────────────────────────────────


class CrowdStrikeCEFAdapter(BaseCEFAdapter):
    """
    Serves CrowdStrike Falcon CEF records for the 'endpoint_logs' and
    'crowdstrike' DataCollector sources.

    Returned dict keys mirror the CrowdStrike Falcon CEF schema:
    dvchost, dvc, suser, Technique, Tactic, CommandLine, ParentProcess,
    DetectId, Severity, FileName, FilePath, fileHash, msg, outcome, etc.
    """

    VENDOR = CEFVendor.CROWDSTRIKE


class CortexXDRCEFAdapter(BaseCEFAdapter):
    """
    Serves Palo Alto Cortex XDR CEF records for the 'network_logs',
    'palo_alto', and 'cortex_xdr' DataCollector sources.

    Returned dict keys mirror the Cortex XDR CEF schema:
    AlertId, Severity, Category, Description, MitreTactic,
    MitreTechnique, PreventionModule, ThreatName, ApplicationName,
    ThreatType, Domain, QueryCount, BehaviorIndicator, ProcessName,
    ConfidenceScore, fileHash, msg, outcome, etc.
    """

    VENDOR = CEFVendor.PALO_ALTO


class OktaCEFAdapter(BaseCEFAdapter):
    """
    Serves Okta CEF records for the 'identity_logs' and 'okta'
    DataCollector sources.

    Returned dict keys mirror the Okta CEF schema:
    SessionId, AuthenticationMethod, DeviceType, Browser, OS,
    EventType, Reason, FailureCount, FactorType, Provider,
    ApplicationName, ApplicationId, Actor, Target,
    FailedAttempts, TimeWindow, GeoLocation, ThreatLevel,
    ResetMethod, InitiatedBy, requestClientApplication, msg, outcome, etc.
    """

    VENDOR = CEFVendor.OKTA


class MixedCEFAdapter(BaseCEFAdapter):
    """
    Serves records from a mixed-vendor CEF file across all sources.
    Useful when all vendor logs are combined into a single SIEM export.
    """

    VENDOR = CEFVendor.UNKNOWN


# ─────────────────────────────────────────────────────────────
# SecurityEvent factory
# ─────────────────────────────────────────────────────────────


class SecurityEventFactory:
    """
    Converts CEF log records directly into SecurityEvent objects ready
    to be dispatched through the AgentOrchestrator.

    Usage
    -----
        events = SecurityEventFactory.from_file("logs.cef")
        for event in events:
            triggered = await orchestrator.dispatch(event)

        # Or from a string
        events = SecurityEventFactory.from_text(cef_string)
    """

    _parser = CEFParser()

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> List[SecurityEvent]:
        records = cls._parser.parse_file(path)
        return [cls._to_event(r) for r in records]

    @classmethod
    def from_text(cls, text: str) -> List[SecurityEvent]:
        records = cls._parser.parse_text(text)
        return [cls._to_event(r) for r in records]

    @classmethod
    def from_record(cls, rec: CEFRecord) -> SecurityEvent:
        return cls._to_event(rec)

    @classmethod
    def _to_event(cls, rec: CEFRecord) -> SecurityEvent:
        d = cls._parser.to_security_event_dict(rec)
        # Ensure event_id is a string (SecurityEvent requires str)
        d["event_id"] = str(d.get("event_id") or uuid.uuid4())
        # Filter to SecurityEvent fields only
        valid_fields = {
            "event_id",
            "event_type",
            "severity",
            "timestamp",
            "source_ip",
            "source_host",
            "user",
            "process",
            "raw_data",
        }
        return SecurityEvent(**{k: v for k, v in d.items() if k in valid_fields})


# ─────────────────────────────────────────────────────────────
# Registration helper
# ─────────────────────────────────────────────────────────────


def register_cef_adapters(
    log_paths: Optional[Dict[str, Union[str, Path]]] = None,
    *,
    mixed_file: Optional[Union[str, Path]] = None,
    cef_text: Optional[str] = None,
) -> Dict[str, int]:
    """
    Register CEF-based adapters into the global _ADAPTER_MAP, replacing
    any previously registered adapters for those sources.

    Parameters
    ----------
    log_paths : dict mapping source-name → file path
        Supported keys:
          "crowdstrike"  → registered as endpoint_logs + crowdstrike
          "cortex_xdr"   → registered as network_logs + palo_alto + cortex_xdr
          "okta"         → registered as identity_logs + okta

    mixed_file : path to a single CEF file containing mixed-vendor records
        Partitions records by vendor and registers each.

    cef_text : raw CEF log content as a string (for in-memory / test use)
        Behaves like mixed_file but reads from string.

    Returns
    -------
    dict mapping adapter name → number of records loaded

    Examples
    --------
        # Separate vendor files
        register_cef_adapters({
            "crowdstrike": "/var/log/cs.cef",
            "cortex_xdr":  "/var/log/cortex.cef",
            "okta":        "/var/log/okta.cef",
        })

        # Single combined export
        register_cef_adapters(mixed_file="/var/log/all.cef")

        # From string (testing / demo)
        register_cef_adapters(cef_text=raw_cef_string)
    """
    stats: Dict[str, int] = {}
    parser = CEFParser()

    # ── Helper: register one adapter under multiple source keys ──
    def _register(adapter: BaseCEFAdapter, source_keys: List[str]) -> None:
        for key in source_keys:
            _ADAPTER_MAP[key] = adapter

    # ── From separate vendor log files ───────────────────────────
    if log_paths:
        for vendor_key, path in log_paths.items():
            path = Path(path)
            if not path.exists():
                logger.warning(
                    "cef_log_file_not_found", path=str(path), vendor=vendor_key
                )
                continue

            records = parser.parse_file(path)

            if vendor_key in ("crowdstrike", "crowdstrike_falcon"):
                cs_recs = [
                    r for r in records if r.vendor == CEFVendor.CROWDSTRIKE
                ] or records
                adapter = CrowdStrikeCEFAdapter(cs_recs)
                _register(adapter, ["endpoint_logs", "crowdstrike"])
                stats["crowdstrike_cef"] = len(cs_recs)

            elif vendor_key in ("cortex_xdr", "palo_alto", "pan"):
                pa_recs = [
                    r for r in records if r.vendor == CEFVendor.PALO_ALTO
                ] or records
                adapter = CortexXDRCEFAdapter(pa_recs)
                _register(adapter, ["network_logs", "palo_alto", "cortex_xdr"])
                stats["cortex_xdr_cef"] = len(pa_recs)

            elif vendor_key in ("okta", "identity"):
                ok_recs = [r for r in records if r.vendor == CEFVendor.OKTA] or records
                adapter = OktaCEFAdapter(ok_recs)
                _register(adapter, ["identity_logs", "okta"])
                stats["okta_cef"] = len(ok_recs)

            else:
                # Generic: register under the given key
                adapter = MixedCEFAdapter(records)
                _ADAPTER_MAP[vendor_key] = adapter
                stats[vendor_key] = len(records)

    # ── From a single mixed file or text string ───────────────────
    raw_text: Optional[str] = None
    if mixed_file:
        raw_text = Path(mixed_file).read_text(encoding="utf-8", errors="replace")
    elif cef_text:
        raw_text = cef_text

    if raw_text:
        all_records = parser.parse_text(raw_text)

        cs_recs = [r for r in all_records if r.vendor == CEFVendor.CROWDSTRIKE]
        pa_recs = [r for r in all_records if r.vendor == CEFVendor.PALO_ALTO]
        ok_recs = [r for r in all_records if r.vendor == CEFVendor.OKTA]

        if cs_recs:
            adapter = CrowdStrikeCEFAdapter(cs_recs)
            _register(adapter, ["endpoint_logs", "crowdstrike"])
            stats["crowdstrike_cef"] = len(cs_recs)

        if pa_recs:
            adapter = CortexXDRCEFAdapter(pa_recs)
            _register(adapter, ["network_logs", "palo_alto", "cortex_xdr"])
            stats["cortex_xdr_cef"] = len(pa_recs)

        if ok_recs:
            adapter = OktaCEFAdapter(ok_recs)
            _register(adapter, ["identity_logs", "okta"])
            stats["okta_cef"] = len(ok_recs)

        if not (cs_recs or pa_recs or ok_recs):
            # Unrecognised vendor — register as generic
            mixed = MixedCEFAdapter(all_records)
            _ADAPTER_MAP["cef_mixed"] = mixed
            stats["cef_mixed"] = len(all_records)

    logger.info("cef_adapters_registered", stats=stats)
    return stats
