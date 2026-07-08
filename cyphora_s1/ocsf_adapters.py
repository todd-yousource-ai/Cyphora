"""
Cyphora-S1 — OCSF Adapters
=============================
DataCollector adapters that serve OCSF event records as investigation
telemetry, and a factory that builds SecurityEvent objects directly
from parsed OCSF records. This is the OCSF counterpart to
cef_adapters.py and follows the identical structure deliberately, so
the two ingestion paths (legacy CEF, modern OCSF) are operated and
extended the same way.

Because OCSF is vendor-neutral, partitioning is done by *category*
rather than by vendor (there is no equivalent to "CrowdStrike CEF" —
a CrowdStrike-sourced OCSF event and an Okta-sourced OCSF event in the
same category use identical field names). Seven category adapters are
provided, one per OCSF top-level category:

  SystemActivityOCSFAdapter        — category_uid 1 -> endpoint_logs
  FindingsOCSFAdapter              — category_uid 2 -> threat_intel
  IAMOCSFAdapter                   — category_uid 3 -> identity_logs
  NetworkActivityOCSFAdapter       — category_uid 4 -> network_logs
  DiscoveryOCSFAdapter             — category_uid 5 -> cloud_logs
  ApplicationActivityOCSFAdapter   — category_uid 6 -> cloud_logs
  RemediationOCSFAdapter           — category_uid 7 -> endpoint_logs

Registration
------------
Call register_ocsf_adapters(...) once at startup, exactly like
register_cef_adapters(...), to populate the DataCollector's
_ADAPTER_MAP with OCSF-sourced telemetry:

    from cyphora_s1.ocsf_adapters import (
        register_ocsf_adapters, OCSFSecurityEventFactory,
    )

    # A single mixed-category OCSF export (JSON array, NDJSON, or
    # single object) — the common shape for SIEM/data-lake exports
    register_ocsf_adapters(mixed_file="/var/log/security_ocsf.ndjson")

    # Build SecurityEvent objects directly from an OCSF file
    events = OCSFSecurityEventFactory.from_file("/path/to/events.ndjson")
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
from cyphora_s1.ocsf_parser import (
    OCSFParser,
    OCSFRecord,
    OCSFCategory,
)

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Base OCSF DataCollector Adapter
# ─────────────────────────────────────────────────────────────


class BaseOCSFAdapter(BaseSourceAdapter):
    """
    Serves pre-loaded OCSF records as investigation telemetry.

    Records are filtered by the time window [since, until] using the
    OCSF `time` field (converted to ISO-8601 on the record). As with
    BaseCEFAdapter, if the window contains no records, ALL records are
    returned so demos/tests against historical exports always have
    data to reason about. Contextual filtering by source IP / host /
    user narrows results to the entities relevant to the triggering
    SecurityEvent when possible.
    """

    #: Override in subclass with an OCSFCategory constant to filter
    CATEGORY: Optional[int] = None

    def __init__(self, records: List[OCSFRecord]):
        self._records = records
        logger.info(
            "ocsf_adapter_loaded",
            category=OCSFCategory.name(self.CATEGORY),
            records=len(records),
        )

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "BaseOCSFAdapter":
        parser = OCSFParser()
        all_records = parser.parse_file(path)
        cat_records = (
            [r for r in all_records if r.category_uid == cls.CATEGORY]
            if cls.CATEGORY is not None
            else all_records
        )
        return cls(cat_records)

    @classmethod
    def from_text(cls, text: str) -> "BaseOCSFAdapter":
        parser = OCSFParser()
        all_records = parser.parse_text(text)
        cat_records = (
            [r for r in all_records if r.category_uid == cls.CATEGORY]
            if cls.CATEGORY is not None
            else all_records
        )
        return cls(cat_records)

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 1000,
    ) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.01)  # non-blocking yield

        window_records = [
            r for r in self._records if self._in_window(r.timestamp, since, until)
        ]
        if not window_records:
            window_records = self._records

        contextual = self._contextual_filter(window_records, event)
        if contextual:
            window_records = contextual

        result = [r.to_dict() for r in window_records[:max_records]]
        logger.debug(
            "ocsf_adapter_query_complete",
            category=OCSFCategory.name(self.CATEGORY),
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
        records: List[OCSFRecord], event: SecurityEvent
    ) -> List[OCSFRecord]:
        matches = []
        for r in records:
            src_match = event.source_ip and r.src_ip == event.source_ip
            host_match = event.source_host and r.src_host == event.source_host
            user_match = event.user and r.user == event.user
            if src_match or host_match or user_match:
                matches.append(r)
        return matches


# ─────────────────────────────────────────────────────────────
# Category-specific adapters
# ─────────────────────────────────────────────────────────────


class SystemActivityOCSFAdapter(BaseOCSFAdapter):
    """
    Serves OCSF System Activity events (category_uid 1: File System
    Activity, Process Activity, Memory Activity, Scheduled Job
    Activity, etc.) for the 'endpoint_logs' DataCollector source.
    """

    CATEGORY = OCSFCategory.SYSTEM_ACTIVITY


class FindingsOCSFAdapter(BaseOCSFAdapter):
    """
    Serves OCSF Findings events (category_uid 2: Detection Finding,
    Incident Finding, Vulnerability Finding, Compliance Finding, Data
    Security Finding) for the 'threat_intel' DataCollector source.
    These are typically pre-triaged alerts forwarded from an upstream
    EDR/XDR/SIEM and carry the richest MITRE ATT&CK context via
    attacks[].
    """

    CATEGORY = OCSFCategory.FINDINGS


class IAMOCSFAdapter(BaseOCSFAdapter):
    """
    Serves OCSF Identity & Access Management events (category_uid 3:
    Authentication, Authorize Session, Account Change, Group
    Management, User Access) for the 'identity_logs' DataCollector
    source. Functionally replaces OktaCEFAdapter for any IdP that
    natively emits OCSF (Okta, Entra ID, Ping, etc. all map to the
    same schema here).
    """

    CATEGORY = OCSFCategory.IAM


class NetworkActivityOCSFAdapter(BaseOCSFAdapter):
    """
    Serves OCSF Network Activity events (category_uid 4: Network
    Activity, HTTP, DNS, DHCP, RDP, SMB, SSH, FTP, Email) for the
    'network_logs' DataCollector source. Functionally replaces
    CortexXDRCEFAdapter / PaloAltoAdapter for any NGFW, proxy, or
    cloud VPC flow log source emitting OCSF.
    """

    CATEGORY = OCSFCategory.NETWORK_ACTIVITY


class DiscoveryOCSFAdapter(BaseOCSFAdapter):
    """
    Serves OCSF Discovery events (category_uid 5: Device/User/Software
    Inventory Info, OS Patch State, Device Config State) for the
    'cloud_logs' DataCollector source.

    Note: Discovery is *defensive* asset/inventory telemetry — it is
    not where attacker reconnaissance or port-scanning shows up (OCSF
    has no dedicated "Network Scan" class). It's useful for asset
    drift and patch-state context, not scan detection.
    """

    CATEGORY = OCSFCategory.DISCOVERY


class ApplicationActivityOCSFAdapter(BaseOCSFAdapter):
    """
    Serves OCSF Application Activity events (category_uid 6: Web
    Resources Activity, API Activity, Datastore Activity, Application
    Lifecycle) for the 'cloud_logs' DataCollector source. Covers
    SaaS/API-layer telemetry that doesn't fit cleanly into endpoint or
    network categories — e.g. bulk datastore reads/exports relevant to
    data_exfiltration detection.
    """

    CATEGORY = OCSFCategory.APPLICATION_ACTIVITY


class RemediationOCSFAdapter(BaseOCSFAdapter):
    """
    Serves OCSF Remediation events (category_uid 7: Remediation
    Activity) for the 'endpoint_logs' DataCollector source. Typically
    carries the *response* side of an incident (e.g. an upstream
    EDR/SOAR's own containment action), useful as corroborating
    context during investigation.
    """

    CATEGORY = OCSFCategory.REMEDIATION


class MixedOCSFAdapter(BaseOCSFAdapter):
    """
    Serves records from a mixed-category OCSF export across all
    sources. Used as a fallback when category partitioning is not
    desired or the export mixes categories arbitrarily.
    """

    CATEGORY = None


# ─────────────────────────────────────────────────────────────
# SecurityEvent factory
# ─────────────────────────────────────────────────────────────

_VALID_SECURITY_EVENT_FIELDS = {
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


class OCSFSecurityEventFactory:
    """
    Converts OCSF event records directly into SecurityEvent objects
    ready to be dispatched through the AgentOrchestrator. Mirrors
    cef_adapters.SecurityEventFactory.

    Usage
    -----
        events = OCSFSecurityEventFactory.from_file("events.ndjson")
        for event in events:
            triggered = await orchestrator.dispatch(event)
    """

    _parser = OCSFParser()

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> List[SecurityEvent]:
        records = cls._parser.parse_file(path)
        return [cls._to_event(r) for r in records]

    @classmethod
    def from_text(cls, text: str) -> List[SecurityEvent]:
        records = cls._parser.parse_text(text)
        return [cls._to_event(r) for r in records]

    @classmethod
    def from_dicts(cls, events: List[Dict[str, Any]]) -> List[SecurityEvent]:
        records = [cls._parser.parse_dict(e) for e in events]
        return [cls._to_event(r) for r in records if r is not None]

    @classmethod
    def from_record(cls, rec: OCSFRecord) -> SecurityEvent:
        return cls._to_event(rec)

    @classmethod
    def _to_event(cls, rec: OCSFRecord) -> SecurityEvent:
        d = cls._parser.to_security_event_dict(rec)
        d["event_id"] = str(d.get("event_id") or uuid.uuid4())
        return SecurityEvent(
            **{k: v for k, v in d.items() if k in _VALID_SECURITY_EVENT_FIELDS}
        )


# ─────────────────────────────────────────────────────────────
# Registration helper
# ─────────────────────────────────────────────────────────────

# category_uid -> AdapterClass. The DataCollector source key each
# adapter registers under is derived from OCSFCategory.source_key()
# (ocsf_parser.py) rather than duplicated here as a second hardcoded
# table — that duplication is exactly what let categories 6/7
# (Application Activity, Remediation) silently fall through to the
# generic "ocsf_mixed" bucket in an earlier version of this module.
# Adding a new category now only requires adding it to BOTH
# OCSFCategory._SOURCE_KEY_MAP and this dict — there's no third place
# a source key could drift out of sync.
_CATEGORY_ADAPTER_CLASSES: Dict[int, type] = {
    OCSFCategory.SYSTEM_ACTIVITY: SystemActivityOCSFAdapter,
    OCSFCategory.FINDINGS: FindingsOCSFAdapter,
    OCSFCategory.IAM: IAMOCSFAdapter,
    OCSFCategory.NETWORK_ACTIVITY: NetworkActivityOCSFAdapter,
    OCSFCategory.DISCOVERY: DiscoveryOCSFAdapter,
    OCSFCategory.APPLICATION_ACTIVITY: ApplicationActivityOCSFAdapter,
    OCSFCategory.REMEDIATION: RemediationOCSFAdapter,
}

# Built once at import time: category_uid -> (AdapterClass, [source_keys]).
_CATEGORY_REGISTRATION: Dict[int, tuple] = {
    category_uid: (adapter_cls, [OCSFCategory.source_key(category_uid)])
    for category_uid, adapter_cls in _CATEGORY_ADAPTER_CLASSES.items()
}

# Fails fast at import time, rather than silently misrouting events at
# runtime, if a category is ever added to OCSFCategory's source-key
# table without a corresponding adapter class registered above (the
# exact gap that let categories 6/7 fall through to "ocsf_mixed" in an
# earlier version of this module). UNMAPPED (0) is deliberately
# excluded — it has no real adapter by design, see MixedOCSFAdapter.
_categories_missing_adapters = (
    set(OCSFCategory._SOURCE_KEY_MAP) - {OCSFCategory.UNMAPPED} - set(_CATEGORY_ADAPTER_CLASSES)
)
assert not _categories_missing_adapters, (
    f"OCSFCategory defines source keys for categories with no registered "
    f"adapter in _CATEGORY_ADAPTER_CLASSES: {_categories_missing_adapters}"
)


def register_ocsf_adapters(
    category_paths: Optional[Dict[int, Union[str, Path]]] = None,
    *,
    mixed_file: Optional[Union[str, Path]] = None,
    ocsf_text: Optional[str] = None,
    ocsf_dicts: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, int]:
    """
    Register OCSF-based adapters into the global _ADAPTER_MAP, replacing
    any previously registered adapters for those sources. Mirrors
    cef_adapters.register_cef_adapters().

    Parameters
    ----------
    category_paths : dict mapping OCSFCategory constant -> file path
        Use when you already have category-separated OCSF exports,
        e.g. {OCSFCategory.IAM: "/var/log/iam_ocsf.ndjson"}.

    mixed_file : path to a single OCSF file (JSON array, NDJSON, or a
        single object) containing events spanning multiple categories.
        Partitions records by category_uid and registers each, exactly
        like register_cef_adapters(mixed_file=...) partitions by vendor.

    ocsf_text : raw OCSF content as a string (testing / in-memory use).

    ocsf_dicts : a list of already-decoded OCSF event dicts (e.g. read
        from a SIEM API response or an internal CEF->OCSF / JSON->OCSF
        conversion — see format_normalizer.py).

    Returns
    -------
    dict mapping adapter source key -> number of records loaded

    Examples
    --------
        # Single combined OCSF export (the common case)
        register_ocsf_adapters(mixed_file="/var/log/security_ocsf.ndjson")

        # Pre-converted events from another format (CEF/JSON/proprietary)
        from cyphora_s1.format_normalizer import UniversalNormalizer
        ocsf_events = UniversalNormalizer().normalize_many(raw_logs)
        register_ocsf_adapters(ocsf_dicts=ocsf_events)
    """
    stats: Dict[str, int] = {}
    parser = OCSFParser()
    by_category: Dict[Optional[int], List[OCSFRecord]] = {}

    def _accumulate(records: List[OCSFRecord]) -> None:
        for r in records:
            by_category.setdefault(r.category_uid, []).append(r)

    # ── From category-separated files ─────────────────────────
    if category_paths:
        for category_uid, path in category_paths.items():
            path = Path(path)
            if not path.exists():
                logger.warning(
                    "ocsf_log_file_not_found", path=str(path), category=category_uid
                )
                continue
            records = parser.parse_file(path)
            # Trust the caller's intent for this slot: keep only records
            # that actually match the declared category, falling back to
            # everything parsed if the file truly contains nothing else.
            cat_records = [r for r in records if r.category_uid == category_uid] or records
            _accumulate(cat_records)

    # ── From a single mixed file / text / pre-decoded dict list ─
    all_records: List[OCSFRecord] = []
    if mixed_file:
        all_records = parser.parse_file(mixed_file)
    elif ocsf_text:
        all_records = parser.parse_text(ocsf_text)
    elif ocsf_dicts:
        all_records = [parser.parse_dict(e) for e in ocsf_dicts]
        all_records = [r for r in all_records if r is not None]
    _accumulate(all_records)

    # ── Single registration pass — every category seen across all
    #    inputs is merged once, so combining category_paths with
    #    mixed_file/ocsf_text/ocsf_dicts for the same category adds
    #    records together instead of one input silently overwriting
    #    the other in _ADAPTER_MAP. ─────────────────────────────────
    def _register(adapter: BaseOCSFAdapter, source_keys: List[str]) -> None:
        for key in source_keys:
            _ADAPTER_MAP[key] = adapter

    unrecognised: List[OCSFRecord] = []
    for category_uid, records in by_category.items():
        if category_uid in _CATEGORY_REGISTRATION:
            adapter_cls, source_keys = _CATEGORY_REGISTRATION[category_uid]
            adapter = adapter_cls(records)
            _register(adapter, source_keys)
            stats[f"ocsf_{OCSFCategory.name(category_uid)}"] = len(records)
        else:
            unrecognised.extend(records)

    if unrecognised:
        mixed = MixedOCSFAdapter(unrecognised)
        _ADAPTER_MAP["ocsf_mixed"] = mixed
        stats["ocsf_mixed"] = len(unrecognised)

    logger.info("ocsf_adapters_registered", stats=stats)
    return stats
