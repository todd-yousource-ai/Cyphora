"""
Cyphora-S1 — Universal Format Normalizer (CEF / JSON / Proprietary -> OCSF)
==============================================================================
Implements the "convert everything to OCSF" design goal: a normalization
layer that sits in front of the existing CEF pipeline and the new OCSF
pipeline, converting any supported source format into OCSF-shaped dicts.
Those OCSF dicts then flow through the same ocsf_parser.OCSFParser /
ocsf_adapters.py machinery used for native OCSF sources — so there is
exactly ONE downstream code path (OCSF -> SecurityEvent) regardless of
how the data arrived.

    ┌──────────┐   ┌──────────┐   ┌───────────────┐   ┌──────────────┐
    │   CEF    │──▶│CEF->OCSF │──▶│               │   │              │
    ├──────────┤   ├──────────┤   │  OCSF (common │──▶│ SecurityEvent│
    │ Proprie- │──▶│JSON->OCSF│──▶│  intermediate │   │   (SEF)      │
    │ tary JSON│   ├──────────┤   │  representation)  │              │
    ├──────────┤   │  (native)│──▶│               │   │              │
    │   OCSF   │──▶│          │   └───────────────┘   └──────────────┘
    └──────────┘   └──────────┘      ocsf_parser.py      OCSFParser.
                                                          to_security_
                                                          event_dict()

Why convert CEF to OCSF at all, instead of just keeping the existing
direct CEF -> SecurityEvent path?
  - Uniform storage / replay: every event Cyphora ingests, regardless
    of source, can be persisted and re-queried in one schema (OCSF),
    which is what downstream data lakes (Security Lake, Snowflake,
    Databricks) and modern SIEMs (per CEF_and_OCSF_and_JSON reference)
    now expect.
  - Uniform SIEM forwarding: the existing siem_enrichment_writer.py /
    siem_connectors/ layer can write back a single normalized shape
    instead of one per source format.
  - Extensibility: adding a 51st proprietary log source means writing
    one FieldMappingProfile (a config-like dict), not a new bespoke
    parser + adapter pair.

The legacy direct CEF -> SecurityEvent path (cef_parser.py /
cef_adapters.py) is NOT removed — it remains the fast path for the
three hand-tuned vendors (CrowdStrike, Cortex XDR, Okta) where maximum
fidelity matters most (e.g. cs1Label resolution, MITRE technique
fields). This module adds the OCSF route as a second, more general
path, and the two can run side by side.

Usage
-----
    from cyphora_s1.format_normalizer import (
        UniversalNormalizer, FieldMappingProfile, ingest_to_security_event_dicts,
    )

    # One-call pipeline: detect format, normalize to OCSF, build
    # SecurityEvent dict(s) — regardless of whether `raw` is CEF text,
    # an OCSF JSON/NDJSON string, a Python dict, or already-OCSF.
    events = ingest_to_security_event_dicts(raw_log_line_or_dict)

    # Register a proprietary JSON log source in ~10 lines, no parser
    # code required:
    profile = FieldMappingProfile(
        vendor_name="Acme EDR",
        category_uid=1,                 # System Activity
        class_uid=1007,                 # Process Activity
        field_map={
            "time": ["ts", "event_time"],
            "severity_id": ["sev"],
            "message": ["summary"],
            "user.name": ["user", "actor_user"],
            "src_endpoint.ip": ["src_ip"],
            "device.hostname": ["host"],
            "process.name": ["proc_name"],
            "process.cmd_line": ["cmdline"],
        },
    )
    normalizer = UniversalNormalizer()
    normalizer.register_profile(profile)
    ocsf_event = normalizer.normalize(acme_raw_dict)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union

import structlog

from cyphora_s1.cef_parser import CEFRecord, CEFParser
from cyphora_s1.ocsf_parser import (
    OCSFParser,
    OCSFCategory,
    SEVERITY_STRING_TO_OCSF_ID,
)

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Format detection
# ─────────────────────────────────────────────────────────────


class SourceFormat:
    CEF = "cef"
    OCSF = "ocsf"
    JSON = "json"           # generic/proprietary JSON, format unknown
    UNKNOWN = "unknown"


class FormatDetector:
    """
    Lightweight sniffing — no external dependency, no false-positive-
    prone heuristics beyond what's needed to route to the right
    converter. Detection order: CEF header signature -> OCSF JSON shape
    -> generic JSON -> unknown.
    """

    # Matches an actual CEF header start: optional short syslog prefix
    # (timestamp + hostname, as CEFParser._parse_header strips), then
    # "CEF:<version>|". Anchored so a JSON blob that merely *mentions*
    # the string "CEF:" inside a field value (e.g. a note or sample log
    # quoted in a description) is not misdetected as CEF.
    _CEF_HEADER_RE = re.compile(r"^(?:\w{3}\s+\d+\s+[\d:]+\s+\S+\s+)?CEF:\d+\|")

    @staticmethod
    def detect(raw: Union[str, Dict[str, Any]]) -> str:
        if isinstance(raw, dict):
            if "class_uid" in raw or "category_uid" in raw:
                return SourceFormat.OCSF
            return SourceFormat.JSON

        if not isinstance(raw, str):
            return SourceFormat.UNKNOWN

        text = raw.strip()
        if not text:
            return SourceFormat.UNKNOWN

        # CEF always starts with "CEF:<version>|" on some line. Real
        # CEF exports often carry a header banner before the first
        # record — comment lines, blank lines, '===' section dividers,
        # and even bare banner-title text (e.g. "CROWDSTRIKE FALCON CEF
        # LOGS") — exactly like the bundled sample_security_logs.cef.
        # CEFParser.parse_text() itself tolerates this by silently
        # discarding any accumulated non-CEF text once a real CEF: line
        # appears, so detection scans ahead through a bounded window of
        # lines rather than bailing out at the first non-blank line.
        # The anchored regex (not a bare substring check) avoids
        # false-positiving on JSON whose content happens to mention
        # "CEF:" without it being a real header.
        for line in text.splitlines()[:25]:
            if FormatDetector._CEF_HEADER_RE.match(line.strip()):
                return SourceFormat.CEF

        # Try JSON; if it parses and looks OCSF-shaped, call it OCSF,
        # otherwise treat it as generic/proprietary JSON.
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            # Could be NDJSON — sniff the first non-blank line only.
            first_line = next((l for l in text.splitlines() if l.strip()), "")
            try:
                decoded = json.loads(first_line)
            except json.JSONDecodeError:
                return SourceFormat.UNKNOWN

        sample = decoded[0] if isinstance(decoded, list) and decoded else decoded
        if isinstance(sample, dict) and ("class_uid" in sample or "category_uid" in sample):
            return SourceFormat.OCSF
        if isinstance(sample, dict):
            return SourceFormat.JSON

        return SourceFormat.UNKNOWN


# ─────────────────────────────────────────────────────────────
# CEF -> OCSF converter
# ─────────────────────────────────────────────────────────────

# Reuses the CEF parser's own event-class/technique resolution logic
# (CEFParser._resolve_event_type) and re-projects the *Cyphora*
# event_type onto an OCSF class_uid/category_uid/activity_id. This is
# intentionally a small, explicit table rather than a full reverse
# mapping of every CEF event_class, because the round trip only needs
# to preserve enough structure for OCSF-side consumers (UEBA, NLQ,
# compliance, SIEM forwarding) — the original CEF fields are preserved
# losslessly in `unmapped` regardless.
_CYPHORA_EVENT_TYPE_TO_OCSF: Dict[str, tuple] = {
    # event_type -> (category_uid, class_uid, activity_id)
    "suspicious_login": (OCSFCategory.IAM, 3002, 1),                # Authentication: Logon
    "privilege_escalation": (OCSFCategory.IAM, 3005, 1),            # User Access: Grant
    "confirmed_attack": (OCSFCategory.FINDINGS, 2004, 1),           # Detection Finding: Create
    "abnormal_file_encryption": (OCSFCategory.SYSTEM_ACTIVITY, 1001, 3),  # File System Activity: Encrypt
    "lateral_movement": (OCSFCategory.NETWORK_ACTIVITY, 4005, 1),   # RDP Activity
    "data_exfiltration": (OCSFCategory.NETWORK_ACTIVITY, 4014, 1),  # Tunnel Activity (covert channel / exfil)
    "credential_dump": (OCSFCategory.SYSTEM_ACTIVITY, 1004, 2),     # Memory Activity: Read
    # No dedicated OCSF "Network Scan" class exists — recon/scan
    # activity is conventionally represented as a Detection Finding
    # (see ocsf_parser.py's note on Discovery vs. Findings).
    "network_scan": (OCSFCategory.FINDINGS, 2004, 1),               # Detection Finding: Create
    "abnormal_process_execution": (OCSFCategory.SYSTEM_ACTIVITY, 1007, 1),  # Process Activity: Launch
    "anomaly_detected": (OCSFCategory.NETWORK_ACTIVITY, 4001, 0),   # Network Activity (generic)
}

class CEFToOCSFConverter:
    """
    Converts a parsed CEFRecord into an OCSF-shaped event dict.

    Strategy: reuse CEFParser.to_security_event_dict()'s event_type
    resolution (MITRE technique -> event class -> tactic -> name
    heuristics) as the bridge, then project that Cyphora event_type
    onto the nearest OCSF class_uid/category_uid/activity_id. All
    original CEF fields are preserved under `unmapped` so no fidelity
    is lost — OCSF's own extensibility model is designed for exactly
    this (see OCSF Schema Overview: "unmapped" object for
    vendor-specific fields).
    """

    def __init__(self) -> None:
        self._cef_parser = CEFParser()

    def convert(self, rec: CEFRecord) -> Dict[str, Any]:
        sef_dict = self._cef_parser.to_security_event_dict(rec)
        cyphora_event_type = sef_dict["event_type"]
        category_uid, class_uid, activity_id = _CYPHORA_EVENT_TYPE_TO_OCSF.get(
            cyphora_event_type, (OCSFCategory.UNMAPPED, 0, 0)
        )

        severity_id = SEVERITY_STRING_TO_OCSF_ID.get(rec.severity, 3)
        ts = rec.timestamp
        try:
            epoch_ms = int(datetime.fromisoformat(ts).timestamp() * 1000)
        except Exception:
            epoch_ms = int(datetime.now(tz=timezone.utc).timestamp() * 1000)

        attacks = []
        technique = rec.fields.get("Technique") or rec.fields.get("cs2")
        tactic = rec.fields.get("Tactic") or rec.fields.get("cs3")
        if technique or tactic:
            attacks.append({
                "tactic": {"name": tactic} if tactic else {},
                "technique": {"uid": technique, "name": technique} if technique else {},
            })

        return {
            "class_uid": class_uid,
            "category_uid": category_uid,
            "activity_id": activity_id,
            "type_uid": (class_uid * 100) + activity_id,
            "severity_id": severity_id,
            "time": epoch_ms,
            "message": rec.name,
            "metadata": {
                "product": {
                    "vendor_name": rec.vendor,
                    "name": rec.product,
                },
                "uid": sef_dict["event_id"],
            },
            "actor": {"user": {"name": rec.fields.get("suser")}} if rec.fields.get("suser") else {},
            "user": {"name": rec.fields.get("duser") or rec.fields.get("suser")},
            "device": {"hostname": rec.fields.get("dvchost"), "ip": rec.fields.get("dvc")},
            "src_endpoint": {"ip": rec.fields.get("src")},
            "process": (
                {"name": rec.fields.get("ProcessName") or rec.fields.get("cs4")}
                if (rec.fields.get("ProcessName") or rec.fields.get("cs4"))
                else {}
            ),
            "attacks": attacks,
            "unmapped": {
                "source_format": "cef",
                "cef_vendor": rec.vendor,
                "cef_event_class": rec.event_class,
                "cef_severity_int": rec.severity_int,
                **{k: v for k, v in rec.fields.items()},
            },
        }

    def convert_text(self, cef_text: str) -> List[Dict[str, Any]]:
        records = self._cef_parser.parse_text(cef_text)
        return [self.convert(r) for r in records]

    def convert_file(self, path: str) -> List[Dict[str, Any]]:
        records = self._cef_parser.parse_file(path)
        return [self.convert(r) for r in records]


# ─────────────────────────────────────────────────────────────
# Generic / proprietary JSON -> OCSF converter
# ─────────────────────────────────────────────────────────────


@dataclass
class FieldMappingProfile:
    """
    Declarative mapping from a proprietary/vendor JSON shape to OCSF.
    This is the extensibility mechanism for "other proprietary
    formats" called out in the design goal: onboarding a new JSON log
    source becomes writing one of these profiles instead of a new
    parser module.

    field_map keys are dotted OCSF attribute paths (e.g.
    "src_endpoint.ip", "user.name", "process.cmd_line"); values are
    an ordered list of candidate keys/dotted-paths to look for in the
    source JSON. The first candidate present in the source record
    wins.

    category_uid / class_uid / activity_id are fixed defaults for this
    source. If the source JSON has its own way of signalling activity
    (e.g. a `severity` string, an `action` field), use
    activity_resolver / severity_resolver for per-record overrides.
    """

    vendor_name: str
    category_uid: int
    class_uid: int
    activity_id: int = 0
    field_map: Dict[str, List[str]] = field(default_factory=dict)
    severity_resolver: Optional[Callable[[Dict[str, Any]], int]] = None
    activity_resolver: Optional[Callable[[Dict[str, Any]], int]] = None
    event_id_field: Optional[str] = None
    time_field_candidates: List[str] = field(
        default_factory=lambda: ["time", "timestamp", "ts", "@timestamp", "event_time"]
    )


def _get_dotted(d: Dict[str, Any], dotted_key: str) -> Any:
    """Resolve 'a.b.c' against nested dicts, or flat 'a.b.c' literal keys."""
    if dotted_key in d:
        return d[dotted_key]
    parts = dotted_key.split(".")
    cur: Any = d
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def _set_dotted(d: Dict[str, Any], dotted_key: str, value: Any) -> None:
    parts = dotted_key.split(".")
    cur = d
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


class GenericJSONToOCSFConverter:
    """
    Converts an arbitrary/proprietary JSON event dict into an
    OCSF-shaped dict using a registered FieldMappingProfile.

    Unmapped source fields (anything not consumed by field_map) are
    preserved under `unmapped`, exactly like the CEF converter and the
    native OCSF parser — no telemetry is silently dropped just because
    a vendor hasn't been explicitly profiled in depth.
    """

    def convert(self, raw: Dict[str, Any], profile: FieldMappingProfile) -> Dict[str, Any]:
        ocsf: Dict[str, Any] = {
            "category_uid": profile.category_uid,
            "class_uid": profile.class_uid,
        }

        consumed_keys: set = set()

        # time
        time_val = None
        for cand in profile.time_field_candidates:
            time_val = _get_dotted(raw, cand)
            if time_val is not None:
                consumed_keys.add(cand)
                break
        ocsf["time"] = self._normalize_time(time_val)

        # activity / severity (resolver takes precedence over a static default)
        ocsf["activity_id"] = (
            profile.activity_resolver(raw) if profile.activity_resolver else profile.activity_id
        )
        ocsf["severity_id"] = (
            profile.severity_resolver(raw) if profile.severity_resolver else 0
        )
        ocsf["type_uid"] = (profile.class_uid * 100) + ocsf["activity_id"]

        # declared field mappings
        for ocsf_path, candidates in profile.field_map.items():
            for cand in candidates:
                value = _get_dotted(raw, cand)
                if value is not None:
                    _set_dotted(ocsf, ocsf_path, value)
                    consumed_keys.add(cand)
                    break

        ocsf.setdefault("metadata", {})["product"] = {"vendor_name": profile.vendor_name}
        event_id = (
            _get_dotted(raw, profile.event_id_field) if profile.event_id_field else None
        )
        if event_id:
            ocsf["metadata"]["uid"] = event_id

        # everything else, preserved
        ocsf["unmapped"] = {
            "source_format": "json",
            "source_vendor": profile.vendor_name,
            **{k: v for k, v in raw.items() if k not in consumed_keys},
        }
        return ocsf

    @staticmethod
    def _normalize_time(value: Any) -> int:
        if value is None:
            return int(datetime.now(tz=timezone.utc).timestamp() * 1000)
        try:
            f = float(value)
            return int(f) if f > 1e12 else int(f * 1000)
        except (TypeError, ValueError):
            pass
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


# ─────────────────────────────────────────────────────────────
# Universal Normalizer — top-level orchestrator
# ─────────────────────────────────────────────────────────────


class UniversalNormalizer:
    """
    Detects the format of an arbitrary raw log (CEF text, OCSF JSON,
    or proprietary JSON matched against a registered
    FieldMappingProfile) and returns an OCSF-shaped dict — the single
    common intermediate representation used everywhere downstream.

    Usage
    -----
        normalizer = UniversalNormalizer()
        normalizer.register_profile(my_vendor_profile)

        ocsf_event = normalizer.normalize(raw_log)          # one event
        ocsf_events = normalizer.normalize_many(raw_logs)    # batch
    """

    def __init__(self) -> None:
        self._cef_to_ocsf = CEFToOCSFConverter()
        self._json_to_ocsf = GenericJSONToOCSFConverter()
        self._profiles: Dict[str, FieldMappingProfile] = {}
        self._cef_parser = CEFParser()
        self._ocsf_parser = OCSFParser()

    def register_profile(self, profile: FieldMappingProfile, key: Optional[str] = None) -> None:
        """Register a FieldMappingProfile for a proprietary JSON source."""
        self._profiles[key or profile.vendor_name] = profile

    def normalize(
        self,
        raw: Union[str, Dict[str, Any]],
        *,
        profile_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Normalize a single raw log entry (CEF text, OCSF JSON/NDJSON,
        or proprietary JSON dict) to a list of OCSF-shaped dicts (a
        list because CEF and OCSF text input can both legitimately be
        multi-record — a full CEF file or an OCSF NDJSON/array export).
        """
        fmt = FormatDetector.detect(raw)

        if fmt == SourceFormat.CEF:
            return self._cef_to_ocsf.convert_text(raw)  # type: ignore[arg-type]

        if fmt == SourceFormat.OCSF:
            # Already OCSF — pass through unchanged (just validate it
            # parses). Delegate to OCSFParser.parse_text(), which
            # already handles single-object / JSON-array / NDJSON
            # transports robustly — a bare json.loads() call cannot
            # parse multi-line NDJSON (the most common real-world OCSF
            # transport, per this module's own docstring) and raises
            # json.JSONDecodeError("Extra data") on it.
            if isinstance(raw, dict):
                return [raw]
            records = self._ocsf_parser.parse_text(raw)
            return [r.raw for r in records]

        if fmt == SourceFormat.JSON:
            raw_dict = raw if isinstance(raw, dict) else json.loads(raw)
            profile = self._resolve_profile(raw_dict, profile_key)
            if profile is None:
                logger.warning(
                    "ocsf_normalize_no_profile",
                    hint="register a FieldMappingProfile for this source; "
                         "falling back to a best-effort generic mapping",
                )
                profile = self._fallback_profile()
            return [self._json_to_ocsf.convert(raw_dict, profile)]

        logger.warning("ocsf_normalize_unknown_format", sample=str(raw)[:120])
        return []

    def normalize_many(self, raw_logs: List[Union[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for raw in raw_logs:
            out.extend(self.normalize(raw))
        return out

    def _resolve_profile(
        self, raw_dict: Dict[str, Any], profile_key: Optional[str]
    ) -> Optional[FieldMappingProfile]:
        if profile_key and profile_key in self._profiles:
            return self._profiles[profile_key]
        # Best-effort auto-match: look for a vendor/product hint field
        for hint_key in ("vendor", "product", "source", "_source_type"):
            hint = raw_dict.get(hint_key)
            if hint and hint in self._profiles:
                return self._profiles[hint]
        return None

    @staticmethod
    def _fallback_profile() -> FieldMappingProfile:
        """
        Best-effort default for unprofiled JSON: maps the most common
        field-name conventions seen across cloud/SaaS audit logs
        (AWS CloudTrail-ish, generic webhook payloads, etc.) so an
        unrecognised source still produces a usable event instead of
        being dropped.
        """
        return FieldMappingProfile(
            vendor_name="unknown_json_source",
            category_uid=OCSFCategory.UNMAPPED,
            class_uid=0,
            field_map={
                "message": ["message", "msg", "description", "summary"],
                "user.name": ["user", "username", "actor", "principal"],
                "src_endpoint.ip": ["src_ip", "source_ip", "ip", "sourceIPAddress"],
                "device.hostname": ["host", "hostname", "device"],
                "process.name": ["process", "process_name"],
                "process.cmd_line": ["cmdline", "command_line", "commandLine"],
            },
        )


# ─────────────────────────────────────────────────────────────
# One-call pipeline: raw (any format) -> SecurityEvent dict
# ─────────────────────────────────────────────────────────────

_default_normalizer = UniversalNormalizer()


def ingest_to_security_event_dicts(
    raw: Union[str, Dict[str, Any]],
    *,
    normalizer: Optional[UniversalNormalizer] = None,
    profile_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Full pipeline in one call: detect format -> normalize to OCSF ->
    convert OCSF -> SecurityEvent-compatible dict(s). This is the
    "same logic now expanded" entry point: it replaces calling
    cef_parser.parse_cef_text() directly when the source format is
    unknown ahead of time, or when uniform OCSF storage/forwarding is
    desired regardless of source.
    """
    norm = normalizer or _default_normalizer
    ocsf_dicts = norm.normalize(raw, profile_key=profile_key)
    ocsf_parser = OCSFParser()
    out = []
    for d in ocsf_dicts:
        rec = ocsf_parser.parse_dict(d)
        if rec:
            out.append(ocsf_parser.to_security_event_dict(rec))
    return out


def register_profile_globally(profile: FieldMappingProfile, key: Optional[str] = None) -> None:
    """Register a FieldMappingProfile on the module-level default normalizer."""
    _default_normalizer.register_profile(profile, key=key)
