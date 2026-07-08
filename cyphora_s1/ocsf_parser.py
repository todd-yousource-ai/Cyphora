"""
Cyphora-S1 — OCSF Event Parser
=================================
Parses Open Cybersecurity Schema Framework (OCSF) events — the
vendor-neutral, AWS/Splunk/IBM-backed schema that is rapidly becoming
the default normalized format for cloud-native SIEMs (see
CEF_and_OCSF_and_JSON reference doc) — into Cyphora SecurityEvent
records.

This module is the OCSF counterpart to cef_parser.py. It is intentionally
built with the same shape (Record class, Parser class,
to_security_event_dict()) so the two pipelines are interchangeable and
maintainable by the same mental model:

    CEF  log line  -> CEFParser  -> CEFRecord  -> SecurityEvent dict
    OCSF JSON event -> OCSFParser -> OCSFRecord -> SecurityEvent dict

OCSF Format Reference
----------------------
An OCSF event is a JSON object, normally carrying at minimum:

    {
      "class_uid": 3002,           # Event Class (e.g. Authentication)
      "category_uid": 3,           # Event Category (e.g. IAM)
      "activity_id": 1,            # Specific activity within the class
      "type_uid": 300201,          # class_uid * 100 + activity_id
      "severity_id": 4,            # 0=Unknown..6=Fatal, 99=Other
      "time": 1718000000000,       # epoch milliseconds
      "metadata": {"product": {"vendor_name": "...", "name": "..."}},
      "actor": {"user": {"name": "...", "uid": "..."}},
      "user": {"name": "...", "uid": "..."},
      "device": {"hostname": "...", "ip": "..."},
      "src_endpoint": {"ip": "...", "hostname": "..."},
      "dst_endpoint": {"ip": "...", "hostname": "..."},
      "process": {"name": "...", "cmd_line": "..."},
      "finding_info": {"title": "...", "uid": "..."},
      "attacks": [{"tactic": {"name": "..."}, "technique": {"uid": "T1059.001", "name": "..."}}],
      "unmapped": {"<vendor specific keys not in the schema>": "..."}
    }

OCSF events normally arrive as:
  - A single JSON object (one event)
  - A JSON array of events (batch export)
  - NDJSON / JSON-Lines (one event per line — the common log-shipper
    transport for OCSF, e.g. Cribl Stream, Datadog Observability
    Pipelines, AWS Security Lake exports)

This module handles all three transports transparently.

Usage
-----
    from cyphora_s1.ocsf_parser import OCSFParser

    parser = OCSFParser()

    # Parse a single event dict (already-decoded JSON)
    record = parser.parse_dict(event_dict)

    # Parse raw text — auto-detects JSON array / NDJSON / single object
    records = parser.parse_text(raw_text)

    # Parse a file on disk (.json / .ndjson / .jsonl)
    records = parser.parse_file("/var/log/security_ocsf.ndjson")
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# OCSF Category reference  (category_uid -> name / Cyphora source key)
# ─────────────────────────────────────────────────────────────


class OCSFCategory:
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IAM = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6
    REMEDIATION = 7
    UNMAPPED = 0

    _NAME_MAP = {
        SYSTEM_ACTIVITY: "system_activity",
        FINDINGS: "findings",
        IAM: "iam",
        NETWORK_ACTIVITY: "network_activity",
        DISCOVERY: "discovery",
        APPLICATION_ACTIVITY: "application_activity",
        REMEDIATION: "remediation",
        UNMAPPED: "uncategorized",
    }

    # Maps an OCSF category to the Cyphora DataCollector source key
    # that adapters for that category should register under.
    _SOURCE_KEY_MAP = {
        SYSTEM_ACTIVITY: "endpoint_logs",
        FINDINGS: "threat_intel",
        IAM: "identity_logs",
        NETWORK_ACTIVITY: "network_logs",
        DISCOVERY: "cloud_logs",
        APPLICATION_ACTIVITY: "cloud_logs",
        REMEDIATION: "endpoint_logs",
        UNMAPPED: "endpoint_logs",
    }

    @classmethod
    def name(cls, category_uid: Optional[int]) -> str:
        return cls._NAME_MAP.get(category_uid, "uncategorized")

    @classmethod
    def source_key(cls, category_uid: Optional[int]) -> str:
        return cls._SOURCE_KEY_MAP.get(category_uid, "endpoint_logs")


# ─────────────────────────────────────────────────────────────
# class_uid + activity_id -> Cyphora event_type
# ─────────────────────────────────────────────────────────────
#
# Keyed as "<class_uid>:<activity_id>" for activity-specific mappings,
# falling back to "<class_uid>:*" for a class-wide default when the
# specific activity_id is not separately distinguished.

_CLASS_ACTIVITY_EVENT_TYPE_MAP: Dict[str, str] = {
    # 1xxx — System Activity
    "1001:*": "abnormal_file_encryption",       # File System Activity
    "1001:3": "abnormal_file_encryption",       # Activity: Encrypt
    "1001:6": "abnormal_file_encryption",       # Activity: Encrypt? (vendor-variant)
    "1002:*": "anomaly_detected",               # Kernel Extension Activity
    "1003:*": "anomaly_detected",               # Kernel Activity
    "1004:*": "anomaly_detected",               # Memory Activity
    "1004:2": "credential_dump",                # Memory Activity: Read (LSASS-style dumps)
    "1005:*": "abnormal_process_execution",      # Module Activity
    "1006:*": "abnormal_process_execution",      # Scheduled Job Activity
    "1007:*": "abnormal_process_execution",      # Process Activity
    "1007:1": "abnormal_process_execution",      # Activity: Launch
    "1008:*": "anomaly_detected",                # Event Log Activity
    # 2xxx — Findings
    "2001:*": "confirmed_attack",                 # Security Finding (generic)
    "2002:*": "confirmed_attack",                 # Vulnerability Finding
    "2003:*": "confirmed_attack",                 # Compliance Finding
    "2004:*": "confirmed_attack",                 # Detection Finding (EDR/XDR/SIEM alert)
    "2005:*": "confirmed_attack",                 # Incident Finding
    "2006:*": "data_exfiltration",                # Data Security Finding
    # 3xxx — IAM
    "3001:*": "privilege_escalation",             # Account Change
    "3002:1": "suspicious_login",                 # Authentication: Logon
    "3002:2": "suspicious_login",                 # Authentication: Logoff
    "3002:3": "suspicious_login",                 # Authentication: Ticket
    "3002:4": "suspicious_login",                 # Authentication: Service Ticket Request
    "3002:*": "suspicious_login",
    "3003:*": "suspicious_login",                 # Authorize Session
    "3004:*": "anomaly_detected",                 # Entity Management
    "3005:*": "privilege_escalation",             # User Access (grant/revoke)
    "3006:*": "privilege_escalation",             # Group Management
    # 4xxx — Network Activity
    "4001:*": "anomaly_detected",                 # Network Activity (generic)
    "4002:*": "anomaly_detected",                 # HTTP Activity
    "4003:*": "anomaly_detected",                 # DNS Activity
    "4003:99": "data_exfiltration",               # DNS Activity: Other (often tunnelling)
    "4004:*": "anomaly_detected",                 # DHCP Activity
    "4005:*": "lateral_movement",                 # RDP Activity
    "4006:*": "lateral_movement",                 # SMB Activity
    "4007:*": "lateral_movement",                 # SSH Activity (often used for lateral movement)
    "4008:*": "data_exfiltration",                # FTP Activity
    "4009:*": "data_exfiltration",                # Email Activity
    "4013:*": "anomaly_detected",                 # NTP Activity
    "4014:*": "data_exfiltration",                # Tunnel Activity (covert channel / C2 / exfil)
    # 5xxx — Discovery
    # NOTE: OCSF Discovery is *defensive* asset/inventory telemetry
    # (device/user/software inventories, OS patch state) — it is not
    # where attacker recon/port-scanning shows up. There is no
    # dedicated "Network Scan" OCSF class. Scan/recon activity is
    # represented either as a Detection Finding (2004, via the MITRE
    # T1046/T1018 technique entries below, which take precedence) or
    # inferred from Network Activity volume — never from category 5.
    "5001:*": "anomaly_detected",                 # Device Inventory Info
    "5002:*": "anomaly_detected",                 # Device Config State
    "5003:*": "anomaly_detected",                 # User Inventory Info
    "5004:*": "anomaly_detected",                 # Operating System Patch State
    "5019:*": "anomaly_detected",                 # Device Config State Change
    "5020:*": "anomaly_detected",                 # Software Inventory Info
    # 6xxx — Application Activity
    "6001:*": "anomaly_detected",                 # Web Resources Activity
    "6002:*": "anomaly_detected",                 # Application Lifecycle
    "6003:*": "anomaly_detected",                 # API Activity
    "6004:*": "data_exfiltration",                # Datastore Activity (bulk reads/exports)
    # 7xxx — Remediation
    "7001:*": "confirmed_attack",                 # Remediation Activity
}

# OCSF attacks[].technique.uid (MITRE ATT&CK) -> Cyphora event_type.
# Re-uses the same priority logic as the CEF parser: MITRE technique,
# when present, takes precedence over the class/activity mapping.
_TECHNIQUE_TO_EVENT_TYPE: Dict[str, str] = {
    "T1003": "credential_dump",
    "T1003.001": "credential_dump",
    "T1021": "lateral_movement",
    "T1021.001": "lateral_movement",
    "T1021.002": "lateral_movement",
    "T1048": "data_exfiltration",
    "T1048.003": "data_exfiltration",
    "T1071": "anomaly_detected",
    "T1071.001": "anomaly_detected",
    "T1486": "abnormal_file_encryption",
    "T1078": "suspicious_login",
    "T1547": "privilege_escalation",
    "T1548": "privilege_escalation",
    "T1055": "abnormal_process_execution",
    "T1059": "abnormal_process_execution",
    "T1059.001": "abnormal_process_execution",
    "T1204": "abnormal_process_execution",
    "T1204.002": "abnormal_process_execution",
    "T1046": "network_scan",
    "T1018": "network_scan",
}

# severity_id (OCSF standard enum) -> Cyphora severity string
_SEVERITY_ID_MAP: Dict[int, str] = {
    0: "medium",      # Unknown -> default to medium rather than silently dropping
    1: "low",          # Informational
    2: "low",          # Low
    3: "medium",       # Medium
    4: "high",         # High
    5: "critical",     # Critical
    6: "critical",     # Fatal
    99: "medium",      # Other
}

# Reverse map used by the CEF -> OCSF converter (format_normalizer.py)
# Cyphora severity string -> a representative OCSF severity_id
SEVERITY_STRING_TO_OCSF_ID: Dict[str, int] = {
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


# ─────────────────────────────────────────────────────────────
# Parsed OCSF record (intermediate representation)
# ─────────────────────────────────────────────────────────────


class OCSFRecord:
    """
    Normalized representation of a single OCSF event.

    Attributes
    ----------
    raw            : original decoded JSON dict, untouched
    class_uid      : OCSF Event Class UID (e.g. 3002 = Authentication)
    category_uid   : OCSF Event Category UID (e.g. 3 = IAM)
    activity_id    : OCSF activity identifier within the class
    type_uid       : class_uid * 100 + activity_id (or as provided)
    severity_id    : OCSF severity enum (0-6, 99)
    severity       : Cyphora severity string (low/medium/high/critical)
    message        : human-readable event description
    timestamp      : ISO-8601 UTC string (from `time`, epoch-ms or ISO)
    vendor         : metadata.product.vendor_name (or product.vendor_name)
    product        : metadata.product.name
    user           : resolved username (actor.user.name / user.name)
    src_ip         : resolved source IP (src_endpoint.ip / device.ip)
    src_host       : resolved source hostname (src_endpoint.hostname / device.hostname)
    process        : resolved process name/cmdline (process.name / process.cmd_line)
    attacks        : list of {tactic, technique_uid, technique_name} dicts
    event_id       : metadata.uid / finding_info.uid, else generated UUID
    unmapped       : vendor-specific fields the schema doesn't define
    """

    __slots__ = (
        "raw",
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
        "severity_id",
        "severity",
        "message",
        "timestamp",
        "vendor",
        "product",
        "user",
        "src_ip",
        "src_host",
        "process",
        "attacks",
        "event_id",
        "unmapped",
    )

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.class_uid = _to_int(raw.get("class_uid"))
        self.category_uid = _to_int(raw.get("category_uid"))
        self.activity_id = _to_int(raw.get("activity_id"), default=0)
        _type_uid_raw = _to_int(raw.get("type_uid"))
        self.type_uid = _type_uid_raw if _type_uid_raw is not None else self._derive_type_uid()
        self.severity_id = _to_int(raw.get("severity_id"), default=0)
        self.severity = _SEVERITY_ID_MAP.get(self.severity_id, "medium")
        self.message = raw.get("message") or raw.get("activity_name") or ""
        self.timestamp = self._parse_timestamp(raw.get("time"))

        metadata = _as_dict(raw.get("metadata"))
        product = _as_dict(metadata.get("product")) or _as_dict(raw.get("product"))
        self.vendor = product.get("vendor_name") or product.get("name") or "unknown"
        self.product = product.get("name") or self.vendor

        self.user = self._resolve_user(raw)
        self.src_ip = self._resolve_src_ip(raw)
        self.src_host = self._resolve_src_host(raw)
        self.process = self._resolve_process(raw)
        self.attacks = self._resolve_attacks(raw)

        self.event_id = (
            metadata.get("uid")
            or _as_dict(raw.get("finding_info")).get("uid")
            or raw.get("uid")
            or str(uuid.uuid4())
        )

        # Anything not consumed by the well-known top-level keys is
        # preserved verbatim so no vendor context is lost.
        # NOTE: "severity" (the human-readable caption, e.g. "Critical")
        # is a legitimate, commonly-populated top-level OCSF field
        # alongside severity_id — AWS Security Lake and most other OCSF
        # producers send both. It MUST be excluded here: to_dict()
        # spreads self.unmapped last, so an un-excluded raw "severity"
        # string would silently override the correctly-computed
        # self.severity (Cyphora's normalized low/medium/high/critical)
        # in raw_data with the source's own un-normalized caption.
        # "timestamp", "vendor", and "event_id" are excluded for the
        # same reason — they're the literal names of computed
        # attributes this class already exposes, even though OCSF's
        # canonical field names are technically "time" and
        # "metadata.product.vendor_name" / "metadata.uid".
        _KNOWN_KEYS = {
            "class_uid", "category_uid", "activity_id", "type_uid",
            "severity_id", "severity", "message", "activity_name", "time",
            "timestamp", "metadata", "product", "vendor", "actor", "user",
            "device", "src_endpoint", "dst_endpoint", "process",
            "finding_info", "attacks", "uid", "event_id", "unmapped",
        }
        self.unmapped = {
            **(raw.get("unmapped") or {}),
            **{k: v for k, v in raw.items() if k not in _KNOWN_KEYS},
        }

    # ── timestamp / id resolution ───────────────────────────────

    def _derive_type_uid(self) -> int:
        if self.class_uid is None:
            return 0
        return (self.class_uid * 100) + (self.activity_id or 0)

    @staticmethod
    def _parse_timestamp(value: Any) -> str:
        if value is None or value == "":
            return datetime.now(tz=timezone.utc).isoformat()
        # OCSF `time` is epoch milliseconds per spec
        try:
            ms = float(value)
            # Heuristic: treat values > 10^12 as ms, else seconds
            if ms > 1e12:
                return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
            return datetime.fromtimestamp(ms, tz=timezone.utc).isoformat()
        except (TypeError, ValueError):
            pass
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).isoformat()
        except Exception:
            return datetime.now(tz=timezone.utc).isoformat()

    # ── entity resolution (actor / user / device / endpoints) ───

    @staticmethod
    def _resolve_user(raw: Dict[str, Any]) -> Optional[str]:
        actor = _as_dict(raw.get("actor"))
        actor_user = _as_dict(actor.get("user"))
        user = _as_dict(raw.get("user"))
        return (
            actor_user.get("name")
            or actor_user.get("email_addr")
            or user.get("name")
            or user.get("email_addr")
            or None
        )

    @staticmethod
    def _resolve_src_ip(raw: Dict[str, Any]) -> Optional[str]:
        src_ep = _as_dict(raw.get("src_endpoint"))
        device = _as_dict(raw.get("device"))
        return src_ep.get("ip") or device.get("ip") or None

    @staticmethod
    def _resolve_src_host(raw: Dict[str, Any]) -> Optional[str]:
        src_ep = _as_dict(raw.get("src_endpoint"))
        device = _as_dict(raw.get("device"))
        return (
            src_ep.get("hostname")
            or device.get("hostname")
            or device.get("name")
            or None
        )

    @staticmethod
    def _resolve_process(raw: Dict[str, Any]) -> Optional[str]:
        process = _as_dict(raw.get("process"))
        if not process:
            return None
        return process.get("cmd_line") or process.get("name") or None

    @staticmethod
    def _resolve_attacks(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        attacks_raw = raw.get("attacks")
        if not isinstance(attacks_raw, list):
            # Defensive: a malformed/non-conformant vendor source might
            # send a single object instead of an array, or omit it
            # entirely. Never let a shape mismatch here raise — MITRE
            # context is a bonus signal, not a required field.
            return []
        resolved = []
        for a in attacks_raw:
            if not isinstance(a, dict):
                continue
            technique = _as_dict(a.get("technique"))
            tactic = _as_dict(a.get("tactic"))
            resolved.append({
                "tactic_name": tactic.get("name"),
                "tactic_uid": tactic.get("uid"),
                "technique_uid": technique.get("uid"),
                "technique_name": technique.get("name"),
            })
        return resolved

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        """
        Flat dict — used as DataCollector telemetry payload.

        `**self.unmapped` is spread FIRST and the computed/authoritative
        fields are listed after, so a vendor-supplied field can never
        silently override a value this class has already resolved (a
        dict literal lets a later key win over an earlier one with the
        same name). This is defense-in-depth on top of the _KNOWN_KEYS
        exclusion in __init__: even if some future OCSF producer's
        `unmapped` sub-object happens to contain a key that collides
        with one of these names, the computed value always wins.
        """
        return {
            **self.unmapped,
            "ocsf_class_uid": self.class_uid,
            "ocsf_category_uid": self.category_uid,
            "ocsf_category_name": OCSFCategory.name(self.category_uid),
            "ocsf_activity_id": self.activity_id,
            "ocsf_type_uid": self.type_uid,
            "ocsf_severity_id": self.severity_id,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "vendor": self.vendor,
            "product": self.product,
            "user": self.user,
            "src_ip": self.src_ip,
            "src_host": self.src_host,
            "process": self.process,
            "message": self.message,
            "attacks": self.attacks,
            "event_id": self.event_id,
        }


def _to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_dict(value: Any) -> Dict[str, Any]:
    """
    Defensive guard used throughout entity resolution: real-world and
    malformed/non-conformant vendor sources sometimes send a string,
    a list, or null where the schema expects a nested object (e.g.
    `"device": "unknown"` instead of `"device": {"hostname": ...}`).
    Treat anything that isn't actually a dict as empty rather than
    raising deep inside attribute resolution.
    """
    return value if isinstance(value, dict) else {}


# ─────────────────────────────────────────────────────────────
# Main OCSF Parser
# ─────────────────────────────────────────────────────────────


class OCSFParser:
    """
    Parses OCSF event content (single object / JSON array / NDJSON)
    into OCSFRecord objects, then converts them to Cyphora
    SecurityEvent-compatible dicts via to_security_event_dict().

    Mirrors the public surface of cef_parser.CEFParser so the two
    ingestion paths are interchangeable in calling code.
    """

    def parse_dict(self, event: Dict[str, Any]) -> Optional[OCSFRecord]:
        """Parse a single already-decoded OCSF event dict."""
        if not isinstance(event, dict) or not event:
            return None
        return OCSFRecord(event)

    def parse_text(self, text: str) -> List[OCSFRecord]:
        """
        Parse OCSF content from a raw string. Auto-detects:
          - a single JSON object              {...}
          - a JSON array of events            [{...}, {...}]
          - NDJSON / JSON-Lines (one per line) {...}\\n{...}
        """
        text = text.strip()
        if not text:
            return []

        # Try whole-document JSON first (object or array)
        try:
            decoded = json.loads(text)
            if isinstance(decoded, list):
                records = [self.parse_dict(e) for e in decoded]
                records = [r for r in records if r is not None]
                logger.info("ocsf_parse_complete", total=len(records), mode="array")
                return records
            if isinstance(decoded, dict):
                rec = self.parse_dict(decoded)
                records = [rec] if rec else []
                logger.info("ocsf_parse_complete", total=len(records), mode="object")
                return records
        except json.JSONDecodeError:
            pass  # fall through to NDJSON handling

        # NDJSON: one JSON object per non-blank line
        records: List[OCSFRecord] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("ocsf_parse_line_skipped", line_no=line_no)
                continue
            if isinstance(decoded, dict):
                rec = self.parse_dict(decoded)
                if rec:
                    records.append(rec)
            elif isinstance(decoded, list):
                for e in decoded:
                    rec = self.parse_dict(e)
                    if rec:
                        records.append(rec)

        logger.info("ocsf_parse_complete", total=len(records), mode="ndjson")
        return records

    def parse_file(self, path: str | Path) -> List[OCSFRecord]:
        """Parse all OCSF records from a .json / .ndjson / .jsonl file on disk."""
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        return self.parse_text(content)

    # ── Conversion to SecurityEvent-compatible dict ────────────

    def to_security_event_dict(self, rec: OCSFRecord) -> Dict[str, Any]:
        """
        Convert an OCSFRecord to a dict compatible with SecurityEvent(**d).

        event_type is resolved in priority order, mirroring the CEF
        parser's logic so AI reasoning and MITRE mapping behave
        consistently regardless of the originating log format:

          1. MITRE technique present in attacks[]
          2. class_uid + activity_id mapping table (specific, then
             class-wide "*" default)
          3. category-level heuristic
          4. message/finding text keyword heuristics
          5. default: 'anomaly_detected'
        """
        event_type = self._resolve_event_type(rec)

        return {
            "event_id": self._make_event_id(rec),
            "event_type": event_type,
            "severity": rec.severity,
            "timestamp": rec.timestamp,
            "source_ip": rec.src_ip,
            "source_host": rec.src_host,
            "user": rec.user,
            "process": rec.process,
            "raw_data": {
                "product": rec.vendor,
                "ocsf_vendor": rec.vendor,
                "ocsf_product": rec.product,
                "ocsf_class_uid": rec.class_uid,
                "ocsf_category_uid": rec.category_uid,
                "ocsf_category_name": OCSFCategory.name(rec.category_uid),
                "ocsf_activity_id": rec.activity_id,
                "ocsf_type_uid": rec.type_uid,
                "ocsf_severity_id": rec.severity_id,
                "source": f"ocsf_{rec.vendor}".lower().replace(" ", "_"),
                **rec.to_dict(),
            },
        }

    # ── Private helpers ────────────────────────────────────────

    @staticmethod
    def _make_event_id(rec: OCSFRecord) -> str:
        return f"ocsf:{rec.event_id}"

    @staticmethod
    def _resolve_event_type(rec: OCSFRecord) -> str:
        # 1. MITRE technique (highest precedence — same as CEF parser)
        for attack in rec.attacks:
            technique = attack.get("technique_uid") or ""
            if technique:
                evt = _TECHNIQUE_TO_EVENT_TYPE.get(technique)
                if not evt:
                    evt = _TECHNIQUE_TO_EVENT_TYPE.get(technique.split(".")[0])
                if evt:
                    return evt

        # 2. class_uid + activity_id table (specific, then wildcard)
        if rec.class_uid is not None:
            specific_key = f"{rec.class_uid}:{rec.activity_id}"
            evt = _CLASS_ACTIVITY_EVENT_TYPE_MAP.get(specific_key)
            if evt:
                return evt
            wildcard_key = f"{rec.class_uid}:*"
            evt = _CLASS_ACTIVITY_EVENT_TYPE_MAP.get(wildcard_key)
            if evt:
                return evt

        # 3. Category-level heuristic
        # (Discovery is intentionally absent here — see the note above
        # _CLASS_ACTIVITY_EVENT_TYPE_MAP: it's defensive asset/inventory
        # telemetry, not attacker recon, so it falls through to the
        # keyword heuristics / default below.)
        category_default = {
            OCSFCategory.FINDINGS: "confirmed_attack",
            OCSFCategory.IAM: "suspicious_login",
            OCSFCategory.NETWORK_ACTIVITY: "anomaly_detected",
            OCSFCategory.SYSTEM_ACTIVITY: "abnormal_process_execution",
        }.get(rec.category_uid)
        if category_default:
            return category_default

        # 4. Message / finding-text keyword heuristics
        msg_lower = (rec.message or "").lower()
        if any(x in msg_lower for x in ["ransomware", "encrypt"]):
            return "abnormal_file_encryption"
        if any(x in msg_lower for x in ["credential", "lsass", "mimikatz", "dump"]):
            return "credential_dump"
        if any(x in msg_lower for x in ["lateral", "psexec", "smb scan", "wmi remote"]):
            return "lateral_movement"
        if any(x in msg_lower for x in ["exfil", "tunneling", "dns tunnel"]):
            return "data_exfiltration"
        if any(x in msg_lower for x in ["privilege", "escalat"]):
            return "privilege_escalation"
        if any(x in msg_lower for x in ["logon", "login", "auth", "locked", "password"]):
            return "suspicious_login"
        if any(x in msg_lower for x in ["malware", "detect", "c2", "command and control"]):
            return "confirmed_attack"
        if any(x in msg_lower for x in ["process", "powershell", "script"]):
            return "abnormal_process_execution"
        if any(x in msg_lower for x in ["scan", "sweep", "enumeration"]):
            return "network_scan"

        return "anomaly_detected"


# ─────────────────────────────────────────────────────────────
# Convenience: parse file/text directly to SecurityEvent dicts
# ─────────────────────────────────────────────────────────────


def parse_ocsf_file(path: str | Path) -> List[Dict[str, Any]]:
    """Parse an OCSF JSON/NDJSON file and return SecurityEvent-compatible dicts."""
    parser = OCSFParser()
    return [parser.to_security_event_dict(r) for r in parser.parse_file(path)]


def parse_ocsf_text(text: str) -> List[Dict[str, Any]]:
    """Parse OCSF JSON/NDJSON text and return SecurityEvent-compatible dicts."""
    parser = OCSFParser()
    return [parser.to_security_event_dict(r) for r in parser.parse_text(text)]
