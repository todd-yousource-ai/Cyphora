"""
Cyphora-S1 — CEF Log Parser
=============================
Parses Common Event Format (CEF) log lines produced by:
  - CrowdStrike Falcon (FalconHost)
  - Palo Alto Networks Cortex XDR
  - Okta Identity Platform

CEF Format Reference
--------------------
CEF:Version|Device Vendor|Device Product|Device Version|
    Device Event Class ID|Name|Severity|Extension

Extension is a space-separated list of key=value pairs.
Values may contain spaces when escaped with a backslash.
Custom fields use the csNLabel / csN pattern, e.g.:
  cs1Label=Technique cs1=T1059.001

This module handles:
  - Multi-line log entries (lines wrapped at column 80 in syslog files)
  - CEF header parsing with pipe-escape handling
  - Extension field parsing including cs1–cs6 label resolution
  - Epoch millisecond → ISO-8601 timestamp conversion
  - Per-vendor field normalization into a flat, consistent dict

Usage
-----
    from cyphora_s1.cef_parser import CEFParser

    parser = CEFParser()

    # Parse a single line
    event = parser.parse_line(raw_cef_string)

    # Parse an entire log file
    events = parser.parse_file("/var/log/crowdstrike.cef")

    # Parse raw string content
    events = parser.parse_text(log_file_contents)
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Vendor identification
# ─────────────────────────────────────────────────────────────


class CEFVendor:
    CROWDSTRIKE = "crowdstrike"
    PALO_ALTO = "palo_alto"
    OKTA = "okta"
    UNKNOWN = "unknown"

    _VENDOR_MAP = {
        "crowdstrike": CROWDSTRIKE,
        "palo alto networks": PALO_ALTO,
        "paloaltonetworks": PALO_ALTO,
        "okta": OKTA,
    }

    @classmethod
    def identify(cls, vendor_str: str) -> str:
        return cls._VENDOR_MAP.get(vendor_str.strip().lower(), cls.UNKNOWN)


# ─────────────────────────────────────────────────────────────
# Maps: CEF event class ID → Cyphora event_type
# ─────────────────────────────────────────────────────────────

_CS_EVENT_TYPE_MAP: Dict[str, str] = {
    # CrowdStrike class IDs
    "detectionsummaryevent": "confirmed_attack",
    "processrollup2": "abnormal_process_execution",
    "networkconnectip4": "anomaly_detected",
    "networkconnectip6": "anomaly_detected",
    "userlogon": "suspicious_login",
    "userlogoff": "suspicious_login",
    "authactivity": "suspicious_login",
    "idindicator": "confirmed_attack",
    "incidentevent": "confirmed_attack",
    "compositeincidentevent": "confirmed_attack",
    # Palo Alto Cortex XDR class IDs
    "alert": "confirmed_attack",
    "prevention": "abnormal_process_execution",
    "network": "anomaly_detected",
    "bioc": "confirmed_attack",
    "xdr_alert": "confirmed_attack",
    # Okta class IDs
    "user.session.start": "suspicious_login",
    "user.authentication.auth_via_mfa": "suspicious_login",
    "user.account.lock": "suspicious_login",
    "user.account.reset_password": "suspicious_login",
    "user.account.privilege.grant": "privilege_escalation",
    "application.user_membership.add": "privilege_escalation",
    "user.mfa.factor.deactivate": "privilege_escalation",
    "policy.evaluate_sign_on": "suspicious_login",
    "security.threat.detected": "confirmed_attack",
    "system.api_token.create": "privilege_escalation",
}

_TECHNIQUE_TO_EVENT_TYPE: Dict[str, str] = {
    "T1003": "credential_dump",
    "T1003.001": "credential_dump",
    "T1021": "lateral_movement",
    "T1021.001": "lateral_movement",
    "T1021.002": "lateral_movement",
    "T1048": "data_exfiltration",
    "T1048.003": "data_exfiltration",
    "T1071": "anomaly_detected",
    "T1486": "abnormal_file_encryption",
    "T1078": "suspicious_login",
    "T1547": "privilege_escalation",
    "T1548": "privilege_escalation",
    "T1055": "abnormal_process_execution",
    "T1059": "abnormal_process_execution",
    "T1059.001": "abnormal_process_execution",
    "T1204": "abnormal_process_execution",
}

# Severity mapping (CEF integer 0-10 → Cyphora string)
_SEVERITY_MAP = {
    0: "low",
    1: "low",
    2: "low",
    3: "low",
    4: "medium",
    5: "medium",
    6: "medium",
    7: "high",
    8: "high",
    9: "critical",
    10: "critical",
}


# ─────────────────────────────────────────────────────────────
# Parsed CEF record (intermediate representation)
# ─────────────────────────────────────────────────────────────


class CEFRecord:
    """
    Parsed representation of a single CEF log line.

    Attributes
    ----------
    raw          : original unparsed line
    version      : CEF version integer
    vendor       : normalised vendor identifier (CEFVendor constant)
    product      : product string as-is from header
    dev_version  : device version string
    event_class  : device event class ID (normalised to lowercase)
    name         : human-readable event name
    severity_int : CEF severity 0-10
    severity     : Cyphora severity string (low/medium/high/critical)
    fields       : merged extension dict with cs labels resolved
    timestamp    : ISO-8601 UTC string (from rt field or now)
    event_id     : auto-generated UUID
    """

    __slots__ = (
        "raw",
        "version",
        "vendor",
        "product",
        "dev_version",
        "event_class",
        "name",
        "severity_int",
        "severity",
        "fields",
        "timestamp",
        "event_id",
    )

    def __init__(
        self,
        raw: str,
        version: int,
        vendor: str,
        product: str,
        dev_version: str,
        event_class: str,
        name: str,
        severity_int: int,
        fields: Dict[str, Any],
    ):
        self.raw = raw
        self.version = version
        self.vendor = vendor
        self.product = product
        self.dev_version = dev_version
        self.event_class = event_class
        self.name = name
        self.severity_int = severity_int
        self.severity = _SEVERITY_MAP.get(severity_int, "medium")
        self.fields = fields
        self.timestamp = self._parse_timestamp(fields.get("rt", ""))
        self.event_id = fields.get(
            "cs1", str(uuid.uuid4())
        )  # cs1 often carries alert ID

    @staticmethod
    def _parse_timestamp(rt_value: str) -> str:
        """Convert epoch-ms string or datetime string to ISO-8601 UTC."""
        if not rt_value:
            return datetime.now(tz=timezone.utc).isoformat()
        try:
            epoch_ms = int(rt_value)
            return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).isoformat()
        except (ValueError, TypeError):
            try:
                return datetime.fromisoformat(rt_value).isoformat()
            except Exception:
                return datetime.now(tz=timezone.utc).isoformat()

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cef_version": self.version,
            "vendor": self.vendor,
            "product": self.product,
            "dev_version": self.dev_version,
            "event_class": self.event_class,
            "event_name": self.name,
            "severity_int": self.severity_int,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            **self.fields,
        }


# ─────────────────────────────────────────────────────────────
# Extension field parser
# ─────────────────────────────────────────────────────────────

# CEF extension tokeniser: key=value where value ends at next key= or EOL
# Handles values that contain spaces (not followed by word=)
_EXT_PATTERN = re.compile(r"(\w+)=((?:(?!\s+\w+=).)+)", re.DOTALL)


def _parse_extension(ext: str) -> Dict[str, str]:
    """
    Parse the CEF extension string into a flat key→value dict.
    Resolves csNLabel/csN pairs: cs1Label=Technique cs1=T1059.001
    becomes {"Technique": "T1059.001", "cs1": "T1059.001", "cs1_label": "Technique"}
    """
    raw_fields: Dict[str, str] = {}
    for match in _EXT_PATTERN.finditer(ext):
        key = match.group(1).strip()
        value = match.group(2).strip().replace("\\=", "=").replace("\\|", "|")
        raw_fields[key] = value

    # Resolve csN label aliases
    resolved: Dict[str, str] = dict(raw_fields)
    for n in range(1, 7):
        label_key = f"cs{n}Label"
        value_key = f"cs{n}"
        label = raw_fields.get(label_key, "")
        value = raw_fields.get(value_key, "")
        if label and value:
            resolved[label] = value
            resolved[f"cs{n}_label"] = label

    return resolved


# ─────────────────────────────────────────────────────────────
# CEF header parser
# ─────────────────────────────────────────────────────────────

# Split on unescaped pipe characters
_PIPE_SPLIT = re.compile(r"(?<!\\)\|")


def _parse_header(header: str) -> Optional[Tuple[int, str, str, str, str, str, int]]:
    """
    Parse 'CEF:0|Vendor|Product|Version|ClassID|Name|Severity'
    Returns (version, vendor, product, dev_version, class_id, name, severity_int)
    or None if the header is malformed.
    """
    # Strip leading syslog timestamp / hostname if present
    # Pattern: optional "Jan  1 00:00:00 hostname " prefix
    header = re.sub(r"^\w{3}\s+\d+\s+[\d:]+\s+\S+\s+", "", header.strip())
    # Strip CEF: prefix
    if not header.upper().startswith("CEF:"):
        return None

    parts = _PIPE_SPLIT.split(header, maxsplit=7)
    if len(parts) < 7:
        return None

    try:
        version = int(parts[0].split(":", 1)[1].strip())
        vendor = parts[1].strip()
        product = parts[2].strip()
        dev_version = parts[3].strip()
        class_id = parts[4].strip()
        name = parts[5].strip()
        severity = int(parts[6].strip())
    except (ValueError, IndexError):
        return None

    return version, vendor, product, dev_version, class_id, name, severity


# ─────────────────────────────────────────────────────────────
# Main CEF Parser
# ─────────────────────────────────────────────────────────────


class CEFParser:
    """
    Parses CEF log content from CrowdStrike Falcon, Palo Alto Cortex XDR,
    and Okta into CEFRecord objects, then converts them to Cyphora
    SecurityEvent-compatible dicts via to_security_event_dict().

    Handles multi-line wrapped CEF entries (common in syslog files where
    long lines are wrapped at 80 or 512 characters).
    """

    # Pre-compiled: strip comment lines and blank lines
    _COMMENT = re.compile(r"^\s*#")
    _BLANK = re.compile(r"^\s*$")
    # Detects start of a new CEF record
    _CEF_START = re.compile(r"^\s*CEF:", re.IGNORECASE)

    def parse_line(self, line: str) -> Optional[CEFRecord]:
        """Parse a single complete CEF line. Returns None if not a valid CEF event."""
        line = line.strip()
        if not line or self._COMMENT.match(line) or not self._CEF_START.match(line):
            return None

        # Split into header (first 7 pipe-delimited fields) and extension
        parts = _PIPE_SPLIT.split(line, maxsplit=7)
        if len(parts) < 7:
            return None

        header_str = "|".join(parts[:7])
        extension = parts[7] if len(parts) > 7 else ""

        parsed = _parse_header(header_str)
        if not parsed:
            logger.debug("cef_parse_header_failed", line=line[:80])
            return None

        version, vendor_raw, product, dev_version, class_id, name, sev_int = parsed
        vendor = CEFVendor.identify(vendor_raw)
        fields = _parse_extension(extension)

        return CEFRecord(
            raw=line,
            version=version,
            vendor=vendor,
            product=product,
            dev_version=dev_version,
            event_class=class_id.lower(),
            name=name,
            severity_int=sev_int,
            fields=fields,
        )

    def parse_text(self, text: str) -> List[CEFRecord]:
        """
        Parse a multi-line string of CEF logs.
        Handles continuation lines (lines that do not start with CEF: are
        appended to the previous CEF line before parsing).
        """
        records: List[CEFRecord] = []
        current_line = ""

        for raw_line in text.splitlines():
            # Skip comments and section headers (===...===)
            if self._COMMENT.match(raw_line) or re.match(r"^\s*=+", raw_line):
                continue
            if self._BLANK.match(raw_line):
                continue

            if self._CEF_START.match(raw_line):
                # Flush previous accumulated line
                if current_line:
                    rec = self.parse_line(current_line)
                    if rec:
                        records.append(rec)
                current_line = raw_line.rstrip()
            else:
                # Continuation of previous line (wrapped)
                current_line = (current_line + " " + raw_line.strip()).strip()

        # Flush last line
        if current_line:
            rec = self.parse_line(current_line)
            if rec:
                records.append(rec)

        logger.info("cef_parse_complete", total=len(records))
        return records

    def parse_file(self, path: str | Path) -> List[CEFRecord]:
        """Parse all CEF records from a log file on disk."""
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        return self.parse_text(content)

    # ── Conversion to SecurityEvent-compatible dict ────────────

    def to_security_event_dict(self, rec: CEFRecord) -> Dict[str, Any]:
        """
        Convert a CEFRecord to a dict compatible with SecurityEvent(**d).

        The Cyphora event_type is resolved in priority order:
          1. MITRE technique → event_type mapping
          2. CEF event class ID → event_type mapping
          3. Outcome field heuristics
          4. Default: 'anomaly_detected'

        raw_data carries the full normalised CEF field dict so that
        the LLM reasoning ensemble and MITRE mapper have maximum context.
        """
        fields = rec.fields
        event_type = self._resolve_event_type(rec)
        vendor_label = rec.vendor  # e.g. "crowdstrike"

        return {
            "event_id": self._make_event_id(rec),
            "event_type": event_type,
            "severity": rec.severity,
            "timestamp": rec.timestamp,
            "source_ip": fields.get("src") or fields.get("dvc") or None,
            "source_host": fields.get("dvchost") or None,
            "user": fields.get("suser") or fields.get("duser") or None,
            "process": (
                fields.get("ProcessName")
                or fields.get("cs4")  # cs4 is often process in CrowdStrike
                or None
            ),
            "raw_data": {
                "product": vendor_label,
                "cef_vendor": rec.vendor,
                "cef_product": rec.product,
                "cef_event_class": rec.event_class,
                "cef_event_name": rec.name,
                "cef_severity": rec.severity_int,
                "source": f"cef_{vendor_label}",
                **rec.to_dict(),
            },
        }

    # ── Private helpers ────────────────────────────────────────

    @staticmethod
    def _make_event_id(rec: CEFRecord) -> str:
        """
        Prefer a vendor-native ID (alert ID, detect ID) if present;
        otherwise generate a UUID.
        """
        # CrowdStrike: DetectId is in cs1 when cs1Label=DetectId
        if rec.fields.get("cs1_label", "").lower() == "detectid":
            return f"cs:{rec.fields.get('cs1', uuid.uuid4().hex)}"
        # Palo Alto: AlertId in cs1 when cs1Label=AlertId
        if rec.fields.get("cs1_label", "").lower() == "alertid":
            return f"pan:{rec.fields.get('cs1', uuid.uuid4().hex)}"
        # Okta: SessionId in cs1 when cs1Label=SessionId
        if rec.fields.get("cs1_label", "").lower() == "sessionid":
            return f"okta:{rec.fields.get('cs1', uuid.uuid4().hex)}"
        return str(uuid.uuid4())

    @staticmethod
    def _resolve_event_type(rec: CEFRecord) -> str:
        """Resolve Cyphora event_type from CEF record fields."""
        fields = rec.fields

        # 1. MITRE technique takes highest precedence
        technique = (
            fields.get("Technique")
            or fields.get("MitreTechnique")
            or fields.get("cs2")  # often Technique in CrowdStrike
            or fields.get("cs6")  # often MitreTechnique in Cortex
            or ""
        )
        if technique:
            # Try full technique first, then base (strip sub-technique)
            evt = _TECHNIQUE_TO_EVENT_TYPE.get(technique)
            if not evt:
                evt = _TECHNIQUE_TO_EVENT_TYPE.get(technique.split(".")[0])
            if evt:
                return evt

        # 2. Event class ID mapping
        evt = _CS_EVENT_TYPE_MAP.get(rec.event_class)
        if evt:
            return evt

        # 3. Tactic heuristics
        tactic = (
            fields.get("Tactic")
            or fields.get("MitreTactic")
            or fields.get("cs3")
            or fields.get("cs5")
            or ""
        ).lower()
        tactic_map = {
            "credential access": "credential_dump",
            "lateral movement": "lateral_movement",
            "exfiltration": "data_exfiltration",
            "impact": "abnormal_file_encryption",
            "privilege escalation": "privilege_escalation",
            "command and control": "anomaly_detected",
            "initial access": "suspicious_login",
        }
        for key, cyphora_type in tactic_map.items():
            if key in tactic:
                return cyphora_type

        # 4. Outcome / name heuristics
        name_lower = rec.name.lower()
        if any(x in name_lower for x in ["ransomware", "encrypt"]):
            return "abnormal_file_encryption"
        if any(x in name_lower for x in ["credential", "lsass", "mimikatz", "dump"]):
            return "credential_dump"
        if any(x in name_lower for x in ["lateral", "psexec", "wmi remote"]):
            return "lateral_movement"
        if any(x in name_lower for x in ["exfil", "tunneling", "dns tunnel"]):
            return "data_exfiltration"
        if any(x in name_lower for x in ["privilege", "escalat"]):
            return "privilege_escalation"
        if any(
            x in name_lower for x in ["logon", "login", "auth", "locked", "password"]
        ):
            return "suspicious_login"
        if any(x in name_lower for x in ["malware", "detect", "c2", "command"]):
            return "confirmed_attack"
        if any(x in name_lower for x in ["process", "powershell", "script"]):
            return "abnormal_process_execution"

        return "anomaly_detected"


# ─────────────────────────────────────────────────────────────
# Convenience: parse file/text directly to SecurityEvent dicts
# ─────────────────────────────────────────────────────────────


def parse_cef_file(path: str | Path) -> List[Dict[str, Any]]:
    """Parse a CEF log file and return a list of SecurityEvent-compatible dicts."""
    parser = CEFParser()
    return [parser.to_security_event_dict(r) for r in parser.parse_file(path)]


def parse_cef_text(text: str) -> List[Dict[str, Any]]:
    """Parse a CEF log string and return a list of SecurityEvent-compatible dicts."""
    parser = CEFParser()
    return [parser.to_security_event_dict(r) for r in parser.parse_text(text)]
