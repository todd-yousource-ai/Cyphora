"""
Cyphora-S1 — Product-Faithful Simulated Data Adapters
======================================================
These adapters replace the generic Simulated*Adapter classes in
acda/runtime/data_collector.py when real product credentials are not
configured.  They generate telemetry that exactly mirrors the JSON
structure returned by each product's real API — same field names, same
value ranges, same nested objects — so the LLM reasoning ensemble sees
authentic-looking investigation context even in offline / test mode.

Products
--------
  CrowdStrikeSimAdapter   CrowdStrike Falcon Detections API response format
  OktaSimAdapter          Okta System Log API response format
  PaloAltoSimAdapter      Palo Alto PAN-OS threat/traffic log format
  CortexXDRSimAdapter     Palo Alto Cortex XDR alert format

Registration
------------
Call register_simulated_adapters() once at the top of any test or
example script that does NOT supply live credentials.  It replaces the
four relevant entries in _ADAPTER_MAP and leaves all other adapters
(including any live-credential ones already registered) unchanged.

    from cyphora_s1.sim_adapters import register_simulated_adapters
    register_simulated_adapters()

Or call register_all_adapters() from cyphora_ingest — it already falls
back to these automatically when credentials are absent.
"""

from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from acda.runtime.data_collector import BaseSourceAdapter, _ADAPTER_MAP
from acda.models.schemas import SecurityEvent


# ── helpers ────────────────────────────────────────────────────────────────


def _iso(base: datetime, offset_seconds: int = 0) -> str:
    return (base + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _rand_host() -> str:
    return random.choice(
        [
            "LAPTOP-JSMITH",
            "WKS-HR-ADMIN",
            "APPSERVER-01",
            "SQLSERVER-01",
            "DC-CORP-01",
            "FILESERVER-01",
            "DEVOPS-BUILD-01",
            "BACKUP-SRV",
            "WKS-DBROWN",
            "MONITORING-SRV",
            "CI-RUNNER-07",
        ]
    )


def _rand_ip(internal: bool = True) -> str:
    if internal:
        return (
            f"10.{random.randint(0,50)}.{random.randint(0,20)}.{random.randint(1,254)}"
        )
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _rand_user() -> str:
    return random.choice(
        [
            "jsmith@corp.example",
            "mwilliams@corp.example",
            "dbrown@corp.example",
            "svc_backup@corp.example",
            "hradmin@corp.example",
            "it_admin@corp.example",
            "CORP\\administrator",
            "CORP\\svc_monitoring",
        ]
    )


MITRE_POOL = [
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    ("T1078", "Valid Accounts", "Defense Evasion"),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
    ("T1105", "Ingress Tool Transfer", "Command and Control"),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ("T1053.005", "Scheduled Task", "Persistence"),
    ("T1047", "Windows Management Instrumentation", "Lateral Movement"),
    ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
]

CS_DETECTION_NAMES = [
    "SUSPICIOUS_POWERSHELL_USAGE",
    "CREDENTIAL_THEFT_TOOL_USAGE",
    "LATERAL_MOVEMENT_PSEXEC",
    "RANSOMWARE_BEHAVIOR_DETECTED",
    "LOLBIN_CERTUTIL_DOWNLOAD",
    "MIMIKATZ_LSASS_DUMP",
    "SCHEDULED_TASK_PERSISTENCE",
    "WMI_REMOTE_EXECUTION",
    "NETWORK_DISCOVERY_SCAN",
    "MALICIOUS_MACRO_EXECUTION",
]

OKTA_EVENT_TYPES = [
    "user.authentication.sso",
    "user.authentication.auth_via_mfa",
    "user.session.start",
    "user.account.privilege.grant",
    "policy.evaluate_sign_on",
    "security.threat.detected",
    "user.mfa.factor.activate",
    "user.account.update_password",
    "application.user_membership.add",
    "system.api_token.create",
]

PAN_THREAT_CATEGORIES = [
    "command-and-control",
    "brute-force",
    "scan",
    "exploit",
    "data-exfiltration",
    "dns-tunneling",
    "spyware",
    "vulnerability",
]

PAN_APPLICATIONS = [
    "ssl",
    "http",
    "smb",
    "rdp",
    "dns",
    "ftp",
    "ssh",
    "dropbox",
    "office365",
    "nessus",
    "ldap",
]

AWS_EVENT_NAMES = [
    "ConsoleLogin",
    "AssumeRole",
    "CreateAccessKey",
    "AttachUserPolicy",
    "PutBucketPolicy",
    "GetObject",
    "StartInstances",
    "AuthorizeSecurityGroupIngress",
]

AZURE_AD_OPERATIONS = [
    "UserLoggedIn",
    "Add service principal credentials",
    "Add member to role",
    "Consent to application",
    "Update application",
    "Reset user password",
    "MFA requirement satisfied by claim in the token",
]


# ══════════════════════════════════════════════════════════════════════════
# 1. CrowdStrike Falcon — Detections API response schema
#    Real endpoint: GET /detects/entities/summaries/GET/v1
# ══════════════════════════════════════════════════════════════════════════


class CrowdStrikeSimAdapter(BaseSourceAdapter):
    """
    Returns records structured exactly like CrowdStrike Falcon
    /detects/entities/summaries/GET/v1 responses, including the nested
    device, behaviors, and tactics fields that the real API returns.

    Field reference:
      https://falcon.crowdstrike.com/documentation/86/detections-monitoring-apis
    """

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 500,
    ) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.04)  # realistic API latency

        # Derive realism cues from the triggering event's raw_data
        raw = event.raw_data or {}
        trigger_technique, trigger_tactic = raw.get("technique", "T1059"), raw.get(
            "tactic", "Execution"
        )
        trigger_host = (
            getattr(event, "source_host", None) or raw.get("host") or _rand_host()
        )
        trigger_user = (
            getattr(event, "user", None) or raw.get("user_id") or _rand_user()
        )

        records: List[Dict[str, Any]] = []
        count = random.randint(3, min(12, max_records))

        for i in range(count):
            technique_id, technique_name, tactic = random.choice(MITRE_POOL)
            # Bias toward the triggering technique for the first record
            if i == 0 and trigger_technique:
                technique_id = trigger_technique
                tactic = trigger_tactic

            ts = _iso(since, offset_seconds=i * random.randint(30, 300))
            detection_id = (
                f"ldt:{uuid.uuid4().hex[:16]}:{random.randint(1000000, 9999999)}"
            )

            records.append(
                {
                    # CrowdStrike top-level detection fields
                    "source": "crowdstrike_falcon",
                    "cid": "abc1234567890abcdef1234567890ab",
                    "detection_id": detection_id,
                    "created_timestamp": ts,
                    "max_severity": random.choice([50, 70, 80, 90, 100]),
                    "max_severity_displayname": random.choice(
                        ["Medium", "High", "Critical"]
                    ),
                    "status": random.choice(["new", "in_progress", "true_positive"]),
                    "assigned_to_name": None,
                    # Device block
                    "device": {
                        "device_id": uuid.uuid4().hex[:32],
                        "cid": "abc1234567890abcdef1234567890ab",
                        "hostname": trigger_host if i < 2 else _rand_host(),
                        "local_ip": getattr(event, "source_ip", None) or _rand_ip(True),
                        "external_ip": _rand_ip(False),
                        "platform_name": "Windows",
                        "os_version": "Windows 11 22H2",
                        "agent_version": "7.15.17706.0",
                        "status": "normal",
                        "first_seen": "2024-01-01T00:00:00Z",
                        "last_seen": ts,
                        "groups": ["corporate_laptops", "domain_joined"],
                    },
                    # Behaviors block — maps 1:1 to MITRE ATT&CK
                    "behaviors": [
                        {
                            "behavior_id": f"ind:{uuid.uuid4().hex[:16]}:1",
                            "timestamp": ts,
                            "alleged_filetype": "exe",
                            "technique": technique_name,
                            "technique_id": technique_id,
                            "tactic": tactic,
                            "tactic_id": f"TA{random.randint(1000, 1599)}",
                            "display_name": random.choice(CS_DETECTION_NAMES),
                            "description": f"Suspicious activity indicative of {technique_name} was detected.",
                            "filename": random.choice(
                                [
                                    "powershell.exe",
                                    "cmd.exe",
                                    "certutil.exe",
                                    "schtasks.exe",
                                    "wmic.exe",
                                ]
                            ),
                            "filepath": f"C:\\Windows\\System32\\{random.choice(['powershell.exe','cmd.exe','certutil.exe'])}",
                            "cmdline": f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {uuid.uuid4().hex}",
                            "parent_details": {
                                "filename": "WINWORD.EXE",
                                "cmdline": "WINWORD.EXE /n C:\\Users\\Documents\\invoice.docm",
                            },
                            "user_name": trigger_user,
                            "user_id": f"S-1-5-21-{random.randint(1000000000,9999999999)}-{random.randint(1000,9999)}",
                            "sha256": uuid.uuid4().hex + uuid.uuid4().hex,
                            "md5": uuid.uuid4().hex,
                            "ioc_type": "hash_sha256",
                            "ioc_value": uuid.uuid4().hex + uuid.uuid4().hex,
                            "severity": random.randint(50, 100),
                            "objective": random.choice(
                                ["Falcon Detection Method", "Binary Executables"]
                            ),
                            "pattern_id": str(random.randint(10000, 50000)),
                            "rule_instance_id": str(random.randint(1, 999)),
                        }
                    ],
                    # Tactics summary
                    "tactics": [tactic],
                    "techniques": [technique_name],
                    "composite_id": f"{detection_id}:{uuid.uuid4().hex[:8]}",
                    "overwatch_notes": (
                        "CrowdStrike Falcon OverWatch analyst reviewed this detection and "
                        "confirmed malicious activity consistent with a targeted intrusion."
                        if random.random() > 0.7
                        else None
                    ),
                    "email_sent": False,
                    "seconds_to_triaged": random.randint(0, 3600),
                    "seconds_to_resolved": None,
                }
            )

        return records[:max_records]


# ══════════════════════════════════════════════════════════════════════════
# 2. Okta System Log — /api/v1/logs response schema
#    Real docs: https://developer.okta.com/docs/reference/api/system-log/
# ══════════════════════════════════════════════════════════════════════════


class OktaSimAdapter(BaseSourceAdapter):
    """
    Returns records structured exactly like Okta System Log API responses,
    including actor, client, authenticationContext, outcome, and request
    nested objects.

    Field reference:
      https://developer.okta.com/docs/reference/api/system-log/#logevent-object
    """

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 1000,
    ) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.025)

        raw = event.raw_data or {}
        trigger_user = (
            getattr(event, "user", None) or raw.get("user_id") or _rand_user()
        )
        trigger_ip = (
            getattr(event, "source_ip", None) or raw.get("source_ip") or _rand_ip(False)
        )
        # Pull geo cues from raw_data if present
        trigger_country = raw.get("client_geo_country", "US")
        trigger_city = raw.get("client_geo_city", "Austin")
        risk_score = raw.get("okta_risk_score", random.randint(5, 95))

        records: List[Dict[str, Any]] = []
        count = random.randint(4, min(15, max_records))

        for i in range(count):
            evt_type = random.choice(OKTA_EVENT_TYPES)
            # First record biases toward the triggering event type
            if i == 0 and raw.get("event_type"):
                evt_type = raw["event_type"]

            ts = _iso(since, offset_seconds=i * random.randint(60, 600))
            success = random.random() > 0.25
            log_id = str(uuid.uuid4())

            records.append(
                {
                    "source": "okta",
                    # Okta LogEvent top-level fields
                    "uuid": log_id,
                    "published": ts,
                    "eventType": evt_type,
                    "version": "0",
                    "severity": random.choice(["INFO", "WARN", "ERROR"]),
                    "legacyEventType": f"core.user_auth.login_{'success' if success else 'failed'}",
                    "displayMessage": f"User {trigger_user} performed {evt_type}",
                    "transaction": {
                        "type": "WEB",
                        "id": uuid.uuid4().hex,
                    },
                    # Actor — the user performing the action
                    "actor": {
                        "id": f"00u{uuid.uuid4().hex[:18]}",
                        "type": "User",
                        "alternateId": trigger_user if i < 3 else _rand_user(),
                        "displayName": trigger_user.split("@")[0]
                        .replace(".", " ")
                        .title(),
                        "detailEntry": None,
                    },
                    # Client — browser/app that made the request
                    "client": {
                        "userAgent": {
                            "rawUserAgent": random.choice(
                                [
                                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
                                    "okta-sdk-python/2.9.4 python/3.11.0",
                                    "curl/7.81.0",
                                ]
                            ),
                            "os": random.choice(["Windows", "Mac OS X", "Linux"]),
                            "browser": random.choice(
                                ["CHROME", "SAFARI", "FIREFOX", "OTHER"]
                            ),
                        },
                        "zone": "None",
                        "device": random.choice(["Computer", "Mobile", "Unknown"]),
                        "id": None,
                        "ipAddress": (
                            trigger_ip if i < 2 else _rand_ip(random.random() > 0.4)
                        ),
                        "geographicalContext": {
                            "city": (
                                trigger_city
                                if i < 2
                                else random.choice(
                                    [
                                        "Austin",
                                        "New York",
                                        "London",
                                        "Singapore",
                                        "Frankfurt",
                                    ]
                                )
                            ),
                            "state": "Texas" if trigger_city == "Austin" else None,
                            "country": (
                                trigger_country
                                if i < 2
                                else random.choice(["US", "GB", "SG", "DE", "IN"])
                            ),
                            "postalCode": "78701" if trigger_city == "Austin" else None,
                            "geolocation": {"lat": 30.27, "lon": -97.74},
                        },
                    },
                    # Authentication context
                    "authenticationContext": {
                        "authenticationProvider": "FACTOR_PROVIDER",
                        "credentialProvider": random.choice(
                            ["OKTA_CREDENTIAL_PROVIDER", None]
                        ),
                        "credentialType": random.choice(
                            ["OktaVerify", "PASSWORD", "TOTP"]
                        ),
                        "issuer": None,
                        "interface": None,
                        "authenticationStep": 0,
                        "externalSessionId": uuid.uuid4().hex,
                    },
                    # Outcome
                    "outcome": {
                        "result": (
                            "SUCCESS"
                            if success
                            else random.choice(["FAILURE", "CHALLENGE", "DENY"])
                        ),
                        "reason": (
                            None
                            if success
                            else random.choice(
                                [
                                    "INVALID_CREDENTIALS",
                                    "LOCKED_OUT",
                                    "MFA_REQUIRED",
                                    "USER_DISABLED",
                                ]
                            )
                        ),
                    },
                    # Security context / risk signals
                    "securityContext": {
                        "asNumber": random.randint(1000, 65535),
                        "asOrg": random.choice(
                            ["AS-CORP", "Comcast Cable", "Amazon AWS", "Digital Ocean"]
                        ),
                        "domain": trigger_ip.rsplit(".", 1)[0] + ".0",
                        "isProxy": random.random() > 0.85,
                        "isp": random.choice(["Comcast", "AT&T", "Amazon", "Google"]),
                    },
                    "request": {
                        "ipChain": [
                            {
                                "ip": trigger_ip,
                                "geographicalContext": {"country": trigger_country},
                                "version": "V4",
                                "source": None,
                            }
                        ]
                    },
                    # Risk signals (Okta Identity Threat Protection)
                    "risk_score": risk_score if i == 0 else random.randint(1, 40),
                    "riskLevel": (
                        "HIGH"
                        if risk_score > 70
                        else ("MEDIUM" if risk_score > 40 else "LOW")
                    ),
                    "isRisky": risk_score > 70 and i == 0,
                    # Targets (app or group being accessed)
                    "target": [
                        {
                            "id": f"0oa{uuid.uuid4().hex[:18]}",
                            "type": "AppInstance",
                            "alternateId": random.choice(
                                [
                                    "Salesforce CRM",
                                    "AWS Management Console",
                                    "GitHub Enterprise",
                                    "Jira Cloud",
                                    "Slack",
                                ]
                            ),
                            "displayName": random.choice(
                                [
                                    "Salesforce CRM",
                                    "AWS Console",
                                    "GitHub",
                                    "Jira",
                                    "Slack",
                                ]
                            ),
                            "detailEntry": None,
                        }
                    ],
                    "debugContext": {
                        "debugData": {
                            "dtHash": uuid.uuid4().hex,
                            "requestId": uuid.uuid4().hex,
                            "requestUri": f"/api/v1/authn",
                            "threatSuspected": str(risk_score > 70).lower(),
                            "url": f"/login/login.htm?fromURI=%2Fapp%2F",
                        }
                    },
                }
            )

        return records[:max_records]


# ══════════════════════════════════════════════════════════════════════════
# 3. Palo Alto Networks — PAN-OS Threat Log + Traffic Log schema
#    Real format: syslog (RFC 5424) fields per PAN-OS log documentation
#    https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/
# ══════════════════════════════════════════════════════════════════════════


class PaloAltoSimAdapter(BaseSourceAdapter):
    """
    Returns records structured exactly like PAN-OS threat and traffic logs
    as returned by the Panorama/firewall XML API query endpoint, after
    being parsed from XML into dict form.  Includes all standard
    PAN-OS CSV syslog fields in their XML-parsed key names.

    Covers both threat logs (log_type=THREAT) and traffic logs (TRAFFIC).
    """

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 500,
    ) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.03)

        raw = event.raw_data or {}
        trigger_src_ip = (
            getattr(event, "source_ip", None) or raw.get("source_ip") or _rand_ip(True)
        )
        trigger_dst_ip = raw.get("destination_ip") or _rand_ip(False)
        trigger_category = raw.get(
            "threat_category", random.choice(PAN_THREAT_CATEGORIES)
        )

        records: List[Dict[str, Any]] = []
        count = random.randint(4, min(14, max_records))

        for i in range(count):
            log_type = "THREAT" if random.random() > 0.3 else "TRAFFIC"
            ts = _iso(since, offset_seconds=i * random.randint(15, 180))
            app = random.choice(PAN_APPLICATIONS)
            category = (
                trigger_category if i < 2 else random.choice(PAN_THREAT_CATEGORIES)
            )
            action = random.choice(
                ["alert", "allow", "block", "reset-both", "sinkhole"]
            )
            src_ip = trigger_src_ip if i < 3 else _rand_ip(True)
            dst_ip = trigger_dst_ip if i < 2 else _rand_ip(random.random() > 0.3)
            threat_id = random.randint(10000, 99999)

            base_record = {
                "source": "palo_alto",
                # PAN-OS standard header fields
                "domain": "1",
                "receive_time": ts,
                "serial": f"0{random.randint(10000000000, 19999999999)}",
                "type": log_type,
                "threat_content_type": (
                    "vulnerability" if log_type == "THREAT" else "end"
                ),
                "config_version": "2305",
                "generate_time": ts,
                "src": src_ip,
                "dst": dst_ip,
                "natsrc": _rand_ip(False),
                "natdst": dst_ip,
                "rule": random.choice(
                    [
                        "C2-Detection-Outbound",
                        "IPS-Internal-Scan-Block",
                        "DLP-Outbound-FileSharing",
                        "Allow-Vuln-Scanning",
                        "Deny-Untrusted-Inbound",
                        "Allow-Egress-HTTPS",
                    ]
                ),
                "srcuser": raw.get("user_id") or _rand_user(),
                "dstuser": None,
                "app": app,
                "vsys": "vsys1",
                "from": "trust",
                "to": (
                    "untrust"
                    if dst_ip.startswith(("185.", "91.", "45.", "103.", "198."))
                    else "trust"
                ),
                "inbound_if": "ethernet1/1",
                "outbound_if": "ethernet1/2",
                "logset": "default",
                "sessionid": random.randint(1000000, 9999999),
                "repeatcnt": random.randint(1, 5),
                "sport": random.randint(1024, 65535),
                "dport": random.choice([80, 443, 445, 53, 3389, 22, 8080, 8443]),
                "natsport": random.randint(1024, 65535),
                "natdport": random.choice([80, 443, 445, 53]),
                "flags": f"0x{random.randint(0, 65535):04x}",
                "proto": random.choice(["tcp", "udp"]),
                "action": action,
                "bytes": random.randint(500, 5_000_000),
                "bytes_sent": random.randint(100, 2_000_000),
                "bytes_received": random.randint(100, 3_000_000),
                "packets": random.randint(5, 10000),
                "start": ts,
                "elapsed": random.randint(1, 3600),
                "category": (
                    category
                    if log_type == "THREAT"
                    else random.choice(
                        ["business-and-economy", "computer-and-internet-info"]
                    )
                ),
                "subcategory": "attack" if log_type == "THREAT" else "technology",
                "severity": random.choice(
                    ["informational", "low", "medium", "high", "critical"]
                ),
                "direction": random.choice(["client-to-server", "server-to-client"]),
                "pcap_id": "0",
                "filedigest": "",
                "cloud": "",
                "url_idx": "4",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "filetype": "",
                "xff": "",
                "referer": "",
                "sender": "",
                "subject": "",
                "recipient": "",
                "reportid": str(random.randint(100000, 999999)),
                "vsys_name": "vsys1",
                "device_name": random.choice(
                    ["PA-5250-PROD", "PA-3220-DMZ", "Panorama"]
                ),
                "tunnel_id_imsi": "0",
                "monitor_tag_imei": "",
                "parent_session_id": "0",
                "parent_start_time": ts,
                "tunnel_type": "N/A",
                "threat_category": category,
                "content_ver": "8812-8618",
                "assoc_id": "0",
                "ppid": "0",
                "http_method": random.choice(["GET", "POST", ""]),
                "tunnel_fragment": "No",
                "chunks": "0",
                "chunks_sent": "0",
                "chunks_received": "0",
                "rule_uuid": str(uuid.uuid4()),
                "http2_connection": "0",
                "dynusergroup_name": "",
                "xff_ip": _rand_ip(False),
                "src_category": "",
                "src_profile": "",
                "src_model": "",
                "src_vendor": "",
                "src_osfamily": "Windows",
                "src_osversion": "10",
                "src_host": random.choice(
                    ["LAPTOP-JSMITH", "WKS-DBROWN", "BACKUP-SRV"]
                ),
                "src_mac": ":".join([f"{random.randint(0,255):02x}" for _ in range(6)]),
            }

            # Threat-log-only fields
            if log_type == "THREAT":
                base_record.update(
                    {
                        "threatid": str(threat_id),
                        "threat_name": random.choice(
                            [
                                "Command-and-Control Beacon Detected",
                                "Internal SMB Port Scan",
                                "DNS Tunneling Data Exfiltration",
                                "Possible Data Exfiltration via File Upload",
                                f"Vulnerability {threat_id} Exploit Attempt",
                            ]
                        ),
                        "misc": raw.get(
                            "suspicious_domain",
                            f"suspicious-{random.randint(1000,9999)}.example.com",
                        ),
                        "thr_category": category,
                        "contenttype": "any",
                        "pcap_id": str(random.randint(0, 1)),
                        "filedigest": uuid.uuid4().hex if random.random() > 0.7 else "",
                        "cortex_xdr_incident_id": (
                            f"XDR-{random.randint(40000, 50000)}"
                            if random.random() > 0.5
                            else None
                        ),
                        "wildfire_report_id": (
                            str(random.randint(100000, 999999))
                            if random.random() > 0.7
                            else None
                        ),
                    }
                )

            records.append(base_record)

        return records[:max_records]


# ══════════════════════════════════════════════════════════════════════════
# 4. Palo Alto Cortex XDR — Alert schema
#    For events sourced from cortex_xdr (used in S3, S4, S5 scenarios)
# ══════════════════════════════════════════════════════════════════════════


class CortexXDRSimAdapter(BaseSourceAdapter):
    """
    Returns records in Cortex XDR alert format as returned by the
    /public_api/v1/alerts/get_alerts_multi_events endpoint.

    Field reference:
      https://cortex.pan.dev/docs/investigate/alerts/
    """

    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 200,
    ) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.035)

        raw = event.raw_data or {}
        trigger_src = getattr(event, "source_ip", None) or _rand_ip(True)

        records: List[Dict[str, Any]] = []
        count = random.randint(2, min(8, max_records))

        for i in range(count):
            ts_epoch = int((since + timedelta(seconds=i * 200)).timestamp() * 1000)
            alert_id = random.randint(10000000, 99999999)
            technique_id, technique_name, tactic = random.choice(MITRE_POOL)

            records.append(
                {
                    "source": "cortex_xdr",
                    "external_id": str(uuid.uuid4()),
                    "severity": random.choice(["low", "medium", "high", "critical"]),
                    "matching_status": "MATCHED",
                    "end_match_attempt_ts": ts_epoch,
                    "local_insert_ts": ts_epoch,
                    "bioc_indicator": None,
                    "matching_service_rule_id": None,
                    "attempt_counter": random.randint(1, 5),
                    "bioc_category_enum_key": None,
                    "is_whitelisted": False,
                    "starred": False,
                    "deduplicate_tokens": str(random.randint(100000, 999999)),
                    "filter_rule_id": None,
                    "mitre_technique_id_and_name": f"{technique_id} - {technique_name}",
                    "mitre_tactic_id_and_name": f"TA{random.randint(1000,1599)} - {tactic}",
                    "agent_version": "7.15.17706.0",
                    "agent_device_domain": "CORP",
                    "agent_fqdn": f"LAPTOP-{uuid.uuid4().hex[:6].upper()}.corp.example",
                    "agent_os_type": "AGENT_OS_WINDOWS",
                    "agent_os_sub_type": "Windows 11 22H2",
                    "agent_data_collection_status": True,
                    "mac": ":".join([f"{random.randint(0,255):02x}" for _ in range(6)]),
                    "win_ver": "Windows 11 22H2",
                    "category": random.choice(
                        [
                            "Malware",
                            "Credential Access",
                            "Lateral Movement",
                            "Exfiltration",
                        ]
                    ),
                    "name": f"XDR Alert {alert_id}",
                    "endpoint_id": uuid.uuid4().hex[:32],
                    "description": f"{technique_name} detected on endpoint. MITRE ATT&CK: {technique_id}.",
                    "host_ip": [trigger_src if i < 2 else _rand_ip(True)],
                    "host_name": raw.get("host") or _rand_host(),
                    "source": "XDR BIOC",
                    "action": random.choice(["BLOCKED", "DETECTED", "QUARANTINE"]),
                    "action_pretty": random.choice(
                        ["Blocked", "Detected", "Quarantined"]
                    ),
                    "alert_id": str(alert_id),
                    "detection_timestamp": ts_epoch,
                    "user_name": raw.get("user_id") or _rand_user(),
                    "actor_process_image_name": random.choice(
                        ["powershell.exe", "cmd.exe", "lsass.exe", "svchost.exe"]
                    ),
                    "actor_process_command_line": f"powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\{uuid.uuid4().hex[:8]}.ps1",
                    "actor_process_image_sha256": uuid.uuid4().hex + uuid.uuid4().hex,
                    "actor_process_signature_status": "N/A",
                    "actor_process_signature_vendor": None,
                    "causality_actor_process_image_name": "WINWORD.EXE",
                    "causality_actor_process_command_line": "WINWORD.EXE /n /dde",
                    "causality_actor_causality_id": uuid.uuid4().hex[:16],
                    "os_actor_process_image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "os_actor_process_command_line": f"powershell.exe -EncodedCommand {uuid.uuid4().hex}",
                    "os_actor_thread_thread_id": random.randint(1000, 9999),
                    "fw_app_id": random.choice(PAN_APPLICATIONS),
                    "fw_interface_from": "ae1.200",
                    "fw_interface_to": "ae1.100",
                    "fw_rule": random.choice(
                        ["C2-Detection-Outbound", "IPS-Internal-Scan-Block"]
                    ),
                    "fw_rule_id": str(uuid.uuid4()),
                    "fw_device_name": "PA-5250-PROD",
                    "fw_serial": f"0{random.randint(10000000000, 19999999999)}",
                    "fw_url_domain": raw.get(
                        "suspicious_domain", f"cdn-{uuid.uuid4().hex[:6]}.example.com"
                    ),
                    "fw_email_subject": None,
                    "fw_email_sender": None,
                    "fw_email_recipient": None,
                    "fw_app_subcategory": "networking",
                    "fw_app_category": "networking",
                    "fw_app_technology": "browser-based",
                    "fw_vsys": "vsys1",
                    "fw_xff": _rand_ip(False),
                    "fw_misc": None,
                    "fw_is_phishing": False,
                    "dst_action_country": raw.get(
                        "destination_country",
                        random.choice(["US", "RU", "CN", "NL", "DE"]),
                    ),
                    "dst_action_external_hostname": raw.get(
                        "destination_fqdn", f"cdn.{uuid.uuid4().hex[:6]}.example.com"
                    ),
                    "dst_action_country_code": "US",
                    "contains_featured_host": random.choice(["NO", "YES"]),
                    "contains_featured_user": random.choice(["NO", "YES"]),
                    "contains_featured_ip": "NO",
                    "referenced_resource": None,
                    "operation_name": None,
                    "identity_sub_type": None,
                    "identity_type": None,
                    "project": None,
                    "cloud_provider": None,
                    "resource_type": None,
                    "resource_sub_type": None,
                    "user_agent": "python-requests/2.31.0",
                    "alert_type": "BIOC",
                }
            )

        return records[:max_records]


# ══════════════════════════════════════════════════════════════════════════
# 5. AWS CloudTrail — event history / CloudTrail Lake schema
# ══════════════════════════════════════════════════════════════════════════


class AWSCloudTrailSimAdapter(BaseSourceAdapter):
    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 500,
    ) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.03)

        raw = event.raw_data or {}
        trigger_user = getattr(event, "user", None) or raw.get("user_id") or _rand_user()
        trigger_ip = getattr(event, "source_ip", None) or raw.get("source_ip") or _rand_ip(False)
        trigger_event = raw.get("eventName") or random.choice(AWS_EVENT_NAMES)

        records: List[Dict[str, Any]] = []
        count = random.randint(3, min(10, max_records))

        for i in range(count):
            ts = _iso(since, offset_seconds=i * random.randint(45, 420))
            event_name = trigger_event if i == 0 else random.choice(AWS_EVENT_NAMES)
            region = random.choice(["us-east-1", "us-west-2", "eu-west-1"])
            principal = trigger_user.replace("@corp.example", "") if "@" in trigger_user else trigger_user

            records.append(
                {
                    "source": "aws_cloudtrail",
                    "eventVersion": "1.10",
                    "eventTime": ts,
                    "eventSource": random.choice(
                        [
                            "signin.amazonaws.com",
                            "iam.amazonaws.com",
                            "s3.amazonaws.com",
                            "ec2.amazonaws.com",
                            "sts.amazonaws.com",
                        ]
                    ),
                    "eventName": event_name,
                    "awsRegion": region,
                    "sourceIPAddress": trigger_ip if i < 2 else _rand_ip(False),
                    "userAgent": random.choice(
                        [
                            "console.amazonaws.com",
                            "aws-cli/2.15.0 Python/3.11",
                            "Boto3/1.34.0",
                            "signin.amazonaws.com",
                        ]
                    ),
                    "userIdentity": {
                        "type": random.choice(["IAMUser", "AssumedRole", "Root"]),
                        "principalId": f"AIDA{uuid.uuid4().hex[:16].upper()}",
                        "arn": f"arn:aws:iam::123456789012:user/{principal}",
                        "accountId": "123456789012",
                        "accessKeyId": f"AKIA{uuid.uuid4().hex[:16].upper()}",
                        "userName": principal,
                        "sessionContext": {
                            "attributes": {
                                "creationDate": ts,
                                "mfaAuthenticated": random.choice(["true", "false"]),
                            }
                        },
                    },
                    "requestParameters": {
                        "bucketName": random.choice(["corp-finance-data", "prod-backups", "terraform-state"]),
                        "roleName": random.choice(["SecurityAudit", "AdminAccess", "ReadOnlyRole"]),
                        "groupName": random.choice(["Admins", "Developers", "SOC"]),
                    },
                    "responseElements": None,
                    "resources": [
                        {
                            "ARN": f"arn:aws:s3:::corp-{random.choice(['finance', 'hr', 'logs'])}",
                            "accountId": "123456789012",
                            "type": random.choice(["AWS::S3::Bucket", "AWS::IAM::Role", "AWS::EC2::Instance"]),
                        }
                    ],
                    "eventID": str(uuid.uuid4()),
                    "readOnly": event_name in {"GetObject"},
                    "eventType": "AwsApiCall",
                    "managementEvent": True,
                    "recipientAccountId": "123456789012",
                    "vpcEndpointId": None,
                    "tlsDetails": {
                        "tlsVersion": "TLSv1.2",
                        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                        "clientProvidedHostHeader": "console.aws.amazon.com",
                    },
                }
            )

        return records[:max_records]


# ══════════════════════════════════════════════════════════════════════════
# 6. Microsoft Entra ID / Azure AD — sign-in + audit log schema
# ══════════════════════════════════════════════════════════════════════════


class AzureADSimAdapter(BaseSourceAdapter):
    async def query(
        self,
        event: SecurityEvent,
        since: datetime,
        until: datetime,
        max_records: int = 500,
    ) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.03)

        raw = event.raw_data or {}
        trigger_user = getattr(event, "user", None) or raw.get("user_id") or _rand_user()
        trigger_ip = getattr(event, "source_ip", None) or raw.get("source_ip") or _rand_ip(False)
        trigger_operation = raw.get("operationName") or random.choice(AZURE_AD_OPERATIONS)

        records: List[Dict[str, Any]] = []
        count = random.randint(4, min(12, max_records))

        for i in range(count):
            ts = _iso(since, offset_seconds=i * random.randint(60, 360))
            operation = trigger_operation if i == 0 else random.choice(AZURE_AD_OPERATIONS)
            user_name = trigger_user if i < 3 else _rand_user()

            records.append(
                {
                    "source": "azure_ad",
                    "id": str(uuid.uuid4()),
                    "category": random.choice(["SignInLogs", "AuditLogs"]),
                    "operationName": operation,
                    "activityDateTime": ts,
                    "result": random.choice(["success", "failure"]),
                    "resultReason": random.choice(
                        [
                            "MFA requirement satisfied",
                            "User successfully authenticated",
                            "Invalid username or password",
                            "Conditional Access policy enforced",
                        ]
                    ),
                    "loggedByService": "Core Directory",
                    "initiatedBy": {
                        "user": {
                            "id": str(uuid.uuid4()),
                            "userPrincipalName": user_name,
                            "displayName": user_name.split("@")[0].replace(".", " ").title(),
                            "ipAddress": trigger_ip if i < 2 else _rand_ip(False),
                        }
                    },
                    "targetResources": [
                        {
                            "id": str(uuid.uuid4()),
                            "displayName": random.choice(
                                [
                                    "Global Administrator",
                                    "Azure Portal",
                                    "Microsoft Graph",
                                    "Payroll App",
                                ]
                            ),
                            "type": random.choice(["User", "Application", "DirectoryRole"]),
                            "userPrincipalName": user_name,
                        }
                    ],
                    "additionalDetails": [
                        {"key": "ClientAppUsed", "value": random.choice(["Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync"])},
                        {"key": "RiskLevelAggregated", "value": random.choice(["low", "medium", "high"])},
                    ],
                    "correlationId": str(uuid.uuid4()),
                    "tenantId": str(uuid.uuid4()),
                    "appDisplayName": random.choice(
                        ["Microsoft Azure Portal", "Office 365 Exchange Online", "Microsoft Graph", "Slack Enterprise App"]
                    ),
                    "clientAppUsed": random.choice(
                        ["Browser", "Mobile Apps and Desktop clients", "Other clients"]
                    ),
                    "conditionalAccessStatus": random.choice(["success", "failure", "notApplied"]),
                    "deviceDetail": {
                        "displayName": raw.get("host") or _rand_host(),
                        "operatingSystem": random.choice(["Windows 11", "macOS", "iOS", "Android"]),
                        "browser": random.choice(["Chrome", "Edge", "Safari", "Firefox"]),
                        "isCompliant": random.choice([True, False]),
                        "isManaged": random.choice([True, False]),
                    },
                    "location": {
                        "city": random.choice(["Austin", "New York", "London", "Singapore"]),
                        "state": random.choice(["Texas", "New York", None]),
                        "countryOrRegion": random.choice(["US", "GB", "SG", "DE"]),
                    },
                    "status": {
                        "errorCode": 0,
                        "failureReason": None,
                        "additionalDetails": "none",
                    },
                }
            )

        return records[:max_records]


# ══════════════════════════════════════════════════════════════════════════
# Registration
# ══════════════════════════════════════════════════════════════════════════


def register_simulated_adapters() -> None:
    """
    Replace generic Simulated*Adapters with product-faithful ones for
    CrowdStrike, Okta, and Palo Alto.  Call this when live credentials
    are not available (dev, CI, offline testing).

    Does NOT override any real adapters that register_all_adapters()
    may have already installed.  Safe to call after register_all_adapters().
    """
    from acda.runtime.data_collector import _ADAPTER_MAP  # re-import for clarity

    sim_map = {
        "aws_cloudtrail": AWSCloudTrailSimAdapter(),
        "azure_ad": AzureADSimAdapter(),
        "crowdstrike": CrowdStrikeSimAdapter(),
        "okta": OktaSimAdapter(),
        "identity_logs": OktaSimAdapter(),  # identity_logs → Okta format
        "palo_alto": PaloAltoSimAdapter(),
        "network_logs": PaloAltoSimAdapter(),  # network_logs → PAN format
        "cortex_xdr": CortexXDRSimAdapter(),
        "endpoint_logs": CrowdStrikeSimAdapter(),  # endpoint_logs → CS format
    }

    registered = []
    for key, adapter in sim_map.items():
        # Only replace if not already overridden by a live-credential adapter
        existing = _ADAPTER_MAP.get(key)
        from acda.runtime.data_collector import (
            SimulatedEndpointLogsAdapter,
            SimulatedNetworkLogsAdapter,
            SimulatedIdentityLogsAdapter,
        )

        if existing is None or type(existing) in (
            SimulatedEndpointLogsAdapter,
            SimulatedNetworkLogsAdapter,
            SimulatedIdentityLogsAdapter,
        ):
            _ADAPTER_MAP[key] = adapter
            registered.append(key)

    import structlog

    structlog.get_logger(__name__).info(
        "cyphora_sim_adapters_registered",
        adapters=registered,
    )
