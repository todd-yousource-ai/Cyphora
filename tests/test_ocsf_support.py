"""
Sanity test for the new OCSF support added to Cyphora-S1.
Run: python3 test_ocsf_support.py
"""
import json
import sys

from acda.models.schemas import SecurityEvent
from cyphora_s1.ocsf_parser import OCSFParser
from cyphora_s1.ocsf_adapters import OCSFSecurityEventFactory, register_ocsf_adapters
from cyphora_s1.cef_parser import CEFParser
from cyphora_s1.format_normalizer import (
    UniversalNormalizer, FieldMappingProfile, FormatDetector, SourceFormat,
    CEFToOCSFConverter, ingest_to_security_event_dicts,
)

PASS = 0
FAIL = 0


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  OK   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label}  {detail}")


print("=" * 70)
print("1) Native OCSF events -> SecurityEvent")
print("=" * 70)

native_ocsf_events = [
    # Authentication: failed/successful logon from a new geography
    {
        "class_uid": 3002, "category_uid": 3, "activity_id": 1,
        "severity_id": 4, "time": 1718000000000,
        "message": "Successful interactive logon from unrecognized geography",
        "metadata": {"product": {"vendor_name": "Okta", "name": "Workforce Identity"}, "uid": "okta-evt-001"},
        "actor": {"user": {"name": "jsmith@corp.example"}},
        "src_endpoint": {"ip": "91.108.56.181"},
        "device": {"hostname": "LAPTOP-JSMITH"},
    },
    # Detection Finding with MITRE ATT&CK context (ransomware)
    {
        "class_uid": 2004, "category_uid": 2, "activity_id": 1,
        "severity_id": 5, "time": 1718000500000,
        "message": "BlackCat ransomware — mass file encryption detected",
        "metadata": {"product": {"vendor_name": "CrowdStrike", "name": "Falcon"}, "uid": "cs-detect-9001"},
        "device": {"hostname": "FILESRV-02", "ip": "10.10.5.40"},
        "attacks": [{"tactic": {"name": "Impact"}, "technique": {"uid": "T1486", "name": "Data Encrypted for Impact"}}],
    },
    # Network Activity: DNS tunnelling signal
    {
        "class_uid": 4003, "category_uid": 4, "activity_id": 99,
        "severity_id": 3, "time": 1718001000000,
        "message": "High-entropy DNS queries to uncategorized domain — possible tunnelling",
        "metadata": {"product": {"vendor_name": "Palo Alto Networks", "name": "Cortex XDR"}},
        "src_endpoint": {"ip": "10.20.0.55"},
        "device": {"hostname": "WKSTN-117"},
    },
]

parser = OCSFParser()
sef_dicts = [parser.to_security_event_dict(r) for r in [parser.parse_dict(e) for e in native_ocsf_events]]
for d in sef_dicts:
    print(f"  -> event_type={d['event_type']:<28} severity={d['severity']:<8} user={d['user']} host={d['source_host']}")

check("Authentication -> suspicious_login", sef_dicts[0]["event_type"] == "suspicious_login")
check("Detection Finding w/ T1486 -> abnormal_file_encryption", sef_dicts[1]["event_type"] == "abnormal_file_encryption")
check("DNS Activity (99) -> data_exfiltration", sef_dicts[2]["event_type"] == "data_exfiltration")
check("Severity mapping high (4)", sef_dicts[0]["severity"] == "high")
check("Severity mapping critical (5)", sef_dicts[1]["severity"] == "critical")

# Build real SecurityEvent objects (validates against the Pydantic schema)
events = OCSFSecurityEventFactory.from_dicts(native_ocsf_events)
check("All native OCSF events -> valid SecurityEvent objects", all(isinstance(e, SecurityEvent) for e in events), str(events))
check("3 events produced", len(events) == 3, str(len(events)))

print()
print("=" * 70)
print("2) NDJSON (newline-delimited OCSF) parsing")
print("=" * 70)
ndjson_text = "\n".join(json.dumps(e) for e in native_ocsf_events)
records = parser.parse_text(ndjson_text)
check("NDJSON parses to 3 records", len(records) == 3, str(len(records)))

print()
print("=" * 70)
print("3) Existing CEF sample file -> CEF->OCSF converter -> OCSF->SecurityEvent")
print("=" * 70)

cef_path = "data/sample_security_logs.cef"
cef_parser = CEFParser()
cef_records = cef_parser.parse_file(cef_path)
check(f"CEF sample file parses ({len(cef_records)} records)", len(cef_records) > 0, str(len(cef_records)))

converter = CEFToOCSFConverter()
ocsf_from_cef = [converter.convert(r) for r in cef_records]
check("All CEF records converted to OCSF-shaped dicts", all("class_uid" in d for d in ocsf_from_cef))

# Round-trip: direct CEF->SEF vs CEF->OCSF->SEF — compare event_type/severity agreement
direct_sef = [cef_parser.to_security_event_dict(r) for r in cef_records]
ocsf_recs = [parser.parse_dict(d) for d in ocsf_from_cef]
roundtrip_sef = [parser.to_security_event_dict(r) for r in ocsf_recs]

agree_severity = sum(1 for a, b in zip(direct_sef, roundtrip_sef) if a["severity"] == b["severity"])
print(f"  severity agreement direct-CEF vs CEF->OCSF->SEF: {agree_severity}/{len(direct_sef)}")
check("Severity preserved through CEF->OCSF->SEF for all records", agree_severity == len(direct_sef))

for a, b in list(zip(direct_sef, roundtrip_sef))[:5]:
    print(f"    direct={a['event_type']:<28} via-ocsf={b['event_type']:<28} sev(direct={a['severity']}, via-ocsf={b['severity']})")

print()
print("=" * 70)
print("4) Proprietary JSON (unknown vendor) -> FieldMappingProfile -> OCSF -> SEF")
print("=" * 70)

acme_raw_event = {
    "ts": "2026-06-20T14:32:00Z",
    "sev": "high",
    "summary": "Suspicious PowerShell execution with encoded command",
    "actor_user": "mwilson@company.com",
    "src_ip": "10.50.22.89",
    "host": "LAPTOP-HR-05",
    "proc_name": "powershell.exe",
    "cmdline": "powershell.exe -encodedCommand JABzAD0A...",
    "vendor": "acme_edr",
}

def acme_severity_resolver(raw):
    return {"low": 2, "medium": 3, "high": 4, "critical": 5}.get(raw.get("sev"), 3)

profile = FieldMappingProfile(
    vendor_name="acme_edr",
    category_uid=1,    # System Activity
    class_uid=1007,    # Process Activity
    activity_id=1,     # Launch
    severity_resolver=acme_severity_resolver,
    field_map={
        "message": ["summary"],
        "user.name": ["actor_user"],
        "src_endpoint.ip": ["src_ip"],
        "device.hostname": ["host"],
        "process.name": ["proc_name"],
        "process.cmd_line": ["cmdline"],
    },
)

normalizer = UniversalNormalizer()
normalizer.register_profile(profile)

fmt = FormatDetector.detect(acme_raw_event)
check("FormatDetector identifies proprietary dict as JSON", fmt == SourceFormat.JSON, fmt)

sef_from_acme = ingest_to_security_event_dicts(acme_raw_event, normalizer=normalizer, profile_key="acme_edr")
check("Proprietary JSON produced exactly 1 SecurityEvent dict", len(sef_from_acme) == 1, str(len(sef_from_acme)))
if sef_from_acme:
    d = sef_from_acme[0]
    print(f"  -> event_type={d['event_type']} severity={d['severity']} user={d['user']} host={d['source_host']} process={d['process']}")
    check("Acme event_type resolved to abnormal_process_execution", d["event_type"] == "abnormal_process_execution", d["event_type"])
    check("Acme severity resolved to high", d["severity"] == "high", d["severity"])
    check("Acme user field correctly mapped", d["user"] == "mwilson@company.com")
    check("Acme process cmd_line correctly mapped", d["process"] == "powershell.exe -encodedCommand JABzAD0A...")
    SecurityEvent(**{k: v for k, v in d.items() if k in {
        "event_id","event_type","severity","timestamp","source_ip","source_host","user","process","raw_data"}})
    check("Acme event validates as a SecurityEvent", True)

print()
print("=" * 70)
print("5) register_ocsf_adapters() — DataCollector integration")
print("=" * 70)
stats = register_ocsf_adapters(ocsf_dicts=native_ocsf_events)
print(f"  adapter registration stats: {stats}")
check("IAM + Findings + Network categories registered", set(stats.keys()) == {"ocsf_iam", "ocsf_findings", "ocsf_network_activity"}, str(stats))

print()
print("=" * 70)
print("6) FormatDetector regression: real CEF file header (comments/banners)")
print("=" * 70)
with open(cef_path) as f:
    real_cef_text = f.read()
fmt_real_cef = FormatDetector.detect(real_cef_text)
check("Real CEF sample (comment+banner header) detected as CEF", fmt_real_cef == SourceFormat.CEF, fmt_real_cef)

tricky_json = json.dumps({"note": "see ref CEF:0|Vendor|Prod|1|x|y|1| in the appendix", "vendor": "x"})
fmt_tricky = FormatDetector.detect(tricky_json)
check("JSON merely mentioning 'CEF:0|' in a value is NOT misdetected as CEF", fmt_tricky == SourceFormat.JSON, fmt_tricky)

syslog_cef = "Jun 20 10:15:00 fw01 CEF:0|PaloAltoNetworks|PAN-OS|10.1|alert|Threat|7|src=1.2.3.4"
fmt_syslog = FormatDetector.detect(syslog_cef)
check("Syslog-prefixed real CEF line still detected as CEF", fmt_syslog == SourceFormat.CEF, fmt_syslog)

print()
print("=" * 70)
print("7) Category 6/7 (Application Activity / Remediation) adapter coverage")
print("=" * 70)
from cyphora_s1.ocsf_adapters import _CATEGORY_REGISTRATION
from cyphora_s1.ocsf_parser import OCSFCategory as _Cat
for cat in (_Cat.SYSTEM_ACTIVITY, _Cat.FINDINGS, _Cat.IAM, _Cat.NETWORK_ACTIVITY,
            _Cat.DISCOVERY, _Cat.APPLICATION_ACTIVITY, _Cat.REMEDIATION):
    check(f"Category {cat} ({_Cat.name(cat)}) has a registered adapter", cat in _CATEGORY_REGISTRATION)

app_event = {"class_uid": 6003, "category_uid": 6, "activity_id": 1, "severity_id": 3,
             "message": "Bulk API export of customer records", "time": 1718000000000}
stats2 = register_ocsf_adapters(ocsf_dicts=[app_event])
check("Application Activity (cat 6) registers into cloud_logs, not ocsf_mixed",
      "ocsf_application_activity" in stats2, str(stats2))

print()
print("=" * 70)
print("8) Defensive hardening: malformed/non-conformant vendor input")
print("=" * 70)
malformed = {
    "class_uid": 1007, "category_uid": 1, "activity_id": 1,
    "severity_id": 4, "time": 1718000000000,
    "message": "malformed vendor payload test",
    "device": "not-a-dict-string",
    "actor": None,
    "attacks": {"technique": {"uid": "T1059"}},  # should be a list, isn't
    "process": "cmd.exe",  # also malformed (string, not dict)
}
try:
    rec = parser.parse_dict(malformed)
    d = parser.to_security_event_dict(rec)
    check("Malformed input (non-dict device/process/attacks) does not raise", True)
    check("Malformed 'attacks' (dict instead of list) resolved to empty list", rec.attacks == [], str(rec.attacks))
    check("Malformed event still produces a usable event_type", d["event_type"] == "abnormal_process_execution", d["event_type"])
except Exception as exc:
    check("Malformed input (non-dict device/process/attacks) does not raise", False, str(exc))

print()
print("=" * 70)
print("9) Critical regression: UniversalNormalizer.normalize() + native OCSF NDJSON")
print("=" * 70)
ndjson_multi = "\n".join(json.dumps(e) for e in native_ocsf_events)
try:
    norm_result = normalizer.normalize(ndjson_multi)
    check("normalize() handles native OCSF NDJSON without raising", True)
    check("normalize() returns all 3 NDJSON records (not just 1, not a crash)",
          len(norm_result) == 3, str(len(norm_result)))
except Exception as exc:
    check("normalize() handles native OCSF NDJSON without raising", False, str(exc))

# The full one-call pipeline must also survive NDJSON end-to-end
pipeline_result = ingest_to_security_event_dicts(ndjson_multi)
check("ingest_to_security_event_dicts() end-to-end with OCSF NDJSON", len(pipeline_result) == 3, str(len(pipeline_result)))

# JSON array form must also still work (regression guard for the fix)
array_result = normalizer.normalize(json.dumps(native_ocsf_events))
check("normalize() still handles OCSF JSON array form", len(array_result) == 3, str(len(array_result)))

print()
print("=" * 70)
print("10) Critical: raw_data field-collision (OCSF 'severity' caption vs. computed)")
print("=" * 70)
collision_event = {
    "class_uid": 2004, "category_uid": 2, "activity_id": 1,
    "severity_id": 5, "severity": "Critical",  # real-world OCSF shape: both fields present
    "time": 1718000000000, "message": "ransomware detected",
}
rec_c = parser.parse_dict(collision_event)
d_c = parser.to_security_event_dict(rec_c)
check("Top-level severity correctly normalized despite raw 'severity' caption field",
      d_c["severity"] == "critical", d_c["severity"])
check("raw_data['severity'] also normalized, not overridden by source's own caption",
      d_c["raw_data"]["severity"] == "critical", d_c["raw_data"]["severity"])

malicious_event = dict(collision_event, unmapped={"severity": "totally-fake-override"})
rec_m = parser.parse_dict(malicious_event)
d_m = parser.to_security_event_dict(rec_m)
check("Defense-in-depth: explicit unmapped.severity cannot override computed value",
      d_m["raw_data"]["severity"] == "critical", d_m["raw_data"]["severity"])

print()
print("=" * 70)
print(f"RESULT: {PASS} passed, {FAIL} failed")
print("=" * 70)
sys.exit(1 if FAIL else 0)
