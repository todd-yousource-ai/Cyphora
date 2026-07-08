# OCSF Support for Cyphora-S1
### Design Document & Implementation Summary — v2.7.0

---

## 1. Why OCSF, and why now

The CEF_and_OCSF_and_JSON reference material already in the project makes the
industry direction clear: CEF is a legacy, pipe-delimited format built for
on-prem network appliances, and it breaks down for cloud-native telemetry —
there's nowhere to put an OAuth token, a container ID, or a Kubernetes
namespace except a generic `cs1`/`cs2` field, which makes correlation across
sources painful. OCSF (Open Cybersecurity Schema Framework), backed by AWS,
Splunk, and IBM, has emerged as the leading vendor-neutral replacement: a
single, strongly-typed JSON taxonomy where an Okta login, an Entra ID login,
and an AWS IAM login all use the same field names (`user.name`, `activity_id`,
`auth_protocol`) instead of three different vocabularies.

The newly-added reference links (`schema.ocsf.io`, the AWS OCSF ETL blog, and
the `ocsf-vrl` GitHub project) confirm the practical pattern the rest of the
industry has converged on: an ETL/normalization layer sits in front of the
SIEM and translates *everything* — CEF, raw JSON, proprietary vendor formats
— into OCSF before it's stored or queried. Commercial tools like Cribl Stream,
Datadog Observability Pipelines, and Splunk Cloud Ingest Processors all do
exactly this: ingest in any format, normalize to OCSF, route downstream.

**Design goal:** give Cyphora-S1 the same capability, using the same
architectural pattern already proven by `cef_parser.py` / `cef_adapters.py`,
so the codebase gains a second, more general ingestion path without
throwing away the first.

## 2. OCSF primer (what the parser needed to model)

| Concept | Meaning | Used in Cyphora as |
|---|---|---|
| `category_uid` | Top-level grouping (1 System Activity, 2 Findings, 3 IAM, 4 Network Activity, 5 Discovery, 6 Application Activity, 7 Remediation) | `OCSFCategory` constants → DataCollector source key |
| `class_uid` | The specific event schema within a category (e.g. 3002 = Authentication, 2004 = Detection Finding) | event_type resolution table |
| `activity_id` | The specific action within a class (e.g. Authentication: 1=Logon, 2=Logoff) | event_type resolution table (class_uid:activity_id key) |
| `type_uid` | `class_uid * 100 + activity_id` — a fully-qualified activity identifier | derived/validated on parse |
| `severity_id` | 0=Unknown … 5=Critical, 6=Fatal, 99=Other | mapped to Cyphora's low/medium/high/critical strings |
| `attacks[]` | MITRE ATT&CK tactic/technique attached directly to a Finding | highest-priority signal for event_type resolution (same precedence CEF gives its `Technique`/`Tactic` fields) |
| `unmapped` | OCSF's own escape hatch for vendor-specific fields the schema doesn't define | used by every converter in this project to guarantee zero data loss |

## 3. Architecture

```
                  ┌─────────────┐
                  │  CEF text   │──────┐
                  └─────────────┘      │
                                        ▼
                              ┌───────────────────┐         ┌──────────────────┐
                  ┌─────────▶ │  CEFToOCSFConverter│ ──────▶│                  │
                  │           └───────────────────┘         │                  │
┌─────────────┐   │                                          │   OCSF (common   │      ┌──────────────┐
│ Proprietary │───┤           ┌───────────────────┐         │   intermediate   │ ───▶ │ SecurityEvent│
│   JSON      │   └─────────▶ │GenericJSONToOCSF   │ ──────▶│   representation) │      │    (SEF)     │
└─────────────┘     (via      │  Converter +        │         │                  │      └──────────────┘
                   FieldMapping│  FieldMappingProfile)        │                  │        ocsf_parser.py
                    Profile)   └───────────────────┘         │                  │      OCSFParser.to_
┌─────────────┐                                              │                  │      security_event_dict()
│ Native OCSF │─────────────────────────────────────────────▶│                  │
└─────────────┘            (pass-through, already OCSF)      └──────────────────┘
```

Everything converges on **one** OCSF → SecurityEvent code path
(`ocsf_parser.OCSFParser.to_security_event_dict`), no matter which format the
data started in. `UniversalNormalizer` (in `format_normalizer.py`) is the
front door: `FormatDetector` sniffs CEF vs. OCSF vs. generic JSON, and routes
to the right converter.

### Why keep the direct CEF → SecurityEvent path too?

The existing `cef_parser.py` / `cef_adapters.py` pair is hand-tuned for
CrowdStrike, Cortex XDR, and Okta CEF exports — it resolves `cs1Label`/`cs1`
aliasing, vendor-native IDs (`DetectId`, `AlertId`, `SessionId`), and MITRE
fields with maximum fidelity for those three vendors specifically. That path
is untouched and remains the fastest, most precise route for those sources.
OCSF is **additive**: a second route for (a) any source that's already OCSF
natively (AWS Security Lake, GuardDuty, increasingly Splunk/Sentinel/Chronicle
exports), (b) uniform storage/SIEM-forwarding regardless of source format, and
(c) onboarding new proprietary JSON sources without writing a bespoke parser.

## 4. New modules

### `cyphora_s1/ocsf_parser.py`
Mirrors `cef_parser.py` exactly in shape: `OCSFRecord` (parsed event),
`OCSFParser` (parses single object / JSON array / NDJSON, also handles the
common "OCSF events shipped one-per-line" transport used by Cribl/Datadog/AWS
Security Lake exports). `to_security_event_dict()` resolves `event_type` in
the same four-tier priority order CEF uses:

1. MITRE technique in `attacks[]`
2. `class_uid:activity_id` lookup table (falls back to `class_uid:*` wildcard)
3. Category-level heuristic (e.g. any unmatched Findings event → `confirmed_attack`)
4. Message/finding-text keyword heuristics (same keyword lists as CEF, for consistency)

### `cyphora_s1/ocsf_adapters.py`
Mirrors `cef_adapters.py`. Because OCSF is vendor-neutral, partitioning is by
**category** rather than vendor: `SystemActivityOCSFAdapter`,
`FindingsOCSFAdapter`, `IAMOCSFAdapter`, `NetworkActivityOCSFAdapter`,
`DiscoveryOCSFAdapter` — each registers into the same `_ADAPTER_MAP` keys the
agents already expect (`endpoint_logs`, `threat_intel`, `identity_logs`,
`network_logs`, `cloud_logs`). `register_ocsf_adapters()` and
`OCSFSecurityEventFactory` are direct counterparts of
`register_cef_adapters()` / `SecurityEventFactory`.

### `cyphora_s1/format_normalizer.py`
The "convert everything to OCSF" layer:

- `FormatDetector.detect()` — CEF text signature → OCSF JSON shape (has
  `class_uid`/`category_uid`) → generic JSON → unknown.
- `CEFToOCSFConverter` — reuses `CEFParser`'s own event-type resolution as the
  bridge, then projects the resolved Cyphora `event_type` onto the nearest
  OCSF `class_uid`/`category_uid`/`activity_id`. All original CEF fields are
  preserved losslessly under `unmapped`.
- `FieldMappingProfile` + `GenericJSONToOCSFConverter` — the extensibility
  mechanism for proprietary JSON sources. A profile is a declarative dict
  (candidate source keys → OCSF dotted path) plus optional
  severity/activity resolver callables. Onboarding a new vendor becomes
  ~15 lines of configuration instead of a new parser module.
- `UniversalNormalizer` — orchestrates detection + conversion;
  `ingest_to_security_event_dicts()` is the one-call pipeline: raw log (any
  format) → OCSF → SecurityEvent dict(s).

## 5. Validated behavior (test results)

A 19-assertion test suite (`test_ocsf_support.py`) and a live orchestrator run
(`examples/run_ocsf_analysis.py`) both passed cleanly:

- **Native OCSF, single/array/NDJSON** — Authentication, Detection Finding
  (with MITRE `T1486`), and DNS Activity events all resolved to the correct
  Cyphora `event_type` and severity, and validated as real `SecurityEvent`
  Pydantic objects.
- **CEF → OCSF → SecurityEvent round-trip** — all 17 records in the existing
  `data/sample_security_logs.cef` sample converted through the new bridge
  with **17/17 severity agreement** against the direct CEF path, and
  identical `event_type` resolution on every inspected record.
- **Proprietary JSON via `FieldMappingProfile`** — a fictitious "Acme EDR"
  JSON shape (`ts`, `sev`, `summary`, `actor_user`, `proc_name`, `cmdline`)
  was mapped to OCSF and resolved to `abnormal_process_execution` / `high`
  severity with zero parser code, only a profile declaration.
- **Live orchestrator dispatch** — 8 native multi-vendor OCSF events (Okta,
  CrowdStrike, Palo Alto, AWS GuardDuty, Netskope) and all 17 bridged CEF
  events were dispatched through the real `AgentOrchestrator` running
  `CyphoraInvestigationAgent` and `CyphoraUEBAAgent`; MITRE mapping, kill-chain
  construction, and UEBA anomaly scoring all executed correctly against the
  OCSF-sourced telemetry, exactly as they do today against CEF telemetry.

## 6. Suggested next steps (not yet implemented)

- **`CYPHORA_OCSF_LOG` env var** — mirror the existing `CYPHORA_CEF_LOG` /
  `CYPHORA_CEF_CROWDSTRIKE` pattern in the Setup/Programmer guides so
  `register_ocsf_adapters()` can be wired up automatically at startup the
  same way `register_cef_adapters()` is today.
- **OCSF as the SIEM-forwarding shape** — `siem_enrichment_writer.py`
  currently writes Cyphora enrichment fields back in each SIEM's native
  shape. A follow-up could add an `OCSFEnrichmentWriter` that emits
  enrichment as an OCSF Finding (`class_uid: 2004`), which AWS Security Lake,
  Splunk, and other OCSF-native destinations could ingest directly.
- **Expand the `class_uid:activity_id` table opportunistically** — the table
  shipped here covers the activity IDs actually exercised by the sample data
  and the existing Cyphora event taxonomy. As real OCSF-native sources are
  onboarded, extend the table rather than relying on the category/keyword
  fallback tiers.
- **Profile library** — as proprietary sources are onboarded via
  `FieldMappingProfile`, consider committing a small library of pre-built
  profiles (e.g. for common SaaS audit-log shapes) the way `cef_parser.py`
  ships hand-tuned vendor logic for CrowdStrike/Cortex XDR/Okta today.

## 7. Code review pass — corrections made

A follow-up thorough review (cross-checked against the authoritative OCSF
schema via `schema.ocsf.io` and the `ocsf/ocsf-schema` GitHub repo, since the
first pass had approximated several `class_uid` numbers from memory) found
and fixed six issues:

1. **Wrong Network Activity `class_uid` numbers.** RDP Activity is `4005`,
   not `4006`; SMB Activity is `4006`, not `4009`; Email Activity is `4009`,
   not `4010`. Fixed in both `ocsf_parser.py`'s resolution table and
   `format_normalizer.py`'s reverse (Cyphora → OCSF) map. Added the real
   `4013` (NTP) and `4014` (Tunnel Activity) classes.
2. **Fabricated "Network Scan" Discovery class.** OCSF's Discovery category
   (5xxx) is *defensive* asset/inventory telemetry (device/user/software
   inventory, OS patch state) — there is no dedicated scan-detection class
   there. The original table invented one at `5003`/`5019` (which are
   actually User Inventory Info / Device Config State Change). Removed the
   fabrication; `network_scan` now resolves correctly via the existing
   MITRE-technique tier (T1046/T1018 in `attacks[]`) or, on the reverse
   path, projects to a Detection Finding (`2004`) — both already
   higher-priority than any class/category default, so no behavior was lost.
3. **Categories 6 (Application Activity) and 7 (Remediation) had no
   adapter.** `OCSFCategory._SOURCE_KEY_MAP` declared source keys for them,
   but `ocsf_adapters._CATEGORY_REGISTRATION` only covered categories 1-5 —
   any category-6/7 event would silently fall into the generic `ocsf_mixed`
   bucket instead of `cloud_logs`/`endpoint_logs`, where the existing agents
   actually look. Added `ApplicationActivityOCSFAdapter` and
   `RemediationOCSFAdapter` and registered both.
4. **`register_ocsf_adapters()` silently overwrote records.** If
   `category_paths` and `mixed_file`/`ocsf_text`/`ocsf_dicts` were both
   passed for the same category, the second call's `_ADAPTER_MAP` write (and
   `stats` entry) silently replaced the first instead of merging. Refactored
   to accumulate all records by category across every input source before
   doing a single registration pass.
5. **`FormatDetector` CEF sniffing was too narrow and had a false-positive
   risk.** The original character-offset check (`"CEF:" in text[:120]`)
   failed on the bundled `sample_security_logs.cef` itself, which has a
   comment-banner header longer than that window — confirmed by testing
   against the real file rather than only synthetic snippets. The fix scans
   a bounded window of lines and, critically, requires an anchored
   `CEF:<digits>|` header pattern (matching how `cef_parser.py` itself
   strips an optional syslog prefix) rather than a bare substring check —
   otherwise a JSON document that merely *mentions* the string `"CEF:"`
   inside a field value would have been misdetected as CEF.
6. **`type_uid` falsy-zero bug.** `_to_int(...) or self._derive_type_uid()`
   would incorrectly discard an explicit, valid `type_uid: 0` (legitimate
   for the OCSF Base Event class) because `0` is falsy in Python. Changed to
   an explicit `is not None` check.

All fixes were verified against an expanded test suite (30 assertions, up
from 19) and a fresh live-orchestrator run against the corrected sample
dataset — including a regression test against the real CEF sample file's
actual header (not just a synthetic snippet) and an explicit false-positive
probe for the format detector.

A second pass confirmed the IAM class numbers (3005 User Access Management,
3006 Group Management) were already correct, and added defensive hardening
that doesn't change any resolution logic but prevents real-world malformed
vendor payloads from crashing the parser: a shared `_as_dict()` guard is now
used everywhere an OCSF event's nested objects (`device`, `actor`, `process`,
`metadata`, `finding_info`, individual `attacks[]` entries) are read, so a
source that sends a string/null/list where the schema expects a nested
object degrades to "field not available" instead of raising. `attacks` is
also now type-checked as a list before iterating, since a non-conformant
source could plausibly send a single object instead of an array. Test count:
33 assertions.

A third, pre-production pass (static analysis via `pyflakes` plus targeted
runtime probes against the exact transport shapes real OCSF producers use)
found and fixed:

- **A crash on native OCSF NDJSON** — `UniversalNormalizer.normalize()`'s
  OCSF passthrough branch called a bare `json.loads()` on the raw text,
  which cannot parse multi-line NDJSON (the most common real-world OCSF
  transport per this module's own docstring — Cribl, Datadog Observability
  Pipelines, AWS Security Lake all ship it this way) and raised
  `JSONDecodeError("Extra data")`. Fixed by delegating to
  `OCSFParser.parse_text()`, which already handles single-object/array/
  NDJSON correctly.
- **A field-collision bug with real-world severity** — `severity` (the
  human-readable caption, e.g. `"Critical"`) is a legitimate, commonly
  populated top-level OCSF field alongside `severity_id` that most
  producers (AWS Security Lake included) send. It was missing from the
  `unmapped`-passthrough exclusion list, so it silently overrode the
  correctly-computed, normalized Cyphora severity string in `raw_data`
  with the source's own un-normalized caption — confirmed reproducible
  with a realistic payload, not just a contrived edge case. Fixed two
  ways: (1) `severity`/`timestamp`/`vendor`/`event_id` added to the
  exclusion list, and (2) as defense-in-depth, `OCSFRecord.to_dict()` now
  spreads `unmapped` *first* and computed fields *after*, so a vendor
  payload can never override an authoritative computed value regardless
  of key name — closing this entire class of bug rather than only the
  specific names already known to collide.
- **Duplicated category→source-key tables** — `ocsf_adapters.py` had its
  own hardcoded `_CATEGORY_REGISTRATION` table that had already drifted
  out of sync with `OCSFCategory`'s table once (the categories 6/7 bug
  fixed in the previous pass). Refactored so adapter registration derives
  its source keys from `OCSFCategory.source_key()` directly, with an
  import-time assertion that fails fast if the two tables are ever out of
  sync again — verified to actually catch the original bug shape.
- Removed dead/unused code (an unreferenced `_CEF_SEVERITY_INT_TO_STRING`
  table, unused imports in three files) and fixed a stale docstring that
  referenced a function name (`ingest_to_security_event`) that doesn't
  match the real one (`ingest_to_security_event_dicts`).

Test count after this pass: 40 assertions, plus a clean `pyflakes` run
across every new file.

## 8. File manifest

| File | Status |
|---|---|
| `cyphora_s1/ocsf_parser.py` | new |
| `cyphora_s1/ocsf_adapters.py` | new |
| `cyphora_s1/format_normalizer.py` | new |
| `cyphora_s1/__init__.py` | updated (exports) |
| `examples/run_ocsf_analysis.py` | new |
| `data/sample_security_logs.ocsf.ndjson` | new |
| `test_ocsf_support.py` | new (test/validation script, 40 assertions) |
| `CHANGES.md` | updated (v2.7.0 entry) |
