# Cyphora-S1 SDK — CHANGES

## v2.6.0 — Eight Critical Bug Fixes (2026)

Built on top of Cyphora-S1 v2.0.  This release resolves all eight
critical and high-priority bugs identified in the enterprise readiness
assessment.  No existing behaviour is broken; all fixes are additive
or drop-in replacements.

---

### Bug Fixes

#### Bug 1 — No SIEM Platform Connectors  ✓ FIXED
**File:** `cyphora_s1/siem_connectors/` (new module)

Added six production SIEM platform connectors:
- `SplunkConnector`   — polls Splunk ES Notable Events via REST API
- `SentinelConnector` — polls Microsoft Sentinel Incidents via Security Graph API
- `QRadarConnector`   — polls IBM QRadar Offenses via REST API
- `ElasticConnector`  — queries Elastic Security signals via Kibana Detection Engine API
- `ChronicleConnector`— polls Google Chronicle SOAR cases
- `ExabeamConnector`  — polls Exabeam AA high-risk user sessions

Each connector implements the `SIEMConnector` abstract base in
`cyphora_s1/siem_connectors/base.py` with `poll()`, `acknowledge()`,
`is_available()`, and `normalise()`.  Dual-mode: push (webhook) and
pull (API polling) alert delivery.

#### Bug 2 — No Enterprise Authentication  ✓ FIXED
**File:** `cyphora_s1/auth/` (new module)

New authentication module provides:
- `cyphora_s1/auth/jwt_auth.py`  — JWT Bearer token creation, validation,
  and FastAPI dependency helpers (`get_current_user`, `require_role`)
- `cyphora_s1/auth/models.py`    — `CyphoraUser`, `Role` enum (ANALYST,
  SENIOR_ANALYST, SOC_MANAGER, ADMIN, READONLY), `ROLE_PERMISSIONS` map
- `cyphora_s1/auth/saml.py`      — SAML 2.0 SP stub (interface is final;
  replace body with python3-saml for production)
- `cyphora_s1/auth/oidc.py`      — OIDC Authorization Code + PKCE flow
  supporting Azure AD, Google, Okta, GitHub, and generic OIDC IdPs

Configuration via environment variables (see each file's docstring).

#### Bug 3 — No Multi-Tenancy  ✓ FIXED
**Files:** `acda/runtime/data_collector.py`, `cyphora_s1/ueba_engine.py`

`data_collector.py`:
- Added `TenantAdapterRegistry` class replacing the global `_ADAPTER_MAP`
  for tenant-scoped adapter lookup.
- `DataCollector` now accepts `tenant_id` parameter; uses registry
  when set, falls back to legacy global map for backward compatibility.

`ueba_engine.py`:
- `BaselineStore.__init__` accepts `tenant_id` (default: `"default"`).
- All Redis keys now prefixed: `cyphora:{tenant_id}:ueba:baseline:{entity_id}`.
- `UEBAEngine` passes `tenant_id` through to `BaselineStore`.

#### Bug 4 — UEBA Cold-Start Returns Fixed 0.3  ✓ FIXED
**File:** `cyphora_s1/ueba_engine.py`

`AnomalyScorer.score()` now uses a tiered cold-start strategy:

  **Tier 1 — Peer group baseline:** if ≥3 mature entities of the same
  type exist, score against the peer group average via `PeerGroupStore`.
  Detects genuinely anomalous first-encounter behaviour.

  **Tier 2 — Event-type heuristic:** uses `event_type` and `severity`
  to derive a calibrated base score (e.g. `privilege_escalation` + `critical`
  → 0.80, `suspicious_login` + `low` → 0.35) even with no baseline data.

  **Tier 3 — Provisional 0.3:** last resort, with `is_cold_start=True`
  flag in `UEBAReport` so callers can distinguish provisional from full scores.

Added `UEBAEngine.warmup_from_logs()` to pre-populate baselines from
historical log data during onboarding, eliminating cold-start entirely.

#### Bug 5 — No Bidirectional SIEM Enrichment  ✓ FIXED
**File:** `cyphora_s1/siem_enrichment_writer.py` (new file)

New `SIEMEnrichmentWriter` module writes Cyphora AI findings back to the
originating SIEM alert after investigation completes.

Six platform writers:
- `SplunkEnrichmentWriter`    — updates notable event via REST API
- `SentinelEnrichmentWriter`  — adds incident comment via Graph API
- `QRadarEnrichmentWriter`    — adds offense note via REST API
- `ElasticEnrichmentWriter`   — adds signal tags via Kibana API
- `ChronicleEnrichmentWriter` — adds case comment via SOAR API
- `ExabeamEnrichmentWriter`   — log-only (no write-back API available)

`SIEMEnrichmentWriterFactory.get_writer(siem_type, **kwargs)` returns
the appropriate writer by SIEM name.

Fields written back to each SIEM alert:
  `cyphora_confidence_score`, `cyphora_mitre_ttps`,
  `cyphora_kill_chain_steps`, `cyphora_severity`,
  `cyphora_case_url`, `cyphora_recommended_actions`,
  `cyphora_analyst_report`

#### Bug 6 — No Analyst Approval Workflow  ✓ FIXED
**File:** `acda/runtime/action_executor.py`

`ActionExecutor._execute_single()` no longer blindly proceeds after
logging a warning for high-risk actions.

New classes:
- `ApprovalStatus` enum: `PENDING`, `APPROVED`, `DENIED`,
  `AUTO_DENIED`, `AUTO_APPROVED`
- `PendingApproval` dataclass: stores approval request with analyst ID,
  note, resolution timestamp
- `ApprovalQueue`: async queue backed by an asyncio.Event per request.
  `submit()` creates a PendingApproval; `wait_for_decision()` suspends
  execution until analyst approves/denies or `auto_deny_seconds` elapses.
  `approve()` and `deny()` are called by the SOC UI (Phase 4).

New `ActionExecutor` parameters:
  `approval_mode` (`"auto"` | `"manual"`),
  `auto_approve_seconds` (default: 300),
  `approval_queue` (injectable for per-tenant queues)

#### Bug 7 — Individual AI Model Scores Not Logged  ✓ FIXED
**File:** `acda/runtime/reasoning_engine.py`

`ReasoningEngine.run()` now emits a `model_scores` list in the
`reasoning_complete` log event containing, per model:
  `model_id`, `score`, `label`, `confidence`, `latency_ms`,
  `reasoning_preview` (first 300 characters of model reasoning).

This provides a complete per-model audit trail for every AI-assisted
security decision, satisfying SOC2 CC6.1 and HIPAA §164.312(b).

#### Bug 8 — PlaybookEngine.rollback() Not Implemented  ✓ FIXED
**File:** `cyphora_s1/playbook_engine.py`

`PlaybookEngine` now maintains a per-execution rollback log
(`self._rollback_log: Dict[str, List[ExecutedStep]]`).

Each successfully executed step is recorded with:
  `step_id`, `action`, `inverse_action`, `output`, `executed_at`,
  `event_snapshot` (SecurityEvent fields for rollback context).

`INVERSE_ACTIONS` map covers all four destructive action types:
  `isolate_host` → `un_isolate_host`
  `disable_account` → `re_enable_account`
  `block_ip` → `unblock_ip`
  `revoke_token` → `reissue_token`
  `quarantine_file` → `restore_file`

`PlaybookEngine.rollback(execution_id)` executes inverse actions in
reverse chronological order using `_INVERSE_HANDLERS`.  Non-reversible
actions (notify_soc, snapshot_memory, etc.) are skipped.

`PlaybookResult.rollback_available` is now True only when ≥1 reversible
step was successfully executed (previously always set to True when
`executed > 0`).  Returns `RollbackResult` with per-step outcomes.

---

### New Files

| Path | Description |
|------|-------------|
| `cyphora_s1/siem_connectors/__init__.py` | Package init |
| `cyphora_s1/siem_connectors/base.py` | SIEMConnector ABC |
| `cyphora_s1/siem_connectors/splunk.py` | Splunk ES connector |
| `cyphora_s1/siem_connectors/sentinel.py` | Microsoft Sentinel connector |
| `cyphora_s1/siem_connectors/qradar.py` | IBM QRadar connector |
| `cyphora_s1/siem_connectors/elastic.py` | Elastic SIEM connector |
| `cyphora_s1/siem_connectors/chronicle.py` | Google Chronicle connector |
| `cyphora_s1/siem_connectors/exabeam.py` | Exabeam AA connector |
| `cyphora_s1/siem_enrichment_writer.py` | Bidirectional SIEM write-back |
| `cyphora_s1/auth/__init__.py` | Package init |
| `cyphora_s1/auth/models.py` | CyphoraUser, Role, ROLE_PERMISSIONS |
| `cyphora_s1/auth/jwt_auth.py` | JWT middleware + FastAPI dependencies |
| `cyphora_s1/auth/saml.py` | SAML 2.0 SSO stub |
| `cyphora_s1/auth/oidc.py` | OIDC/OAuth2 Authorization Code flow |

### Modified Files

| Path | Change |
|------|--------|
| `acda/runtime/reasoning_engine.py` | Bug 7: per-model score logging |
| `acda/runtime/action_executor.py` | Bug 6: ApprovalQueue + suspension |
| `acda/runtime/data_collector.py` | Bug 3: TenantAdapterRegistry |
| `cyphora_s1/ueba_engine.py` | Bugs 3+4: tenant scoping + cold-start |
| `cyphora_s1/playbook_engine.py` | Bug 8: rollback() implementation |

---

### Inherited Bug Fixes (from ACDA-SDK v1.1 / v2.0)

All previously fixed bugs remain intact.
