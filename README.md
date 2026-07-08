<div align="center">

# Cyphora

### The AI SOC analyst that has to convince three models before it touches your environment.

**An open-source, AI-native SIEM platform — and the autonomous-agent SDK it runs on.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Status: Beta](https://img.shields.io/badge/Status-Public%20Beta-orange.svg)]()
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)]()
[![Self-Hosted](https://img.shields.io/badge/Deploy-Self--Hosted%20%7C%20Air--Gapped-success.svg)]()
[![Maintained by YouSource.ai](https://img.shields.io/badge/Maintained%20by-YouSource.ai-blue.svg)](https://yousource.ai)

</div>

---

Cyphora is two applications in one repository:

| # | Application | What it is | Directory |
|---|---|---|---|
| **1** | **ACDA-SDK** | The **Autonomous Cyber Defense Agent SDK** — a general-purpose framework for building consensus-validated AI security agents. Foundation layer. Usable stand-alone. | [`acda/`](./acda) |
| **2** | **Cyphora-S1** | The **AI-native SIEM** built on ACDA-SDK — investigation, UEBA, compliance, and natural-language query agents, plus multi-vendor ingestion and SIEM integrations. Product layer. | [`cyphora_s1/`](./cyphora_s1) |

> **Public Beta.** Cyphora has been validated end-to-end against real CrowdStrike Falcon, Okta, and Palo Alto Networks telemetry. It works, and its limitations are documented honestly in [Known Issues](#known-issues). We are releasing it under the MIT license as an open-source industry contribution, and we are looking for enterprise and government security teams to break it against their own data.

---

## Why Cyphora exists

Every SOC on earth is drowning in the same three problems:

1. **Alert fatigue.** Analysts triage thousands of alerts a day; the real attack is buried in the noise, and the team burns out finding it.
2. **You can't trust a single AI to pull the trigger.** LLMs hallucinate. An AI that can disable an account or isolate a host on its own is a new, worse insider threat. One bad inference and you've DoS'd your own executive team.
3. **The good tooling is a black box you rent.** Per-event pricing, mandatory cloud egress of your most sensitive telemetry, and a model you can neither inspect nor replace.

**Cyphora is built around a single architectural conviction: no one AI model is ever given authority to act.**

Every security event is scored **independently by three separate AI models**. A weighted consensus is computed, and an action fires **only** if that consensus clears a configured threshold. If the models disagree, the system **declines to act** and surfaces the event for a human — by design, not as a fallback. This is AI safety enforced by architecture, not by a prompt asking the model to please be careful.

And because Cyphora runs on the open ACDA-SDK, you **self-host the whole thing**. No per-event billing. No mandatory cloud dependency. Bring your own model keys — or your own models. Your logs never have to leave your boundary.

### Who it's for

- **Enterprise SOC & detection-engineering teams** who want AI-accelerated triage without handing an LLM the keys to production.
- **Federal, state, and local government cyber groups** who need a self-hosted, inspectable, air-gap-capable platform with a full audit trail behind every decision.
- **Security engineers and researchers** who want a real, working, consensus-validated agent framework (ACDA-SDK) to build their own defensive automation on.

---

## Proof: a verified beta run, not marketing copy

The numbers below are from a **single verified run** against CrowdStrike Falcon, Okta, and Palo Alto Networks telemetry, spanning five coordinated kill-chain scenarios plus a real-format CEF sample log. Run window: **May 25 – June 2, 2026.** Every action count was independently verified by direct `grep` against the scenario and agent log files. Technical write-up by **John Chiong**.

### The core mechanism, working as designed

> **34 of 35 events passed consensus. The one that did not — a suspicious login for an admin account — scored 0.6267 average across the three models, producing a weighted consensus of 0.6895. Below the 0.75 threshold. No playbook executed, no account disabled, no IP blocked.**
>
> *That is the architecture working as intended: the system declined to act on a low-confidence signal rather than guessing.*

| Metric | Result |
|---|---|
| Total kill-chain events processed | **35** |
| Consensus passed | **34 / 35** (97.1%) |
| Events correctly **withheld** by the consensus gate | **1** — weighted score `0.6895` < `0.75` threshold |
| Average consensus — passing events | **0.929** (range `0.894` – `0.957`) |
| Coordinated attack scenarios | **5** (ransomware, insider exfil, credential + lateral movement, LOLBin/DNS tunneling, cloud takeover) |
| Scenario steps detected & MITRE-mapped | **19 / 19** (100%) |
| MITRE ATT&CK TTPs identified | **105** across the 5 scenarios |
| Natural-language queries answered | **10 / 10** |
| UEBA behavioral events scored | **7 / 7** |
| Compliance frameworks assessed (×3 independent runs each) | **5** — SOC 2, ISO 27001, PCI-DSS v4, HIPAA, NIS2 |

### Human-assisted remediation, not autonomous action

Confirmed findings trigger response playbooks — but higher-risk containment steps are **gated behind analyst approval**, never fired automatically. Every action below is tied to a specific investigated event, not a blanket rule match, and every destructive action is individually reversible.

| Response action | Count in run |
|---|---|
| `generate_incident_report` | 35× |
| `notify_soc` | 35× |
| `create_threat_alert` | 34× |
| `revoke_token` | 28× |
| `block_ip` | 28× |
| `disable_account` | 27× |
| `isolate_host` | 11× |
| `snapshot_memory` | 3× |

### Compliance automation — including where it graded itself down

The same telemetry window was independently assessed three times against all five frameworks:

- **ISO 27001** averaged the highest coverage at **83%**.
- **SOC 2** came in **lowest at 46%** — and Cyphora **flagged SOC 2 as its own primary remediation target** in its output.

We publish that 46% deliberately. It is what the tool reported about its own gaps, not a curated result. A compliance engine you can't catch understating a gap isn't one you should trust with an audit.

### One known issue, stated up front

In this run the **natural-language query parser fell back to heuristic extraction on all 10 queries** rather than structured JSON parsing. It still returned correct results, but this path is less robust for complex or ambiguous queries. It is tracked as [`NLQ-001`](#known-issues) and is being fixed before general availability. See [Known Issues](#known-issues) for the complete, unflinching list.

---

## Table of Contents

- [Application 1 — ACDA-SDK (the foundation)](#application-1--acda-sdk-the-foundation)
- [Application 2 — Cyphora-S1 (the SIEM)](#application-2--cyphora-s1-the-siem)
- [How it works — the five-stage pipeline](#how-it-works--the-five-stage-pipeline)
- [The consensus engine, in detail](#the-consensus-engine-in-detail)
- [Repository structure](#repository-structure)
- [Log formats & integrations](#log-formats--integrations)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Testing](#testing)
- [Known issues](#known-issues)
- [Roadmap & contribution priorities](#roadmap--contribution-priorities)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Contributing](#contributing)
- [Contact](#contact)

---

## Architecture at a glance

Two layers. ACDA-SDK is the engine; Cyphora-S1 is the product built on top of it **without modifying the SDK core** — the cleanest possible proof that the SDK is genuinely reusable.

```
┌──────────────────────────────────────────────────────────────────────┐
│                       APPLICATION 2 — CYPHORA-S1                     │
│  cyphora_s1/                    The AI-native SIEM                   │
│  ├── cef_parser.py            CEF ingestion + vendor dialects        │
│  ├── cyphora_ingest.py        7 live API source adapters             │
│  ├── mitre_mapper.py          ATT&CK mapping + kill-chain builder    │
│  ├── ueba_engine.py           Behavioral baselines + anomaly scoring │
│  ├── nl_query_engine.py       Plain-English → query → results        │
│  ├── compliance_engine.py     SOC2 / ISO / PCI / HIPAA / NIS2        │
│  ├── playbook_engine.py       Ordered response playbooks + rollback  │
│  ├── siem_connectors/         6 bidirectional SIEM connectors        │
│  └── auth/                    JWT · SAML 2.0 · OIDC/OAuth2           │
├──────────────────────────────────────────────────────────────────────┤
│                        APPLICATION 1 — ACDA-SDK                      │
│  acda/                          The autonomous-agent engine          │
│  ├── runtime/                                                        │
│  │   ├── reasoning_engine.py       Multi-model LLM ensemble (async)  │
│  │   ├── consensus_validator.py    weighted / majority / unanimous / quorum │
│  │   ├── action_executor.py        Pluggable dispatch + ApprovalQueue│
│  │   └── data_collector.py         Source adapters + tenant registry │
│  ├── orchestrator/            Event routing (200 concurrent max)     │
│  ├── compiler/                YAML → validated Python agent          │
│  ├── models/schemas.py        Pydantic v2 SecurityEvent models       │
│  ├── simulation/              Built-in attack scenario simulator     │
│  └── cli.py                   the `acda` CLI                         │
└──────────────────────────────────────────────────────────────────────┘
        Ingest → Collect → Reason → Consensus → Act   (every event, every agent)
```

---

## Application 1 — ACDA-SDK (the foundation)

**ACDA-SDK** (Autonomous Cyber Defense Agent SDK) is the open-source engineering foundation beneath Cyphora-S1. It provides the complete event pipeline, multi-model AI reasoning, consensus validation, pluggable action dispatch, and agent orchestration. You can build and deploy your own defensive agents on ACDA-SDK **with no Cyphora-S1 dependency at all** — it is a standalone framework.

### Agents are declarative before they are code

Every agent is defined in a YAML **Agent Definition Format (ADF)** spec. The compiler validates it against a schema and enforces hard safety constraints *before* generating a single line of Python. The YAML is the authoritative source of truth for an agent's configuration; the compiled `BaseAgent` subclass mirrors those constants and adds engine behavior in `run()`.

```yaml
agent:
  name: MyCustomThreatAgent
  version: '1.0'

triggers:
  event_types: [suspicious_login, confirmed_attack, anomaly_detected]

data_collection:
  sources: [endpoint_logs, identity_logs]
  time_window: 30m                 # s / m / h / d

reasoning:
  ai_models: [claude-sonnet-4-6, claude-opus-4-6, gpt-4o]
  task: attack_chain_analysis
  temperature: 0.15

consensus_validation:
  method: weighted_vote            # weighted_vote | majority_vote | unanimous | quorum
  threshold: 0.75                  # 0.0 – 1.0
  weights:
    claude-sonnet-4-6: 0.40
    claude-opus-4-6:   0.35
    gpt-4o:            0.25        # weights must sum to exactly 1.0

actions: [generate_incident_report, notify_soc, mitre_map]

safety_controls:
  max_runtime: 180s
  approval_required: manual        # none | manual | auto
  dry_run_mode: false
```

**Constraints the validator enforces at compile time — not at 3 a.m. in production:**

- Consensus model weights must sum **exactly** to `1.0`.
- Every `sources` key must be a registered adapter in `_ADAPTER_MAP`.
- Every `event_type` must match the `EventType` enum.
- `max_runtime` and `approval_required` must satisfy the `safety_controls` schema.

### The `acda` CLI

```bash
# Agent lifecycle
acda init MyAgent --output-dir agent_definitions/     # scaffold a new ADF YAML
acda validate agent_definitions/myagent.yaml          # validate against the ADF schema
acda build    agent_definitions/myagent.yaml \
     --output-dir generated_agents/                   # compile YAML → Python BaseAgent

# Execution & simulation (no live credentials required)
acda run InvestigationAgent -e suspicious_login --dry-run
acda simulate ransomware --dry-run
acda simulate data_exfiltration --speed 5.0 --dry-run
acda simulate lateral_movement --dry-run

# Operations
acda registry list       # all registered agents + their trigger types
acda status              # orchestrator health, queue depth, throughput stats
acda deploy myagent --namespace cyber-defense         # Kubernetes deployment
```

### Model adapters — bring your own brain

The reasoning engine ships with three adapter types in [`acda/runtime/reasoning_engine.py`](./acda/runtime/reasoning_engine.py):

| Adapter | Backend | Notes |
|---|---|---|
| `AnthropicModelAdapter` | Claude (any `claude-*` model) via the official async SDK | Default Sonnet + Opus in the consensus ensemble. |
| `OpenAIModelAdapter` | GPT-4o / any OpenAI-compatible chat model | Uses JSON-object structured output. |
| `SimulationModelAdapter` | Deterministic offline scorer | Powers `--dry-run`, CI, and air-gapped demos with **zero** API calls. |

Any provider exposing an OpenAI- or Anthropic-compatible API can be substituted in the agent YAML **without touching platform code**. Self-host an open-weights model behind a compatible endpoint and Cyphora will never call a cloud API.

---

## Application 2 — Cyphora-S1 (the SIEM)

Cyphora-S1 is the AI-native SIEM layer. It ships **four production agents**, all built on ACDA-SDK:

| Agent | Triggers on | Produces |
|---|---|---|
| **`CyphoraInvestigationAgent`** | 10 event types (`suspicious_login`, `privilege_escalation`, `credential_dump`, `lateral_movement`, `data_exfiltration`, `abnormal_file_encryption`, `confirmed_attack`, `ueba_anomaly`, …) | `AttackIntelligence` — MITRE TTPs, temporally-ordered kill chain, plain-English incident report, selected response playbook |
| **`CyphoraUEBAAgent`** | 5 event types | `UEBAReport` — `risk_score` 0–1, `risk_label`, per-feature anomaly explanations; emits `ueba_anomaly` at ≥ 0.70 |
| **`CyphoraComplianceAgent`** | `compliance_check` (weekly by default; on-demand supported) | Five framework reports **in parallel**: SOC 2, ISO 27001, PCI-DSS v4, HIPAA, NIS2 — with a remediation-prioritized gap list |
| **`CyphoraNLQueryAgent`** | `nl_query` | Formatted markdown/narrative answer, execution time, record count — no SPL/KQL/AQL required |

### Investigation pipeline — full kill chain in under 60 seconds

```
SecurityEvent
     │
     ▼
 MITREMapper        →  Maps CEF custom fields (Technique/Tactic/cs2/cs3/cs6), event
     │                 class IDs, and AI reasoning to all 14 ATT&CK tactics. Extracts
     │                 sub-techniques where the data supports it. Emits a MITRE
     │                 Navigator deep-link for every investigation.
     ▼
 KillChainBuilder   →  Assembles an ordered kill chain from Initial Access through
     │                 Impact, extracting IOCs (source IPs, hosts, accounts, file
     │                 hashes, threat-intel hits) per stage.
     ▼
 IncidentReporter   →  Claude Sonnet (preferred) or GPT-4o writes a plain-English
     │                 incident report. Template fallback guarantees a report is
     │                 always produced, even if every model call fails.
     ▼
 AttackIntelligence →  TTPs · kill-chain steps · analyst report · Navigator link · IOC summary
```

### UEBA — seven behavioral anomaly features

Per-entity baselines for users, hosts, and service accounts, scored continuously:

| Feature | Detection logic | Score |
|---|---|---|
| Login outside normal hours | Login hour vs. `typical_login_hours`; flags ≥ 3h deviation, critical at ≥ 6h | 0.60–0.80 |
| Login from new IP | Source IP vs. `typical_source_ips` allowlist | 0.65 |
| Impossible travel | Geographically impossible movement given timestamps (e.g. NY → Singapore in 22 min) | ≥ 0.85 |
| Abnormal data volume | Bytes vs. EMA of `avg_bytes_per_day`; logarithmic above 5× baseline | 0.65–0.90 |
| Mass file write / encryption | Files written vs. baseline; > 5× or > 200 files = critical ransomware signal | 0.85–0.95 |
| Non-admin privilege use | Any privileged action by a user whose `has_admin_rights` baseline is `False` | 0.80 |
| Threat-intel hit | Source IP/indicator matched against live threat-intel feeds — always critical | 0.95 |

**Cold start is handled, not faked.** A tiered strategy — peer-group baseline (if ≥ 3 mature peers exist) → event-type heuristic → provisional `0.3` with an explicit `is_cold_start=True` flag — means early scores are labeled as provisional rather than presented as ground truth. Use `warmup_from_logs()` to pre-seed baselines from historical exports. UEBA becomes meaningfully reliable after ~30–90 days of operational data; treat early scores as indicative.

### Response playbooks — with a real undo button

Four built-in playbooks. Steps marked **[approval]** suspend execution and route to the `ApprovalQueue` until an authorized analyst approves, or an auto-deny timeout fires (default 300 s).

| Playbook | Steps |
|---|---|
| `ransomware_response` | `snapshot_memory` → `isolate_host` **[approval]** → `quarantine_file` **[approval]** → `notify_soc` → `pagerduty_incident` (sev ≥ high) → `generate_incident_report` |
| `credential_compromise` | `revoke_token` **[approval]** → `disable_account` **[approval]** → `block_ip` **[approval]** → `notify_soc` → `pagerduty_incident` → `generate_incident_report` |
| `data_exfiltration_response` | `block_ip` **[approval]** → `kill_process` → `isolate_host` **[approval]** → `snapshot_memory` → `pagerduty_incident` → `notify_soc` → `generate_incident_report` |
| `lateral_movement_response` | `block_ip` **[approval]** → `isolate_host` **[approval]** → `revoke_token` **[approval]** → `snapshot_memory` → `pagerduty_incident` → `notify_soc` → `generate_incident_report` |

**Rollback:** every destructive action records its inverse before executing. `rollback(execution_id)` reverses all steps in reverse chronological order:
`isolate_host ↔ un_isolate_host` · `disable_account ↔ re_enable_account` · `block_ip ↔ unblock_ip` · `revoke_token ↔ reissue_token` · `quarantine_file ↔ restore_file`.

### Compliance — five frameworks, in parallel, weighted

| Framework | Controls covered |
|---|---|
| **SOC 2 Type II** | CC6.1–CC6.3, CC6.7, CC7.1–CC7.3, CC8.1, CC9.1 |
| **ISO 27001:2022** | A.5.15, A.5.23, A.8.5, A.8.7, A.8.15, A.8.16 |
| **PCI-DSS v4.0** | Req 1.3, 7.2, 8.2, 10.2, 10.7, 12.10 |
| **HIPAA** | §164.312(a)(1), (b), (c)(1), (e)(1) |
| **NIS2 (EU 2022/2555)** | Art.21 (a), (b), (e), (g), (h), (i) |

All five run concurrently via `asyncio.gather()`. Scores reflect **weighted** control coverage across a configurable telemetry lookback (default 90 days), not a naive satisfied/total ratio. Evidence packages require qualified auditor or compliance-officer review before formal regulatory submission — Cyphora accelerates the evidence collection, it does not replace the auditor.

---

## How it works — the five-stage pipeline

Every event — regardless of source or agent — flows through the same pipeline. This uniformity is why the SDK is reusable and why the audit trail is complete.

| Stage | Component | What happens |
|---|---|---|
| **1. Ingest** | Source adapters | A CEF file, live API, or simulated adapter populates a `SecurityEvent`. Register adapters with `register_cef_adapters()` / `register_all_adapters()` / `register_simulated_adapters()`. |
| **2. Collect** | `DataCollector.collect()` | Queries every registered adapter for the surrounding time window (default 30 min). Returns a `CollectedData` object. |
| **3. Reason** | `ReasoningEngine.run()` | Dispatches to each configured model **in parallel**. Returns a `ReasoningResult` with a per-model `ModelScore` (score, label, confidence, latency, reasoning preview). Every score is logged for audit. |
| **4. Consensus** | `ConsensusValidator.validate()` | Applies `weighted_vote` / `majority_vote` / `unanimous` / `quorum`. Returns `ConsensusResult(passed: bool, score, explanation)`. |
| **5. Act** | `ActionExecutor.run()` | Fires actions **only if consensus passed**. High-risk actions route to the `ApprovalQueue` and suspend until an analyst decides or the auto-deny timeout elapses. |

---

## The consensus engine, in detail

This is the safety-critical heart of the system, so here is exactly what it computes. From [`acda/runtime/consensus_validator.py`](./acda/runtime/consensus_validator.py):

**Weighted vote (production default):**

```
                Σ (weightᵢ × confidenceᵢ)
consensus =  ─────────────────────────────      →   act only if consensus ≥ threshold
                     Σ weightᵢ
```

This is precisely the math behind the withheld event in the verified run: the admin-login event scored `0.6267` average across the three models, which — under the configured Sonnet 0.40 / Opus 0.35 / GPT-4o 0.25 weighting — produced a weighted consensus of **0.6895**, below the `0.75` threshold. **No action fired.** The system chose to be uncertain out loud rather than confident and wrong.

| Method | Rule | Use it for |
|---|---|---|
| `weighted_vote` | `Σ(wᵢ·confidenceᵢ) / Σwᵢ ≥ threshold` | **Production default.** Ships Sonnet 0.40 / Opus 0.35 / GPT-4o 0.25. |
| `majority_vote` | > 50% of models individually score ≥ threshold | Lower-risk, high-throughput actions. |
| `unanimous` | **All** models must score ≥ threshold | Highest-impact containment: host isolation, account disable. |
| `quorum` | ≥ a configurable fraction (default 67%) agree | Medium-risk actions needing 2-of-3. |

Guardrails built into the validator: a hard `min_models_required` floor (fails closed if too few models responded), an `asyncio.timeout` on the whole validation (a hung provider fails closed, it does not hang the SOC), and a full per-model breakdown string in every `ConsensusResult.explanation` for audit. Every individual model's score, confidence, latency, and a 300-char reasoning preview are emitted in the `reasoning_complete` log event — a complete per-model audit trail for every AI-assisted decision, which is what SOC 2 CC6.1 and HIPAA §164.312(b) actually require.

---

## Repository structure

```
Cyphora/
├── acda/                          ★ APPLICATION 1 — ACDA-SDK (build on top; no need to modify)
│   ├── agents/
│   │   ├── agents.py              Original ACDA-SDK BaseAgent subclasses
│   │   └── cyphora_agents.py      The four Cyphora-S1 production agents
│   ├── compiler/                  YAML → Python compiler + ADF schema validator
│   ├── models/schemas.py          All Pydantic v2 models (SecurityEvent, ModelScore, …)
│   ├── orchestrator/              AgentOrchestrator — event routing + concurrency
│   ├── runtime/                   reasoning · consensus · action · data collection
│   ├── simulation/                Built-in attack scenario simulator
│   └── cli.py                     the `acda` CLI
│
├── cyphora_s1/                    ★ APPLICATION 2 — Cyphora-S1 SIEM engine
│   ├── cef_parser.py / cef_adapters.py    CEF parsing + DataCollector adapters
│   ├── cyphora_ingest.py          7 live API source adapters
│   ├── sim_adapters.py            Product-faithful simulated adapters (offline/dev)
│   ├── mitre_mapper.py            ATT&CK mapping + kill-chain builder
│   ├── ueba_engine.py             Behavioral baselines + anomaly scoring
│   ├── nl_query_engine.py         Natural-language → query → results
│   ├── compliance_engine.py       SOC2 / ISO / PCI / HIPAA / NIS2
│   ├── playbook_engine.py         Ordered response playbooks + rollback
│   ├── siem_connectors/           6 bidirectional SIEM connectors
│   ├── siem_enrichment_writer.py  Writes AI findings back to the originating SIEM
│   └── auth/                      JWT · SAML 2.0 · OIDC
│
├── agent_definitions/             ADF YAML agent specs (authoritative config)
├── data/sample_security_logs.cef  17-event mixed-vendor CEF sample log
├── examples/                      Runnable demo scripts (start here)
├── generated_agents/              Output of `acda build` (git-ignored)
├── tests/                         63-event test dataset + runner + pytest suite
├── k8s/deployment.yaml            Kubernetes manifests (HPA, NetworkPolicy, RBAC)
├── requirements.txt · setup.py
├── CHANGES.md                     Version history & the 8 critical bug fixes (v2.6)
├── LICENSE                        MIT License
├── SECURITY.md                    Security policy & vulnerability disclosure
└── README.md                      (this file)
```

---

## Log formats & integrations

### Ingest formats

| Format | Status | Notes |
|---|---|---|
| **CEF (Common Event Format)** | ✅ Native | Full spec: multi-line syslog wrapping, `csNLabel`/`csN` resolution, escaped pipes, epoch-ms timestamps. Verified dialects for CrowdStrike, Palo Alto Networks, Okta. |
| **Structured JSON** | ✅ Native (live API) | Direct ingestion of nested JSON via live connectors (CloudTrail, MS Graph, GCP Logging, …). |
| OCSF · LEEF · Syslog RFC 5424 · ECS · Windows EVTX | 📋 Planned | Prioritized community-contribution targets — see [Roadmap](#roadmap--contribution-priorities). |

### CEF — verified vendor dialects

| Vendor | Vendor string | Key custom fields |
|---|---|---|
| **CrowdStrike Falcon** | `CrowdStrike` | `cs1`=DetectId, `cs2`=Technique, `cs3`=Tactic, `cs4`=ProcessName, `cs5`=ParentProcess, `cs6`=MitreTechnique |
| **Palo Alto / Cortex XDR** | `Palo Alto Networks` | `cs1`=AlertId, `cs6`=MitreTechnique |
| **Okta** | `Okta` | `cs1`=SessionId |

### Live API connectors — 7 sources

`AWSCloudTrailAdapter` · `AzureADAdapter` (Entra ID / Graph) · `OktaAdapter` · `CrowdStrikeAdapter` · `PaloAltoAdapter` (PAN-OS XML API) · `GitHubAuditAdapter` · `GCPAuditAdapter`. Each requires only least-privilege read scopes; see [Configuration](#configuration).

### SIEM connectors — 6 platforms, bidirectional

Inbound alert polling **plus** write-back of AI findings to the originating alert record:

| Platform | Ingest | Write-back |
|---|---|---|
| **Splunk ES** | polls `Cyphora_Notable_Events` saved search | updates notable-event fields |
| **Microsoft Sentinel** | polls open Incidents (Graph API) | adds Incident comment |
| **IBM QRadar** | polls open Offenses (REST v19) | adds Offense note |
| **Elastic Security** | queries open signals (Kibana Detection Engine) | adds signal tags |
| **Google Chronicle SOAR** | polls open cases | adds case comment |
| **Exabeam Advanced Analytics** | polls sessions with risk ≥ 90 | log-only (no write-back API) |

Fields written back (prefixed `cyphora_` to avoid collisions): `cyphora_confidence_score`, `cyphora_mitre_ttps`, `cyphora_kill_chain_steps`, `cyphora_severity`, `cyphora_recommended_actions`, `cyphora_analyst_report`, `cyphora_case_url`, `cyphora_enriched`.

---

## Quick start

### Requirements

| | Minimum | Notes |
|---|---|---|
| Python | **3.11** | 3.12 recommended. Uses `asyncio`, walrus, PEP 604 unions. 3.10 and below unsupported. |
| RAM | 4 GB | 8 GB recommended. **No local model weights** — inference is API-based. |
| OS | Linux Ubuntu 22.04+ | macOS 13+ and Windows 11 + WSL2 supported. |
| Network | Outbound 443 | To `api.anthropic.com` (and optionally `api.openai.com`) — or point at your own self-hosted endpoint. |
| Redis | Optional | Strongly recommended in production for UEBA baseline persistence & multi-replica correctness. Falls back to in-memory automatically. |

### Install

```bash
git clone https://github.com/yousource-ai/cyphora.git        # confirm URL at publish time
cd cyphora

python3 -m venv .venv && source .venv/bin/activate            # .venv\Scripts\activate on Windows
pip install -r requirements.txt
pip install -e .                                              # installs the `acda` CLI

acda --help                                                   # verify
```

### Minimal `.env`

At minimum an Anthropic key is required. **Any log source you leave unconfigured is automatically served by a product-faithful simulated adapter**, so you can run the whole platform end-to-end with zero real credentials.

```bash
ANTHROPIC_API_KEY=sk-ant-api03-...        # required
OPENAI_API_KEY=sk-...                     # optional — enables GPT-4o (25% consensus weight)
REDIS_URL=redis://localhost:6379/0        # optional — blank falls back to in-memory
CYPHORA_DRY_RUN=1                          # recommended for evaluation: no live containment
CYPHORA_CEF_LOG=data/sample_security_logs.cef
```

> Never commit `.env` — it is already in `.gitignore`. In production use Vault, AWS Secrets Manager, or Kubernetes Secrets.

### First run — no live credentials needed

```bash
export $(grep -v '^#' .env | xargs)

# Analyze the bundled 17-event mixed-vendor CEF sample (CrowdStrike + Palo Alto + Okta)
python examples/run_cef_analysis.py --dry-run --verbose

# Or your own export:
python examples/run_cef_analysis.py --log-file /path/to/export.cef --dry-run --verbose
```

See [`examples/`](./examples) for per-agent entry points (investigation, UEBA, NL query, compliance) and [`k8s/deployment.yaml`](./k8s/deployment.yaml) for the HA Kubernetes reference (2-pod orchestrator, HPA-scaled investigation agents 2–20, least-privilege RBAC, egress-443-only NetworkPolicy).

---

## Configuration

Cyphora is configured entirely through environment variables — nothing sensitive lives in code. The full reference (every AI key, CEF path, live-API credential pair, and platform flag) is documented inline in each adapter's docstring. Key rules:

- **Credential pairs are all-or-nothing.** Setting `OKTA_DOMAIN` without `OKTA_API_TOKEN` skips the adapter (logged as `adapter_skipped_missing_credentials`) rather than half-initializing.
- **Adapter registration order matters:** always call `register_all_adapters()` *before* `register_simulated_adapters()`, so simulated adapters only fill slots a live adapter didn't claim.
- **`CYPHORA_DRY_RUN=1`** disables all real containment actions and PagerDuty alerts — use it for every evaluation.

---

## Testing

The suite contains **63 security events** (46 synthetic + 17 real-format CEF) across 5 coordinated kill-chain scenarios, per-agent capability tests, and negative tests that must **not** trigger investigations (false-positive suppression).

```bash
# Full run — all agents, all scenarios (start here, dry-run + verbose)
python tests/run_cyphora_test_suite.py --dry-run --verbose

# A single scenario or agent
python tests/run_cyphora_test_suite.py --scenario S1_RANSOMWARE --verbose
python tests/run_cyphora_test_suite.py --agent CyphoraInvestigationAgent

# pytest unit tests + coverage
pytest tests/ -v --asyncio-mode=auto
pytest tests/ --cov=acda --cov=cyphora_s1 --cov-report=term-missing
```

| Scenario | Steps | Kill chain |
|---|---|---|
| S1 — Ransomware | 5 | Macro → C2 beacon → PsExec lateral → Mimikatz LSASS dump → BlackCat encryption (8,741 files @ 148/s) |
| S2 — Insider exfil | 4 | Impossible travel NY→SG (22 min) → Org Admin grant → 2.8 GB 7z archive → Dropbox DLP hit |
| S3 — Credential + lateral | 4 | MFA fatigue (47 attempts) → LSASS handle → SMB scan (312 hosts) → WMI exec to 5 servers |
| S4 — LOLBin + DNS tunnel | 3 | certutil download → scheduled-task persistence → iodine DNS tunneling |
| S5 — Cloud takeover | 3 | Credential stuffing → 40 GPU cryptomining instances → 12 backdoor IAM admins → CloudTrail disabled |

---

## Known issues

Documented from the beta evaluation and a full codebase review (v2.6). Contributions closing these are **especially** welcome — each maps to a [roadmap item](#roadmap--contribution-priorities).

| ID | Severity | Component | Description |
|---|---|---|---|
| `GAP-C1` | Critical | `cef_parser.py` | CEF vendor coverage limited to CrowdStrike, Palo Alto, Okta. Other vendors → `vendor='unknown'`, losing MITRE extraction precision. |
| `GAP-C2` | Critical | Ingest | No native Syslog (RFC 3164/5424) or JSON-Lines **file** parser. Non-CEF sources need live API connectors — a direct constraint on **air-gapped** deployments. |
| `GAP-C3` | Critical | Ingest | No LEEF file parser. `QRadarConnector` polls live but cannot process historical LEEF exports. |
| `GAP-H1` | High | `cef_parser.py` | Timestamp reads only `rt=`; vendors using `start=`/`end=`/`deviceCustomDate1=` fall back to `datetime.now()`, corrupting time-window filtering and UEBA timelines. |
| `GAP-H2` | High | `cef_parser.py` | Generic class-ID event-type resolution can misfire for unknown vendors, triggering unnecessary (billable) AI investigations. |
| `GAP-H3` | High | SIEM connectors | All six `normalise()` methods map only a subset of fields; the AI receives sparser context than from live adapters. |
| `GAP-H4` | High | SIEM connectors | ArcSight and Sumo Logic connectors are absent. |
| `NLQ-001` | Medium | `nl_query_engine.py` | All 10 beta queries fell back to heuristic extraction (`nl_parse_failed_using_heuristics`) instead of structured JSON parsing. Results correct; path less robust. **In progress.** |
| `GAP-M1` | Medium | Ingest | No event deduplication — overlapping file + live-API ingest can double-investigate. |
| `GAP-M2` | Medium | Ingest | No rate limiting on file ingest — large historical exports can exhaust LLM API limits and the 200-agent concurrency cap. |
| `GAP-M3` | Medium | UEBA | Without Redis, baselines reset on restart; multi-replica deployments without Redis produce split anomaly scores. |

---

## Roadmap & contribution priorities

These are the highest-impact places to contribute — each closes a known issue against the existing `BaseParser` / `SIEMConnector` interfaces:

- **More CEF vendor dialects** (`GAP-C1`) — Fortinet, SentinelOne, Cisco, Check Point, Trend Micro.
- **`SyslogParser` + `JSONLinesParser`** (`GAP-C2`) — with an ECS field-mapping preset; unblocks air-gapped ingest.
- **`LEEFParser`** (`GAP-C3`) — IBM QRadar historical file analysis.
- **CEF timestamp resolution chain** (`GAP-H1`) — `rt=` → `start=` → `end=` → `deviceCustomDate1=` → syslog header → `now()` with an `is_synthetic_timestamp` flag.
- **Deeper SIEM `normalise()`** (`GAP-H3`) and **ArcSight / Sumo Logic connectors** (`GAP-H4`).
- **Windows EVTX parser** — EventID 4624 → `suspicious_login`, 4688 → `abnormal_process_execution`, 4768/4769 → `credential_dump`, 7045 → `privilege_escalation`.
- **NLQ structured-parser fix** (`NLQ-001`).

**Off-limits without prior maintainer discussion:** changes to core consensus logic, anything that weakens or bypasses the `ApprovalQueue` for high-risk actions, and new model integrations not evaluated for consensus-weight compatibility. The safety architecture is the product.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `acda: command not found` | venv inactive or `pip install -e .` not run. `source .venv/bin/activate && pip install -e .` |
| `consensus.passed=False` for everything | Usually `ANTHROPIC_API_KEY` missing → reasoning returns low placeholder scores. Verify egress: `curl -I https://api.anthropic.com`. |
| CEF parse returns 0 records | File has no `CEF:`-prefixed lines, or non-UTF-8 encoding. `head -5 file.cef`. |
| Everything shows `vendor='unknown'` | Vendor string isn't in `_VENDOR_MAP`. Accepted: `crowdstrike`, `palo alto networks`, `paloaltonetworks`, `okta`. Add mappings for others. |
| Adapters show simulated data despite credentials | `register_simulated_adapters()` ran before `register_all_adapters()`. Reverse the order. |
| UEBA baselines reset on restart | `REDIS_URL` unset. `docker run -d -p 6379:6379 redis:alpine && export REDIS_URL=redis://localhost:6379/0`. |

---

## License

Cyphora — both **ACDA-SDK** and **Cyphora-S1** — is released under the **MIT License**. See [`LICENSE`](./LICENSE) for the full text.

MIT is about as permissive as open-source licensing gets. You are free to use, copy, modify, merge, publish, distribute, sublicense, and sell the software — including **inside a closed-source commercial product or a paid SaaS offering** — for any purpose, commercial or non-commercial, with no royalty and no separate commercial license required. The only condition is that you preserve the copyright notice and the MIT permission notice in copies or substantial portions of the software. The software is provided "as is," without warranty of any kind.

> Running this in production, embedding it, or shipping a product on top of it are all expressly permitted by the license. **Commercial support, priority fixes, and integration help are available** from YouSource.ai for teams that want them — see [Contact](#contact) — but they are a service offering, not a licensing requirement.

---

## Contributing

We welcome contributions. Before writing code, please **open a GitHub issue** describing the change and await maintainer acknowledgment — this prevents duplicate effort and aligns on approach up front. Standards for every PR:

- Python 3.11+ syntax throughout; type annotations on all public functions; Pydantic v2 models for all data structures.
- `asyncio`-native implementations for all I/O; no bare `except:` clauses.
- New ingestion paths must mirror the existing pipeline so they are operationally interchangeable with `cef_parser.py` / `cef_adapters.py`.
- Any YAML consensus weights must sum to exactly `1.0`.
- **Tests are required** — new parsers must cover vendor identification, event-type mapping, timestamp parsing, and field extraction. Add to `tests/`.

See the [contribution priorities](#roadmap--contribution-priorities) for the highest-impact work, and [`CHANGES.md`](./CHANGES.md) for version history. By submitting a pull request, you agree that your contribution is licensed under the same MIT license as the project.

---

## Contact

| Purpose | Contact |
|---|---|
| **Beta evaluation access** (enterprise / government) | **info@yousource.ai** — include org, deployment environment (on-prem / private cloud / air-gapped), current SIEMs, and daily alert volume |
| General inquiries | john@yousource.ai |
| Commercial support & integration services | john@yousource.ai |
| Security disclosure | see [`SECURITY.md`](./SECURITY.md) — subject `Security Disclosure — [brief description]` |
| Website | [yousource.ai](https://yousource.ai) |

---

<div align="center">

**An open-source industry contribution from [YouSource.ai](https://yousource.ai).**

Cyphora-S1 v2.6 · ACDA-SDK v1.1 · Public Beta · MIT License · Copyright © 2026 YouSource.ai

*Technical verification write-up by John Chiong. Verified run: May 25 – June 2, 2026. Figures independently confirmed against scenario and agent log files.*

</div>
