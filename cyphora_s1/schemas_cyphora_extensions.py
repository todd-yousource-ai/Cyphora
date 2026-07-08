# ─────────────────────────────────────────────────────────────
# PASTE THIS BLOCK INTO acda/models/schemas.py
# Add AFTER the existing imports and BEFORE AgentMetadata
# These extensions add all Cyphora-S1 specific data models.
# ─────────────────────────────────────────────────────────────

# schemas_cyphora_extensions.py
# ──────────────────────────────────────────────────────────────
# Cyphora-S1 additions to ACDA-SDK schemas.py
# Import from this file OR paste directly into schemas.py.
# ──────────────────────────────────────────────────────────────

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


# ── New EventType values (extend EventType enum in schemas.py) ──

CYPHORA_EVENT_TYPES = [
    "nl_query",  # Natural language query pseudo-event
    "compliance_check",  # Compliance evidence collection event
    "ueba_anomaly",  # UEBA-generated anomaly event
    "threat_hunt",  # Scheduled threat hunt result
    "playbook_triggered",  # Playbook auto-execution event
]

# ── New ActionType values (extend ActionType enum in schemas.py) ──

CYPHORA_ACTION_TYPES = [
    "pagerduty_incident",  # Create PagerDuty incident
    "compliance_report",  # Generate compliance evidence report
    "mitre_map",  # Run MITRE ATT&CK mapping
    "nl_query_execute",  # Execute NL query
    "slack_message",  # Post message to Slack channel
    "webhook_notify",  # POST to custom webhook URL
]


# ── Cyphora-S1 specific Pydantic models ────────────────────────


class MITRETechniqueSchema(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    sub_technique: Optional[str] = None
    description: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    mitre_url: Optional[str] = None


class KillChainStepSchema(BaseModel):
    step_number: int
    timestamp: str
    tactic: str
    technique: str
    technique_id: str
    description: str
    source_event: str
    indicators: List[str] = Field(default_factory=list)


class AttackIntelligenceSchema(BaseModel):
    event_id: str
    analysis_timestamp: str
    ttps_identified: List[MITRETechniqueSchema] = Field(default_factory=list)
    kill_chain: List[KillChainStepSchema] = Field(default_factory=list)
    plain_english_report: str = ""
    severity: str
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    recommended_actions: List[str] = Field(default_factory=list)
    mitre_navigator_link: str = ""


class UEBAAnomalySchema(BaseModel):
    feature: str
    observed_value: Any
    baseline_value: Any
    deviation_score: float = Field(ge=0.0, le=1.0)
    explanation: str
    is_critical: bool = False


class UEBAReportSchema(BaseModel):
    entity_id: str
    entity_type: str
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_label: str
    anomalies: List[UEBAAnomalySchema] = Field(default_factory=list)
    baseline_age_days: float = 0.0
    analysis_timestamp: str
    event_id: str
    recommended_investigation: List[str] = Field(default_factory=list)


class ComplianceControlSchema(BaseModel):
    control_id: str
    framework: str
    title: str
    status: str  # satisfied | partial | gap | manual_required
    evidence_count: int = 0
    gap_description: Optional[str] = None
    recommendation: Optional[str] = None


class ComplianceReportSchema(BaseModel):
    report_id: str
    framework: str
    generated_at: str
    period_start: str
    period_end: str
    compliance_percentage: float
    controls_satisfied: int
    controls_total: int
    findings: List[ComplianceControlSchema] = Field(default_factory=list)
    summary: str


class NLQueryIntentSchema(BaseModel):
    data_sources: List[str] = Field(default_factory=list)
    time_window: str = "24h"
    user_filter: Optional[str] = None
    host_filter: Optional[str] = None
    after_hour: Optional[int] = None
    max_results: int = 100
    output_format: str = "table"
    original_query: str = ""
    confidence: float = 0.0
    explanation: str = ""


class PlaybookStepResultSchema(BaseModel):
    step_id: str
    name: str
    action: str
    status: str  # success | failed | skipped | pending_approval
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    dry_run: bool = False
    duration_ms: float = 0.0


class PlaybookResultSchema(BaseModel):
    playbook_name: str
    execution_id: str
    event_id: str
    started_at: str
    completed_at: str
    status: str
    steps_total: int
    steps_executed: int
    steps_skipped: int
    steps_failed: int
    step_results: List[PlaybookStepResultSchema] = Field(default_factory=list)
    duration_ms: float = 0.0
    rollback_available: bool = False


class EnhancedAgentExecutionReport(BaseModel):
    """
    Extends AgentExecutionReport with Cyphora-S1 enrichments.
    Use this instead of AgentExecutionReport for Cyphora-S1 agents.
    """

    # Inherited fields from AgentExecutionReport (replicated for standalone use)
    agent_name: str
    execution_id: str
    event_id: str
    data_collected: bool
    status: str = "completed"
    duration_ms: float = 0.0
    errors: List[str] = Field(default_factory=list)

    # Cyphora-S1 enrichments
    attack_intelligence: Optional[AttackIntelligenceSchema] = None
    ueba_report: Optional[UEBAReportSchema] = None
    compliance_report: Optional[ComplianceReportSchema] = None
    nl_query_result: Optional[str] = None  # formatted markdown output
    playbook_result: Optional[PlaybookResultSchema] = None


# ── Cyphora-S1 specific DataSourceType additions ─────────────
CYPHORA_DATA_SOURCES = [
    "aws_cloudtrail",
    "azure_ad",
    "okta",
    "crowdstrike",
    "palo_alto",
    "github_audit",
    "gcp_audit",
]
