"""
ACDA-SDK — Agent Definition Framework Schemas
Pydantic v2 models that represent every node in the ADF YAML/JSON spec.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────


class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConsensusMethod(str, Enum):
    WEIGHTED_VOTE = "weighted_vote"
    MAJORITY_VOTE = "majority_vote"
    UNANIMOUS = "unanimous"
    QUORUM = "quorum"


class ApprovalLevel(str, Enum):
    NONE = "none"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


class RuntimeType(str, Enum):
    CONTAINER = "container"
    PROCESS = "process"
    SERVERLESS = "serverless"


class DataSourceType(str, Enum):
    ENDPOINT_LOGS = "endpoint_logs"
    NETWORK_LOGS = "network_logs"
    IDENTITY_LOGS = "identity_logs"
    FILE_ACTIVITY_LOGS = "file_activity_logs"
    CLOUD_LOGS = "cloud_logs"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY_SCAN = "vulnerability_scan"


class EventType(str, Enum):
    ABNORMAL_PROCESS_EXECUTION = "abnormal_process_execution"
    SUSPICIOUS_LOGIN = "suspicious_login"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONFIRMED_ATTACK = "confirmed_attack"
    ABNORMAL_FILE_ENCRYPTION = "abnormal_file_encryption"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_DUMP = "credential_dump"
    NETWORK_SCAN = "network_scan"
    ANOMALY_DETECTED = "anomaly_detected"


class ActionType(str, Enum):
    GENERATE_INCIDENT_REPORT = "generate_incident_report"
    NOTIFY_SOC = "notify_soc"
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    CREATE_THREAT_ALERT = "create_threat_alert"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    REVOKE_TOKEN = "revoke_token"
    SNAPSHOT_MEMORY = "snapshot_memory"


# ─────────────────────────────────────────────
# Sub-models
# ─────────────────────────────────────────────


class AgentMetadata(BaseModel):
    description: str
    priority: Priority = Priority.MEDIUM
    owner: str = "security_platform"
    tags: List[str] = Field(default_factory=list)
    version_notes: Optional[str] = None


class ScheduleTrigger(BaseModel):
    interval: str  # e.g. "10m", "1h", "30s"
    start_immediately: bool = True

    @field_validator("interval")
    @classmethod
    def validate_interval(cls, v: str) -> str:
        import re

        if not re.match(r"^\d+[smhd]$", v):
            raise ValueError(f"Invalid interval format '{v}'. Use: 30s, 10m, 1h, 1d")
        return v


class EventTrigger(BaseModel):
    event_types: List[Union[EventType, str]] = Field(default_factory=list)
    filter_expression: Optional[str] = None
    min_severity: Optional[str] = None


class TriggerConfig(BaseModel):
    event_types: Optional[List[Union[EventType, str]]] = None
    schedule: Optional[ScheduleTrigger] = None
    filter_expression: Optional[str] = None

    @model_validator(mode="after")
    def at_least_one_trigger(self) -> "TriggerConfig":
        if not self.event_types and not self.schedule:
            raise ValueError(
                "Agent must have at least one trigger: event_types or schedule"
            )
        return self


class AnomalyQuery(BaseModel):
    type: str
    dataset: str
    lookback: str = "1h"
    threshold: Optional[float] = None


class DataCollectionConfig(BaseModel):
    sources: Optional[List[Union[DataSourceType, str]]] = None
    time_window: str = "30m"
    query: Optional[AnomalyQuery] = None
    max_records: int = 10_000
    enrich_with_threat_intel: bool = False

    @field_validator("time_window")
    @classmethod
    def validate_time_window(cls, v: str) -> str:
        import re

        if not re.match(r"^\d+[smhd]$", v):
            raise ValueError(f"Invalid time_window format '{v}'")
        return v


class ReasoningConfig(BaseModel):
    ai_models: List[str] = Field(default_factory=list)
    task: str
    system_prompt: Optional[str] = None
    temperature: float = Field(default=0.2, ge=0.0, le=1.0)
    max_tokens: int = Field(default=2048, ge=64)
    chain_of_thought: bool = True


class ConsensusConfig(BaseModel):
    method: ConsensusMethod = ConsensusMethod.WEIGHTED_VOTE
    threshold: float = Field(default=0.80, ge=0.0, le=1.0)
    weights: Optional[Dict[str, float]] = None
    min_models_required: int = Field(default=2, ge=1)
    timeout_seconds: int = Field(default=30, ge=5)

    @model_validator(mode="after")
    def validate_weights(self) -> "ConsensusConfig":
        if self.weights:
            total = sum(self.weights.values())
            if abs(total - 1.0) > 0.001:
                raise ValueError(f"Consensus weights must sum to 1.0, got {total:.3f}")
        return self


class SafetyControls(BaseModel):
    max_runtime: str = "120s"
    escalation_required: bool = False
    approval_required: Optional[Union[ApprovalLevel, str]] = ApprovalLevel.NONE
    rate_limit_per_minute: int = Field(default=60, ge=1)
    dry_run_mode: bool = False
    kill_switch_enabled: bool = True
    audit_all_actions: bool = True


class GraphQueryConstraints(BaseModel):
    time_window: str = "10m"
    unusual_destination: bool = False
    min_hop_count: Optional[int] = None
    max_hop_count: Optional[int] = None


class GraphQueryConfig(BaseModel):
    name: str
    pattern: str
    constraints: GraphQueryConstraints = Field(default_factory=GraphQueryConstraints)


class ActionIntegration(BaseModel):
    integration: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
    retry_count: int = 3


# ─────────────────────────────────────────────
# Top-level Agent Definition
# ─────────────────────────────────────────────


class AgentDefinition(BaseModel):
    """
    Root model for a complete ADF agent definition.
    Parsed directly from YAML or JSON agent spec files.
    """

    # FIX: Replaced deprecated `class Config` with Pydantic v2 `model_config`.
    # `class Config: use_enum_values = True` still worked in v2 as a fallback,
    # but raised deprecation warnings and could break in a future Pydantic release.
    model_config = ConfigDict(use_enum_values=True)

    name: str = Field(..., min_length=3, max_length=128)
    version: str = "1.0"
    metadata: AgentMetadata = Field(
        default_factory=lambda: AgentMetadata(description="Cyber defense agent")
    )
    triggers: TriggerConfig
    data_collection: DataCollectionConfig = Field(default_factory=DataCollectionConfig)
    reasoning: Optional[ReasoningConfig] = None
    consensus_validation: Optional[ConsensusConfig] = None
    actions: List[Union[ActionType, str]] = Field(default_factory=list)
    safety_controls: SafetyControls = Field(default_factory=SafetyControls)
    graph_queries: Optional[List[GraphQueryConfig]] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        import re

        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", v):
            raise ValueError(
                f"Agent name '{v}' must be alphanumeric/underscore, starting with a letter"
            )
        return v


class AdfDocument(BaseModel):
    """Wraps a single 'agent:' top-level YAML document."""

    agent: AgentDefinition


# ─────────────────────────────────────────────
# Runtime / Execution Models
# ─────────────────────────────────────────────


class SecurityEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    source_host: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    severity: str = "medium"
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class CollectedData(BaseModel):
    event: SecurityEvent
    logs: List[Dict[str, Any]] = Field(default_factory=list)
    graph_nodes: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intel: List[Dict[str, Any]] = Field(default_factory=list)
    collection_time_ms: float = 0.0


class ModelScore(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_id: str
    score: float = Field(..., ge=0.0, le=1.0)
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: Optional[str] = None
    latency_ms: float = 0.0


class ReasoningResult(BaseModel):
    scores: List[ModelScore]
    task: str
    raw_outputs: Dict[str, Any] = Field(default_factory=dict)


class ConsensusResult(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    passed: bool
    score: float
    threshold: float
    method: str
    model_votes: List[ModelScore]
    explanation: str


class ActionResult(BaseModel):
    action: str
    success: bool
    timestamp: str
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    dry_run: bool = False


class AgentExecutionReport(BaseModel):
    agent_name: str
    execution_id: str
    event: SecurityEvent
    data_collected: bool
    reasoning_result: Optional[ReasoningResult] = None
    consensus_result: Optional[ConsensusResult] = None
    actions_taken: List[ActionResult] = Field(default_factory=list)
    duration_ms: float = 0.0
    status: str = "completed"
    errors: List[str] = Field(default_factory=list)


# ─────────────────────────────────────────────
# Orchestrator / Registry Models
# ─────────────────────────────────────────────


class OrchestratorConfig(BaseModel):
    max_concurrent_agents: int = Field(default=200, ge=1)
    priority_queue: bool = True
    retry_policy_max_retries: int = 3
    timeout_seconds: int = 120


class DeploymentConfig(BaseModel):
    runtime: RuntimeType = RuntimeType.CONTAINER
    replicas: int = Field(default=3, ge=1)
    cpu: float = Field(default=1.0, ge=0.1)
    memory_gb: float = Field(default=2.0, ge=0.25)
    namespace: str = "cyber-defense"


class AgentRegistryEntry(BaseModel):
    agent_name: str
    version: str
    definition_path: str
    enabled: bool = True
    deployment: Optional[DeploymentConfig] = None
