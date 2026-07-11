"""
Cyphora-S1 — Agent Implementations
====================================
Python implementations of the four Cyphora-S1 YAML-defined agents.
Unlike the vanilla ACDA-SDK agents in agents.py, these agents integrate
directly with the Cyphora-S1 engine layer (cyphora_s1/*) to deliver
the full AI-native SIEM feature set.

Architecture note
-----------------
cyphora_s1 engines are *service classes*, not agents.  Agents drive the
ACDA-SDK event loop (trigger → collect → reason → consensus → act).
Engines are called by agents at appropriate points in that loop and
return enriched output (AttackIntelligence, UEBAReport, etc.) that the
agent then stores in the AgentExecutionReport and uses to decide actions.

Agents
------
  CyphoraInvestigationAgent   Primary threat-investigation agent
  CyphoraUEBAAgent            Behavioral baseline maintenance + anomaly scoring
  CyphoraComplianceAgent      Evidence collection + framework report generation
  CyphoraNLQueryAgent         Natural language query interface

Usage
-----
    from acda.agents.cyphora_agents import (
        CyphoraInvestigationAgent,
        CyphoraUEBAAgent,
        CyphoraComplianceAgent,
        CyphoraNLQueryAgent,
    )
    from cyphora_s1.cyphora_ingest import register_all_adapters
    from acda.orchestrator.orchestrator import AgentOrchestrator

    register_all_adapters()        # must be called before agents are used

    orchestrator = AgentOrchestrator()
    orchestrator.register_agents([
        CyphoraInvestigationAgent(),
        CyphoraUEBAAgent(),
        CyphoraComplianceAgent(),
        CyphoraNLQueryAgent(),
    ])
    await orchestrator.start()
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, List, Optional

import structlog

from acda.runtime.base_agent import BaseAgent
from acda.runtime.data_collector import DataCollector
from acda.runtime.reasoning_engine import ReasoningEngine
from acda.runtime.consensus_validator import ConsensusValidator
from acda.runtime.action_executor import ActionExecutor
from acda.models.schemas import (
    SecurityEvent,
    CollectedData,
    ReasoningResult,
    ConsensusResult,
    AgentExecutionReport,
    ActionResult,
)

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════
# 1. CyphoraInvestigationAgent
#    Source YAML: agent_definitions/cyphora_investigation_agent.yaml
#
#    Primary Cyphora-S1 agent. Extends the vanilla InvestigationAgent
#    with MITRE ATT&CK mapping, UEBA scoring, kill-chain building,
#    plain-English incident reporting, and automated playbook execution.
# ═══════════════════════════════════════════════════════════════


class CyphoraInvestigationAgent(BaseAgent):
    """
    Cyphora-S1 AI Threat Investigator.

    Triggers on any high-confidence security event (including ueba_anomaly
    events emitted by CyphoraUEBAAgent).  Collects multi-source telemetry,
    runs a 3-model AI ensemble, maps findings to MITRE ATT&CK, builds a
    kill chain, generates a plain-English incident report, and executes
    the appropriate automated response playbook.

    Engine dependencies (from cyphora_s1/):
      - ThreatInvestigator  (mitre_mapper)   MITRE mapping + report
      - UEBAEngine          (ueba_engine)    Behavioural context
      - PlaybookEngine      (playbook_engine) Automated response

    Priority : critical
    Owner    : cyphora_s1_platform
    Version  : 2.0
    """

    TRIGGERS: List[str] = [
        "suspicious_login",
        "abnormal_process_execution",
        "privilege_escalation",
        "credential_dump",
        "lateral_movement",
        "data_exfiltration",
        "abnormal_file_encryption",
        "anomaly_detected",
        "confirmed_attack",
        "ueba_anomaly",
    ]

    DATA_SOURCES: List[str] = [
        "endpoint_logs",
        "network_logs",
        "identity_logs",
        "file_activity_logs",
        "cloud_logs",
        "aws_cloudtrail",
        "azure_ad",
        "okta",
        "crowdstrike",
        "threat_intel",
    ]
    TIME_WINDOW: str = "30m"

    AI_MODELS: List[str] = ["claude-sonnet-4-6", "claude-opus-4-6", "gpt-4o"]
    REASONING_TASK: str = (
        "Analyse the security telemetry for evidence of a cyber attack. "
        "Identify the attack type, affected systems, attacker TTPs, and the "
        "full attack chain. Map findings to MITRE ATT&CK. Score threat "
        "confidence 0.0-1.0. Be conservative — only high-confidence threats "
        "should score above 0.8."
    )
    REASONING_TEMPERATURE: float = 0.15
    REASONING_MAX_TOKENS: int = 4096

    CONSENSUS_METHOD: str = "weighted_vote"
    CONSENSUS_THRESHOLD: float = 0.75
    CONSENSUS_WEIGHTS: Dict[str, float] = {
        "claude-sonnet-4-6": 0.40,
        "claude-opus-4-6": 0.35,
        "gpt-4o": 0.25,
    }
    MIN_MODELS_REQUIRED: int = 2

    ACTIONS: List[str] = [
        "generate_incident_report",
        "notify_soc",
        "create_threat_alert",
    ]

    MAX_RUNTIME: str = "180s"
    APPROVAL_REQUIRED: str = "none"
    DRY_RUN_MODE: bool = False

    def __init__(
        self,
        ueba_redis_url: Optional[str] = None,
        playbook_dry_run: bool = False,
        playbook_approval_mode: str = "auto",
    ) -> None:
        super().__init__(name="CyphoraInvestigationAgent", version="2.0")

        # ── ACDA-SDK core components ───────────────────────────
        self._collector = DataCollector(
            sources=self.DATA_SOURCES,
            time_window=self.TIME_WINDOW,
        )
        self._reasoner = ReasoningEngine(
            models=self.AI_MODELS,
            task=self.REASONING_TASK,
            temperature=self.REASONING_TEMPERATURE,
        )
        self._consensus = ConsensusValidator(
            method=self.CONSENSUS_METHOD,
            threshold=self.CONSENSUS_THRESHOLD,
            weights=self.CONSENSUS_WEIGHTS,
        )
        self._executor = ActionExecutor(
            actions=self.ACTIONS,
            approval_required=self.APPROVAL_REQUIRED,
            dry_run=self.DRY_RUN_MODE,
        )

        # ── Cyphora-S1 engine layer ────────────────────────────
        # Deferred imports so the SDK core can run without cyphora_s1
        from cyphora_s1.mitre_mapper import ThreatInvestigator
        from cyphora_s1.ueba_engine import UEBAEngine
        from cyphora_s1.playbook_engine import PlaybookEngine

        self._threat_investigator = ThreatInvestigator(llm_model="claude-sonnet-4-6")
        self._ueba_engine = UEBAEngine(redis_url=ueba_redis_url)
        # approval_mode defaults to "auto" but is overridden by the
        # CYPHORA_PLAYBOOK_APPROVAL_MODE env var inside PlaybookEngine.
        # Set it to "auto_approve" for unattended simulations so
        # approval-gated steps run immediately instead of blocking ~30s each.
        self._playbook_engine = PlaybookEngine(
            dry_run=playbook_dry_run,
            approval_mode=playbook_approval_mode,
        )

    # ── ACDA-SDK pipeline overrides ────────────────────────────

    async def collect_data(self, event: SecurityEvent) -> CollectedData:
        return await self._collector.collect(event)

    async def analyze(self, data: CollectedData) -> ReasoningResult:
        return await self._reasoner.run(data)

    async def validate_consensus(self, reasoning: ReasoningResult) -> ConsensusResult:
        return await self._consensus.validate(reasoning)

    async def execute_actions(
        self, event: SecurityEvent, consensus: ConsensusResult
    ) -> List[ActionResult]:
        if not consensus.passed:
            logger.info(
                "consensus_not_reached",
                agent=self.name,
                score=consensus.score,
            )
            return []
        return await self._executor.run(event)

    # ── Main run — Cyphora-S1 extended pipeline ────────────────

    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        """
        Extended ACDA-SDK pipeline enriched with Cyphora-S1 engines.

        Pipeline:
          1. Collect multi-source telemetry
          2. Run 3-model AI ensemble + consensus
          3. UEBA behavioural analysis (parallel with reasoning)
          4. MITRE ATT&CK mapping + kill chain + incident report
          5. Select and execute automated response playbook
          6. Package all outputs into AgentExecutionReport
        """
        execution_id = str(uuid.uuid4())
        start = time.perf_counter()
        report = AgentExecutionReport(
            agent_name=self.name,
            execution_id=execution_id,
            event=event,
            data_collected=False,
        )

        try:
            # 1. Data collection
            data = await self.collect_data(event)
            report.data_collected = True

            # 2. Multi-model reasoning + consensus (and UEBA in parallel)
            reasoning, ueba_report = await asyncio.gather(
                self.analyze(data),
                self._ueba_engine.analyze(event, data),
                return_exceptions=True,
            )

            if isinstance(reasoning, Exception):
                raise reasoning  # surface reasoning failures immediately

            report.reasoning_result = reasoning

            consensus = await self.validate_consensus(reasoning)
            report.consensus_result = consensus

            # 3. MITRE ATT&CK mapping + kill chain + plain-English report
            #    (run regardless of consensus — intelligence is always useful)
            attack_intel = await self._threat_investigator.investigate(
                event=event,
                data=data,
                reasoning=reasoning,
                consensus_score=consensus.score,
            )
            # Attach to report extras for downstream consumers
            report.errors  # ensure extras dict path works
            if not hasattr(report, "extras"):
                report.__dict__["extras"] = {}
            report.__dict__["extras"]["attack_intelligence"] = attack_intel

            # Log UEBA findings. Tier by severity so the high-volume
            # low/medium band stays at info and only high/critical
            # anomalies surface at warning level for alerting.
            if not isinstance(ueba_report, Exception) and ueba_report.is_anomalous:
                report.__dict__["extras"]["ueba_report"] = ueba_report
                _log = (
                    logger.warning
                    if ueba_report.risk_label in ("high", "critical")
                    else logger.info
                )
                _log(
                    "ueba_anomaly_detected",
                    entity=ueba_report.entity_id,
                    risk=ueba_report.risk_label,
                    score=f"{ueba_report.risk_score:.2f}",
                )

            # 4. Execute actions if consensus reached
            if consensus.passed:
                actions = await self.execute_actions(event, consensus)
                report.actions_taken = actions

                # 5. Automated playbook execution
                playbook_name = await self._playbook_engine.select_playbook(event)
                if playbook_name:
                    playbook_result = await self._playbook_engine.run_playbook(
                        playbook_name, event
                    )
                    report.__dict__["extras"]["playbook_result"] = playbook_result
                    logger.info(
                        "playbook_executed",
                        playbook=playbook_name,
                        status=playbook_result.status,
                        steps=f"{playbook_result.steps_executed}/{playbook_result.steps_total}",
                    )

            report.status = "completed"

        except Exception as exc:
            report.status = "error"
            report.errors.append(str(exc))
            logger.error(
                "cyphora_investigation_error",
                agent=self.name,
                error=str(exc),
                exc_info=True,
            )
        finally:
            report.duration_ms = (time.perf_counter() - start) * 1000

        return report


# ═══════════════════════════════════════════════════════════════
# 2. CyphoraUEBAAgent
#    Source YAML: agent_definitions/cyphora_ueba_agent.yaml
#
#    Runs on a 1-hour schedule and on-demand for behaviour-related
#    events.  Maintains rolling statistical baselines for all users
#    and entities, scores deviations, and emits ueba_anomaly events
#    when risk_score >= 0.70 (which then trigger CyphoraInvestigationAgent).
# ═══════════════════════════════════════════════════════════════


class CyphoraUEBAAgent(BaseAgent):
    """
    Cyphora-S1 UEBA Agent.

    Maintains behavioral baselines for users, hosts, and service accounts.
    Emits ueba_anomaly events for entities whose risk_score exceeds the
    ANOMALY_THRESHOLD (default 0.70) so that CyphoraInvestigationAgent
    can investigate further.

    Engine dependencies (from cyphora_s1/):
      - UEBAEngine  (ueba_engine)  Baseline storage + anomaly scoring

    Priority : high
    Owner    : cyphora_s1_platform
    Version  : 1.0
    """

    TRIGGERS: List[str] = [
        "suspicious_login",
        "privilege_escalation",
        "data_exfiltration",
        "anomaly_detected",
        "lateral_movement",
    ]

    DATA_SOURCES: List[str] = [
        "identity_logs",
        "endpoint_logs",
        "network_logs",
        "file_activity_logs",
        "okta",
        "azure_ad",
    ]
    TIME_WINDOW: str = "24h"

    AI_MODELS: List[str] = ["claude-sonnet-4-6", "gpt-4o"]
    REASONING_TASK: str = (
        "Analyse user and entity behavior for anomalies. Compare observed "
        "activity against the entity's baseline. Identify deviations that may "
        "indicate insider threat, credential compromise, or lateral movement. "
        "Score each anomaly 0.0-1.0 by severity."
    )
    REASONING_TEMPERATURE: float = 0.1

    CONSENSUS_METHOD: str = "weighted_vote"
    CONSENSUS_THRESHOLD: float = 0.70
    CONSENSUS_WEIGHTS: Dict[str, float] = {
        "claude-sonnet-4-6": 0.55,
        "gpt-4o": 0.45,
    }

    ACTIONS: List[str] = [
        "create_threat_alert",
        "notify_soc",
    ]

    # Risk score above which a ueba_anomaly event is emitted
    ANOMALY_THRESHOLD: float = 0.70

    MAX_RUNTIME: str = "120s"
    APPROVAL_REQUIRED: str = "none"
    DRY_RUN_MODE: bool = False

    def __init__(self, redis_url: Optional[str] = None) -> None:
        super().__init__(name="CyphoraUEBAAgent", version="1.0")

        self._collector = DataCollector(
            sources=self.DATA_SOURCES,
            time_window=self.TIME_WINDOW,
        )
        self._reasoner = ReasoningEngine(
            models=self.AI_MODELS,
            task=self.REASONING_TASK,
            temperature=self.REASONING_TEMPERATURE,
        )
        self._consensus = ConsensusValidator(
            method=self.CONSENSUS_METHOD,
            threshold=self.CONSENSUS_THRESHOLD,
            weights=self.CONSENSUS_WEIGHTS,
        )
        self._executor = ActionExecutor(
            actions=self.ACTIONS,
            approval_required=self.APPROVAL_REQUIRED,
            dry_run=self.DRY_RUN_MODE,
        )

        from cyphora_s1.ueba_engine import UEBAEngine

        self._ueba_engine = UEBAEngine(redis_url=redis_url)

    async def collect_data(self, event: SecurityEvent) -> CollectedData:
        return await self._collector.collect(event)

    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        """
        UEBA pipeline:
          1. Collect identity + endpoint telemetry
          2. Run UEBAEngine.analyze() — scores behavioral deviations
          3. If risk_score >= ANOMALY_THRESHOLD, run AI reasoning + consensus
          4. Execute alert + baseline-update actions
          5. Log ueba_anomaly for downstream investigation
        """
        execution_id = str(uuid.uuid4())
        start = time.perf_counter()
        report = AgentExecutionReport(
            agent_name=self.name,
            execution_id=execution_id,
            event=event,
            data_collected=False,
        )

        try:
            data = await self._collector.collect(event)
            report.data_collected = True

            # Core UEBA scoring — does not need LLM consensus
            ueba_report = await self._ueba_engine.analyze(event, data)

            if not hasattr(report, "extras"):
                report.__dict__["extras"] = {}
            report.__dict__["extras"]["ueba_report"] = ueba_report

            if ueba_report.is_anomalous:
                # Tier by severity: low/medium at info, high/critical at warning.
                _log = (
                    logger.warning
                    if ueba_report.risk_label in ("high", "critical")
                    else logger.info
                )
                _log(
                    "ueba_anomaly",
                    entity=ueba_report.entity_id,
                    risk=ueba_report.risk_label,
                    score=f"{ueba_report.risk_score:.2f}",
                    anomalies=len(ueba_report.anomalies),
                )

                # LLM reasoning for explanation and recommendation
                reasoning = await self._reasoner.run(data)
                report.reasoning_result = reasoning

                consensus = await self._consensus.validate(reasoning)
                report.consensus_result = consensus

                if consensus.passed:
                    actions = await self._executor.run(event)
                    report.actions_taken = actions

            report.status = "completed"

        except Exception as exc:
            report.status = "error"
            report.errors.append(str(exc))
            logger.error(
                "ueba_agent_error",
                agent=self.name,
                error=str(exc),
                exc_info=True,
            )
        finally:
            report.duration_ms = (time.perf_counter() - start) * 1000

        return report


# ═══════════════════════════════════════════════════════════════
# 3. CyphoraComplianceAgent
#    Source YAML: agent_definitions/cyphora_compliance_agent.yaml
#
#    Scheduled weekly.  Collects 90 days of telemetry from all connected
#    sources and generates compliance evidence reports for all five
#    frameworks in parallel.
# ═══════════════════════════════════════════════════════════════


class CyphoraComplianceAgent(BaseAgent):
    """
    Cyphora-S1 Compliance Evidence Agent.

    Runs on a weekly schedule (or on-demand via compliance_check events).
    Collects 90 days of telemetry from all connected sources and invokes
    ComplianceEngine to produce SOC 2, ISO 27001, PCI-DSS, HIPAA, and
    NIS2 evidence packages — each in parallel.

    Engine dependencies (from cyphora_s1/):
      - ComplianceEngine  (compliance_engine)  Evidence collection + report gen

    Priority : medium
    Owner    : cyphora_s1_platform
    Version  : 1.0
    """

    TRIGGERS: List[str] = ["compliance_check"]

    DATA_SOURCES: List[str] = [
        "identity_logs",
        "endpoint_logs",
        "network_logs",
        "aws_cloudtrail",
        "azure_ad",
        "okta",
        "github_audit",
        "gcp_audit",
        "threat_intel",
    ]
    TIME_WINDOW: str = "2160h"  # 90 days

    AI_MODELS: List[str] = ["claude-sonnet-4-6"]
    REASONING_TASK: str = (
        "Review collected security logs and identify which compliance controls "
        "are satisfied by the available evidence. Flag controls with insufficient "
        "evidence as gaps. Provide specific recommendations for closing each gap."
    )
    REASONING_TEMPERATURE: float = 0.1

    CONSENSUS_METHOD: str = "majority_vote"
    CONSENSUS_THRESHOLD: float = 0.60

    ACTIONS: List[str] = ["compliance_report", "notify_soc", "generate_incident_report"]

    LOOKBACK_DAYS: int = 90

    MAX_RUNTIME: str = "600s"
    APPROVAL_REQUIRED: str = "none"
    DRY_RUN_MODE: bool = False

    def __init__(self, lookback_days: int = 90) -> None:
        super().__init__(name="CyphoraComplianceAgent", version="1.0")
        self.LOOKBACK_DAYS = lookback_days

        self._collector = DataCollector(
            sources=self.DATA_SOURCES,
            time_window=self.TIME_WINDOW,
        )
        self._executor = ActionExecutor(
            actions=self.ACTIONS,
            approval_required=self.APPROVAL_REQUIRED,
            dry_run=self.DRY_RUN_MODE,
        )

        from cyphora_s1.compliance_engine import ComplianceEngine

        self._compliance_engine = ComplianceEngine()

    async def collect_data(self, event: SecurityEvent) -> CollectedData:
        # ComplianceEngine manages its own collection and persistence.
        return CollectedData(event=event)

    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        """
        Compliance pipeline:
          1. Trigger ComplianceEngine for all 5 frameworks in parallel
          2. Log per-framework compliance percentages
          3. Execute notify_soc action with summary
        """
        execution_id = str(uuid.uuid4())
        start = time.perf_counter()
        report = AgentExecutionReport(
            agent_name=self.name,
            execution_id=execution_id,
            event=event,
            data_collected=False,
        )

        try:
            # The ComplianceEngine manages its own data collection
            # internally via DataCollector — no need to pre-collect here.
            report.data_collected = True

            all_reports = await self._compliance_engine.generate_all_frameworks(
                lookback_days=self.LOOKBACK_DAYS
            )

            if not hasattr(report, "extras"):
                report.__dict__["extras"] = {}
            report.__dict__["extras"]["compliance_reports"] = all_reports

            for framework, fw_report in all_reports.items():
                logger.info(
                    "compliance_report_generated",
                    framework=framework,
                    compliance_pct=f"{fw_report.compliance_percentage:.1f}%",
                    controls_satisfied=fw_report.controls_satisfied,
                    controls_total=fw_report.controls_total,
                )

            actions = await self._executor.run(event)
            report.actions_taken = actions
            report.status = "completed"

        except Exception as exc:
            report.status = "error"
            report.errors.append(str(exc))
            logger.error(
                "compliance_agent_error",
                agent=self.name,
                error=str(exc),
                exc_info=True,
            )
        finally:
            report.duration_ms = (time.perf_counter() - start) * 1000

        return report


# ═══════════════════════════════════════════════════════════════
# 4. CyphoraNLQueryAgent
#    Source YAML: agent_definitions/cyphora_nl_query_agent.yaml
#
#    Triggered by nl_query events (generated by the query interface or
#    dashboard).  Parses the natural language question from the event's
#    raw_data field and returns formatted results via NLQueryEngine.
# ═══════════════════════════════════════════════════════════════


class CyphoraNLQueryAgent(BaseAgent):
    """
    Cyphora-S1 Natural Language Query Agent.

    Responds to nl_query events by parsing the question from
    event.raw_data, executing the query against available data
    sources, and returning formatted results.  Powers the
    "Ask Cyphora" interface in the SOC dashboard.

    Engine dependencies (from cyphora_s1/):
      - NLQueryEngine  (nl_query_engine)  NL → query intent → results

    Priority : medium
    Owner    : cyphora_s1_platform
    Version  : 1.0
    """

    TRIGGERS: List[str] = ["nl_query"]

    DATA_SOURCES: List[str] = [
        "endpoint_logs",
        "identity_logs",
        "network_logs",
        "file_activity_logs",
        "cloud_logs",
        "aws_cloudtrail",
        "azure_ad",
        "okta",
    ]
    TIME_WINDOW: str = "24h"  # overridden dynamically by NLQueryEngine

    AI_MODELS: List[str] = ["claude-sonnet-4-6"]

    CONSENSUS_METHOD: str = "majority_vote"
    CONSENSUS_THRESHOLD: float = 0.50

    ACTIONS: List[str] = ["nl_query_execute"]

    MAX_RUNTIME: str = "60s"
    APPROVAL_REQUIRED: str = "none"
    DRY_RUN_MODE: bool = False

    def __init__(self) -> None:
        super().__init__(name="CyphoraNLQueryAgent", version="1.0")

        self._executor = ActionExecutor(
            actions=self.ACTIONS,
            approval_required=self.APPROVAL_REQUIRED,
            dry_run=self.DRY_RUN_MODE,
        )

        from cyphora_s1.nl_query_engine import NLQueryEngine

        self._nl_engine = NLQueryEngine(llm_model="claude-sonnet-4-6")

    async def collect_data(self, event: SecurityEvent) -> CollectedData:
        # NLQueryEngine performs its own query-time collection.
        return CollectedData(event=event)

    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        """
        NL query pipeline:
          1. Extract plain-English question from event.raw_data
          2. Run NLQueryEngine.query() — parse intent, execute, format
          3. Attach formatted results to the report extras
        """
        execution_id = str(uuid.uuid4())
        start = time.perf_counter()
        report = AgentExecutionReport(
            agent_name=self.name,
            execution_id=execution_id,
            event=event,
            data_collected=True,  # NLQueryEngine manages its own collection
        )

        try:
            # Extract the query text from the event
            query_text: str = (
                event.raw_data.get("query", "")
                if isinstance(event.raw_data, dict)
                else str(event.raw_data or "")
            )

            if not query_text:
                raise ValueError("nl_query event missing 'query' key in raw_data")

            nl_result = await self._nl_engine.query(query_text)

            if not hasattr(report, "extras"):
                report.__dict__["extras"] = {}
            report.__dict__["extras"]["nl_query_result"] = nl_result

            logger.info(
                "nl_query_completed",
                records=nl_result.record_count,
                execution_ms=f"{nl_result.execution_time_ms:.0f}",
            )

            report.status = "completed"

        except Exception as exc:
            report.status = "error"
            report.errors.append(str(exc))
            logger.error(
                "nl_query_agent_error",
                agent=self.name,
                error=str(exc),
                exc_info=True,
            )
        finally:
            report.duration_ms = (time.perf_counter() - start) * 1000

        return report
