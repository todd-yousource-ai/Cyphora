"""
ACDA-SDK — Generated Agents
All three agent implementations derived from the ADF YAML definitions.

Agents:
  1. InvestigationAgent     — responds to suspicious events, AI analysis
  2. ThreatHuntingAgent     — scheduled proactive threat hunter
  3. ContainmentAgent       — executes containment on confirmed attacks
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
# 1. Investigation Agent
#    Source YAML: investigation_agent.yaml
# ═══════════════════════════════════════════════════════════════


class InvestigationAgent(BaseAgent):
    """
    Investigates suspicious security events.

    Triggers : abnormal_process_execution, suspicious_login, privilege_escalation
    Priority : high
    Owner    : security_platform
    """

    TRIGGERS = [
        "abnormal_process_execution",
        "suspicious_login",
        "privilege_escalation",
    ]

    DATA_SOURCES = ["endpoint_logs", "network_logs", "identity_logs"]
    TIME_WINDOW = "30m"

    AI_MODELS = ["model_A", "model_B", "model_C"]
    REASONING_TASK = "attack_chain_analysis"
    REASONING_TEMPERATURE = 0.2

    CONSENSUS_METHOD = "weighted_vote"
    CONSENSUS_THRESHOLD = 0.80
    CONSENSUS_WEIGHTS: Dict[str, float] = {
        "model_A": 0.40,
        "model_B": 0.35,
        "model_C": 0.25,
    }

    ACTIONS = ["generate_incident_report", "notify_soc"]

    MAX_RUNTIME = "120s"
    APPROVAL_REQUIRED = "none"
    DRY_RUN_MODE = False
    ESCALATION_REQUIRED = False

    def __init__(self) -> None:
        super().__init__(name="InvestigationAgent", version="1.0")
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

    async def collect_data(self, event: SecurityEvent) -> CollectedData:
        logger.info("collecting_data", agent=self.name, event_id=event.event_id)
        start = time.perf_counter()
        data = await self._collector.collect(event)
        data.collection_time_ms = (time.perf_counter() - start) * 1000
        return data

    async def analyze(self, data: CollectedData) -> ReasoningResult:
        logger.info("starting_analysis", agent=self.name, task=self.REASONING_TASK)
        return await self._reasoner.run(data)

    async def validate_consensus(self, reasoning: ReasoningResult) -> ConsensusResult:
        logger.info(
            "validating_consensus", agent=self.name, threshold=self.CONSENSUS_THRESHOLD
        )
        return await self._consensus.validate(reasoning)

    async def execute_actions(
        self, event: SecurityEvent, consensus: Optional[ConsensusResult] = None
    ) -> List[ActionResult]:
        if consensus is not None and not consensus.passed:
            logger.warning(
                "actions_blocked_consensus_failed",
                agent=self.name,
                score=consensus.score,
                threshold=self.CONSENSUS_THRESHOLD,
            )
            return []
        return await self._executor.run(event)

    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        execution_id = str(uuid.uuid4())
        start = time.perf_counter()
        report = AgentExecutionReport(
            agent_name=self.name,
            execution_id=execution_id,
            event=event,
            data_collected=False,
        )
        try:
            data = await self.collect_data(event)
            report.data_collected = True

            reasoning = await self.analyze(data)
            report.reasoning_result = reasoning

            consensus = await self.validate_consensus(reasoning)
            report.consensus_result = consensus

            actions = await self.execute_actions(event, consensus)
            report.actions_taken = actions
            report.status = "completed"

        except Exception as exc:
            report.status = "error"
            report.errors.append(str(exc))
            logger.error("agent_error", agent=self.name, error=str(exc), exc_info=True)
        finally:
            report.duration_ms = (time.perf_counter() - start) * 1000
        return report


# ═══════════════════════════════════════════════════════════════
# 2. Threat Hunting Agent
#    Source YAML: threat_hunting_agent.yaml
# ═══════════════════════════════════════════════════════════════


class ThreatHuntingAgent(BaseAgent):
    """
    Proactively hunts for threats every 10 minutes.

    Triggers : schedule (every 10m)
    Priority : medium
    """

    TRIGGERS: List[str] = []  # No event triggers — schedule-only
    SCHEDULE_INTERVAL = "10m"

    DATA_SOURCES = ["endpoint_logs"]
    TIME_WINDOW = "10m"

    AI_MODELS = ["model_A", "model_B"]
    REASONING_TASK = "anomaly_detection"
    REASONING_TEMPERATURE = 0.1

    CONSENSUS_METHOD = "weighted_vote"
    CONSENSUS_THRESHOLD = 0.75
    CONSENSUS_WEIGHTS: Dict[str, float] = {
        "model_A": 0.55,
        "model_B": 0.45,
    }

    ACTIONS = ["create_threat_alert"]

    MAX_RUNTIME = "90s"
    APPROVAL_REQUIRED = "none"
    DRY_RUN_MODE = False

    def __init__(self) -> None:
        super().__init__(name="ThreatHuntingAgent", version="1.0")
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

    async def collect_data(self, event: SecurityEvent) -> CollectedData:
        return await self._collector.collect(event)

    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        execution_id = str(uuid.uuid4())
        start = time.perf_counter()
        report = AgentExecutionReport(
            agent_name=self.name,
            execution_id=execution_id,
            event=event,
            data_collected=False,
        )
        try:
            data = await self.collect_data(event)
            report.data_collected = True

            reasoning = await self._reasoner.run(data)
            report.reasoning_result = reasoning

            consensus = await self._consensus.validate(reasoning)
            report.consensus_result = consensus

            if consensus.passed:
                actions = await self._executor.run(event)
                report.actions_taken = actions
            else:
                logger.info(
                    "threat_hunt_no_threat",
                    agent=self.name,
                    score=consensus.score,
                )

            report.status = "completed"

        except Exception as exc:
            report.status = "error"
            report.errors.append(str(exc))
        finally:
            report.duration_ms = (time.perf_counter() - start) * 1000
        return report


# ═══════════════════════════════════════════════════════════════
# 3. Containment Agent
#    Source YAML: containment_agent.yaml
# ═══════════════════════════════════════════════════════════════


class ContainmentAgent(BaseAgent):
    """
    Executes automatic containment on confirmed attacks.

    Triggers : confirmed_attack
    Actions  : isolate_host, block_ip, disable_account
    Approval : high_risk (destructive actions require approval)
    """

    TRIGGERS = ["confirmed_attack"]

    DATA_SOURCES = ["endpoint_logs", "network_logs", "identity_logs"]
    TIME_WINDOW = "15m"

    # No AI reasoning — acts on confirmed signals directly
    AI_MODELS: List[str] = []
    REASONING_TASK = "none"

    ACTIONS = ["isolate_host", "block_ip", "disable_account"]

    MAX_RUNTIME = "60s"
    APPROVAL_REQUIRED = "high_risk"
    DRY_RUN_MODE = False
    ESCALATION_REQUIRED = True

    def __init__(self, dry_run: bool = False) -> None:
        super().__init__(name="ContainmentAgent", version="1.0")
        self.DRY_RUN_MODE = dry_run
        self._collector = DataCollector(
            sources=self.DATA_SOURCES,
            time_window=self.TIME_WINDOW,
        )
        self._executor = ActionExecutor(
            actions=self.ACTIONS,
            approval_required=self.APPROVAL_REQUIRED,
            dry_run=self.DRY_RUN_MODE,
        )

    async def collect_data(self, event: SecurityEvent) -> CollectedData:
        return await self._collector.collect(event)

    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        execution_id = str(uuid.uuid4())
        start = time.perf_counter()
        report = AgentExecutionReport(
            agent_name=self.name,
            execution_id=execution_id,
            event=event,
            data_collected=False,
        )
        try:
            logger.warning(
                "containment_triggered",
                agent=self.name,
                event_type=event.event_type,
                host=event.source_host,
                ip=event.source_ip,
                user=event.user,
                dry_run=self.DRY_RUN_MODE,
            )

            # Collect context before acting
            data = await self.collect_data(event)
            report.data_collected = True

            # Execute containment actions (no reasoning needed for confirmed_attack)
            actions = await self._executor.run(event)
            report.actions_taken = actions
            report.status = "completed"

            succeeded = [a for a in actions if a.success]
            failed = [a for a in actions if not a.success]

            logger.info(
                "containment_complete",
                agent=self.name,
                succeeded=len(succeeded),
                failed=len(failed),
            )

        except Exception as exc:
            report.status = "error"
            report.errors.append(str(exc))
            logger.error(
                "containment_error", agent=self.name, error=str(exc), exc_info=True
            )
        finally:
            report.duration_ms = (time.perf_counter() - start) * 1000
        return report


# ═══════════════════════════════════════════════════════════════
# 4. Ransomware Investigation Agent  (bonus — from SDK spec)
# ═══════════════════════════════════════════════════════════════


class RansomwareInvestigationAgent(BaseAgent):
    """
    Specialized investigation agent for ransomware events.

    Triggers : abnormal_file_encryption
    Actions  : isolate_host, notify_soc
    """

    TRIGGERS = ["abnormal_file_encryption"]

    DATA_SOURCES = ["endpoint_logs", "file_activity_logs"]
    TIME_WINDOW = "15m"

    AI_MODELS = ["model_A", "model_B"]
    REASONING_TASK = "ransomware_detection"
    REASONING_TEMPERATURE = 0.1

    CONSENSUS_METHOD = "weighted_vote"
    CONSENSUS_THRESHOLD = 0.85  # higher threshold for destructive containment
    CONSENSUS_WEIGHTS: Dict[str, float] = {"model_A": 0.6, "model_B": 0.4}

    ACTIONS = ["isolate_host", "notify_soc", "generate_incident_report"]

    MAX_RUNTIME = "90s"
    APPROVAL_REQUIRED = "high_risk"
    DRY_RUN_MODE = False

    def __init__(self) -> None:
        super().__init__(name="RansomwareInvestigationAgent", version="1.0")
        self._collector = DataCollector(
            sources=self.DATA_SOURCES, time_window=self.TIME_WINDOW
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

    async def collect_data(self, event: SecurityEvent) -> CollectedData:
        return await self._collector.collect(event)

    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        execution_id = str(uuid.uuid4())
        start = time.perf_counter()
        report = AgentExecutionReport(
            agent_name=self.name,
            execution_id=execution_id,
            event=event,
            data_collected=False,
        )
        try:
            data = await self.collect_data(event)
            report.data_collected = True

            reasoning = await self._reasoner.run(data)
            report.reasoning_result = reasoning

            consensus = await self._consensus.validate(reasoning)
            report.consensus_result = consensus

            if consensus.passed:
                logger.warning(
                    "ransomware_confirmed_executing_containment",
                    agent=self.name,
                    host=event.source_host,
                    consensus_score=consensus.score,
                )
                actions = await self._executor.run(event)
                report.actions_taken = actions

            report.status = "completed"

        except Exception as exc:
            report.status = "error"
            report.errors.append(str(exc))
        finally:
            report.duration_ms = (time.perf_counter() - start) * 1000
        return report


# ─── Registry ────────────────────────────────────────────────

ALL_AGENTS = [
    InvestigationAgent,
    ThreatHuntingAgent,
    ContainmentAgent,
    RansomwareInvestigationAgent,
]
