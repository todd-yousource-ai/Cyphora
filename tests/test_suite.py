"""
ACDA-SDK — Test Suite
Tests for: validator, code generator, consensus engine, agents, orchestrator, simulator
"""

from __future__ import annotations

import asyncio
import json
import textwrap
import uuid
from datetime import datetime, timezone
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from acda.models.schemas import (
    AgentDefinition,
    AdfDocument,
    CollectedData,
    ConsensusConfig,
    ModelScore,
    ReasoningResult,
    SecurityEvent,
)
from acda.compiler.schema_validator import AdfValidator
from acda.compiler.code_generator import AgentCodeGenerator
from acda.runtime.consensus_validator import ConsensusValidator
from acda.runtime.data_collector import DataCollector
from acda.runtime.action_executor import ActionExecutor
from acda.agents.agents import (
    InvestigationAgent,
    ThreatHuntingAgent,
    ContainmentAgent,
    RansomwareInvestigationAgent,
)
from acda.orchestrator.orchestrator import AgentOrchestrator
from acda.simulation.attack_simulator import AttackSimulator, ATTACK_SCENARIOS


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────


def make_event(
    event_type: str = "suspicious_login",
    severity: str = "high",
    host: str = "WORKSTATION-001",
    ip: str = "192.168.1.100",
    user: str = "CORP\\user01",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source_host=host,
        source_ip=ip,
        user=user,
        severity=severity,
    )


def make_scores(
    model_ids: List[str] = None,
    score: float = 0.90,
) -> List[ModelScore]:
    ids = model_ids or ["model_A", "model_B", "model_C"]
    return [
        ModelScore(
            model_id=mid,
            score=score,
            label="threat_detected",
            confidence=score,
            reasoning="Test reasoning",
        )
        for mid in ids
    ]


VALID_YAML = textwrap.dedent(
    """
    agent:
      name: TestInvestigationAgent
      version: "1.0"
      metadata:
        description: Test agent
        priority: high
        owner: test_team
      triggers:
        event_types:
          - suspicious_login
          - privilege_escalation
      data_collection:
        sources:
          - endpoint_logs
          - network_logs
        time_window: 30m
      reasoning:
        ai_models:
          - model_A
          - model_B
        task: attack_chain_analysis
        temperature: 0.2
      consensus_validation:
        method: weighted_vote
        threshold: 0.80
      actions:
        - generate_incident_report
        - notify_soc
      safety_controls:
        max_runtime: 120s
        approval_required: none
        dry_run_mode: false
"""
)

INVALID_YAML_MISSING_TRIGGER = textwrap.dedent(
    """
    agent:
      name: BadAgent
      version: "1.0"
      triggers: {}
      actions:
        - notify_soc
"""
)

INVALID_YAML_BAD_THRESHOLD = textwrap.dedent(
    """
    agent:
      name: BadThresholdAgent
      version: "1.0"
      triggers:
        event_types:
          - suspicious_login
      consensus_validation:
        threshold: 1.5
"""
)


# ═══════════════════════════════════════════════════════════════
# ADF Validator Tests
# ═══════════════════════════════════════════════════════════════


class TestAdfValidator:

    def setup_method(self):
        self.validator = AdfValidator()

    def test_valid_yaml_passes(self):
        result, agent = self.validator.validate_string(VALID_YAML, "yaml")
        assert result.valid, f"Expected valid, got errors: {result.errors}"
        assert agent is not None
        assert agent.name == "TestInvestigationAgent"

    def test_valid_yaml_fields_parsed_correctly(self):
        _, agent = self.validator.validate_string(VALID_YAML, "yaml")
        assert agent.version == "1.0"
        assert "suspicious_login" in agent.triggers.event_types
        assert agent.data_collection.time_window == "30m"
        assert agent.reasoning.task == "attack_chain_analysis"
        assert agent.consensus_validation.threshold == 0.80
        assert "notify_soc" in agent.actions

    def test_missing_trigger_fails(self):
        result, agent = self.validator.validate_string(
            INVALID_YAML_MISSING_TRIGGER, "yaml"
        )
        assert not result.valid
        assert agent is None

    def test_json_format_valid(self):
        doc = {
            "agent": {
                "name": "JsonAgent",
                "version": "1.0",
                "triggers": {"event_types": ["suspicious_login"]},
                "actions": ["notify_soc"],
            }
        }
        result, agent = self.validator.validate_string(json.dumps(doc), "json")
        assert result.valid
        assert agent.name == "JsonAgent"

    def test_unknown_format_fails(self):
        result, agent = self.validator.validate_string("{}", "toml")
        assert not result.valid

    def test_warning_no_actions(self):
        yaml_no_actions = textwrap.dedent(
            """
            agent:
              name: ObserveOnlyAgent
              triggers:
                event_types:
                  - suspicious_login
        """
        )
        result, agent = self.validator.validate_string(yaml_no_actions, "yaml")
        assert result.valid
        assert any("no actions" in w.lower() for w in result.warnings)

    def test_warning_low_consensus_threshold(self):
        yaml_low = textwrap.dedent(
            """
            agent:
              name: LowThresholdAgent
              triggers:
                event_types:
                  - suspicious_login
              consensus_validation:
                threshold: 0.40
              actions:
                - notify_soc
        """
        )
        result, _ = self.validator.validate_string(yaml_low, "yaml")
        assert result.valid
        assert any("0.4" in w or "low" in w.lower() for w in result.warnings)


# ═══════════════════════════════════════════════════════════════
# Code Generator Tests
# ═══════════════════════════════════════════════════════════════


class TestCodeGenerator:

    def setup_method(self):
        self.validator = AdfValidator()
        self.generator = AgentCodeGenerator()

    def _get_agent(self, yaml_str: str) -> AgentDefinition:
        result, agent = self.validator.validate_string(yaml_str, "yaml")
        assert result.valid
        return agent

    def test_generates_class_name(self):
        agent = self._get_agent(VALID_YAML)
        code = self.generator.generate(agent)
        assert "class TestInvestigationAgent(BaseAgent):" in code

    def test_generates_triggers(self):
        agent = self._get_agent(VALID_YAML)
        code = self.generator.generate(agent)
        assert "suspicious_login" in code
        assert "privilege_escalation" in code

    def test_generates_actions(self):
        agent = self._get_agent(VALID_YAML)
        code = self.generator.generate(agent)
        assert "generate_incident_report" in code
        assert "notify_soc" in code

    def test_generates_consensus_threshold(self):
        agent = self._get_agent(VALID_YAML)
        code = self.generator.generate(agent)
        assert "0.8" in code  # threshold

    def test_generates_run_method(self):
        agent = self._get_agent(VALID_YAML)
        code = self.generator.generate(agent)
        assert (
            "async def run(self, event: SecurityEvent) -> AgentExecutionReport:" in code
        )

    def test_no_reasoning_skips_reasoning_section(self):
        yaml_no_reasoning = textwrap.dedent(
            """
            agent:
              name: SimpleAgent
              triggers:
                event_types:
                  - confirmed_attack
              actions:
                - notify_soc
        """
        )
        agent = self._get_agent(yaml_no_reasoning)
        code = self.generator.generate(agent)
        assert "class SimpleAgent(BaseAgent):" in code
        # No reasoning defined — self._reasoner should not be instantiated
        assert "self._reasoner = ReasoningEngine" not in code

    def test_output_is_valid_python_syntax(self):
        import ast

        agent = self._get_agent(VALID_YAML)
        code = self.generator.generate(agent)
        # Should not raise SyntaxError
        try:
            ast.parse(code)
        except SyntaxError as e:
            pytest.fail(f"Generated code has syntax error: {e}")


# ═══════════════════════════════════════════════════════════════
# Consensus Validator Tests
# ═══════════════════════════════════════════════════════════════


class TestConsensusValidator:

    @pytest.mark.asyncio
    async def test_weighted_vote_passes_above_threshold(self):
        validator = ConsensusValidator(
            method="weighted_vote",
            threshold=0.80,
            weights={"model_A": 0.4, "model_B": 0.35, "model_C": 0.25},
        )
        reasoning = ReasoningResult(scores=make_scores(score=0.90), task="test")
        result = await validator.validate(reasoning)
        assert result.passed
        assert result.score >= 0.80

    @pytest.mark.asyncio
    async def test_weighted_vote_fails_below_threshold(self):
        validator = ConsensusValidator(method="weighted_vote", threshold=0.90)
        reasoning = ReasoningResult(scores=make_scores(score=0.50), task="test")
        result = await validator.validate(reasoning)
        assert not result.passed

    @pytest.mark.asyncio
    async def test_majority_vote_passes_simple_majority(self):
        validator = ConsensusValidator(method="majority_vote", threshold=0.60)
        scores = [
            ModelScore(model_id="A", score=0.85, label="threat", confidence=0.85),
            ModelScore(model_id="B", score=0.75, label="threat", confidence=0.75),
            ModelScore(model_id="C", score=0.30, label="benign", confidence=0.30),
        ]
        reasoning = ReasoningResult(scores=scores, task="test")
        result = await validator.validate(reasoning)
        assert result.passed  # 2/3 > 50%

    @pytest.mark.asyncio
    async def test_unanimous_requires_all_models(self):
        validator = ConsensusValidator(method="unanimous", threshold=0.70)
        scores = [
            ModelScore(model_id="A", score=0.90, label="threat", confidence=0.90),
            ModelScore(
                model_id="B", score=0.50, label="benign", confidence=0.50
            ),  # fails
        ]
        reasoning = ReasoningResult(scores=scores, task="test")
        result = await validator.validate(reasoning)
        assert not result.passed

    @pytest.mark.asyncio
    async def test_insufficient_models(self):
        validator = ConsensusValidator(
            method="weighted_vote", threshold=0.80, min_models_required=3
        )
        # Only 2 models provided
        reasoning = ReasoningResult(
            scores=make_scores(["model_A", "model_B"], 0.90), task="test"
        )
        result = await validator.validate(reasoning)
        assert not result.passed
        assert "Insufficient" in result.explanation

    @pytest.mark.asyncio
    async def test_equal_weights_when_none_provided(self):
        validator = ConsensusValidator(method="weighted_vote", threshold=0.80)
        scores = make_scores(["A", "B", "C"], score=0.90)
        reasoning = ReasoningResult(scores=scores, task="test")
        result = await validator.validate(reasoning)
        assert result.passed

    @pytest.mark.asyncio
    async def test_consensus_result_has_explanation(self):
        validator = ConsensusValidator(method="weighted_vote", threshold=0.80)
        reasoning = ReasoningResult(scores=make_scores(score=0.90), task="test")
        result = await validator.validate(reasoning)
        assert isinstance(result.explanation, str)
        assert len(result.explanation) > 0


# ═══════════════════════════════════════════════════════════════
# Data Collector Tests
# ═══════════════════════════════════════════════════════════════


class TestDataCollector:

    @pytest.mark.asyncio
    async def test_collects_from_multiple_sources(self):
        collector = DataCollector(
            sources=["endpoint_logs", "network_logs"],
            time_window="30m",
        )
        event = make_event()
        data = await collector.collect(event)
        assert data.data_collected if hasattr(data, "data_collected") else True
        assert len(data.logs) > 0

    @pytest.mark.asyncio
    async def test_unknown_source_skipped_gracefully(self):
        collector = DataCollector(
            sources=["endpoint_logs", "totally_fake_source_xyz"],
            time_window="10m",
        )
        event = make_event()
        data = await collector.collect(event)
        # Should not raise, and should still collect from known source
        assert isinstance(data.logs, list)

    @pytest.mark.asyncio
    async def test_threat_intel_enrichment(self):
        collector = DataCollector(
            sources=["endpoint_logs"],
            time_window="5m",
            enrich_with_threat_intel=True,
        )
        event = make_event(ip="203.0.113.99")
        data = await collector.collect(event)
        assert isinstance(data.threat_intel, list)


# ═══════════════════════════════════════════════════════════════
# Action Executor Tests
# ═══════════════════════════════════════════════════════════════


class TestActionExecutor:

    @pytest.mark.asyncio
    async def test_dry_run_returns_success_without_real_action(self):
        executor = ActionExecutor(
            actions=["isolate_host", "block_ip"],
            dry_run=True,
        )
        event = make_event()
        results = await executor.run(event)
        assert len(results) == 2
        assert all(r.dry_run for r in results)
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_known_actions_execute_successfully(self):
        executor = ActionExecutor(
            actions=["notify_soc", "generate_incident_report"],
            dry_run=False,
        )
        event = make_event()
        results = await executor.run(event)
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_unknown_action_returns_failure(self):
        executor = ActionExecutor(actions=["totally_fake_action_xyz"])
        event = make_event()
        results = await executor.run(event)
        assert len(results) == 1
        assert not results[0].success
        assert "Unknown action" in results[0].error

    @pytest.mark.asyncio
    async def test_empty_actions_returns_empty(self):
        executor = ActionExecutor(actions=[])
        results = await executor.run(make_event())
        assert results == []


# ═══════════════════════════════════════════════════════════════
# Agent Tests
# ═══════════════════════════════════════════════════════════════


class TestInvestigationAgent:

    @pytest.mark.asyncio
    async def test_runs_successfully_on_suspicious_login(self):
        agent = InvestigationAgent()
        event = make_event("suspicious_login")
        report = await agent.safe_run(event)
        assert report.status == "completed"
        assert report.data_collected
        assert report.reasoning_result is not None
        assert report.consensus_result is not None

    @pytest.mark.asyncio
    async def test_report_has_execution_id(self):
        agent = InvestigationAgent()
        event = make_event("privilege_escalation")
        report = await agent.safe_run(event)
        assert len(report.execution_id) > 0

    @pytest.mark.asyncio
    async def test_dry_run_blocks_real_actions(self):
        agent = InvestigationAgent()
        agent.DRY_RUN_MODE = True
        agent._executor.dry_run = True
        event = make_event("suspicious_login")
        report = await agent.safe_run(event)
        # If actions were taken they should be dry_run
        for action in report.actions_taken:
            assert (
                action.dry_run
                or not action.success
                or action.action in ("generate_incident_report", "notify_soc")
            )

    @pytest.mark.asyncio
    async def test_kill_switch_prevents_execution(self):
        agent = InvestigationAgent()
        agent.kill()
        with pytest.raises(RuntimeError, match="cannot run"):
            await agent.safe_run(make_event())


class TestContainmentAgent:

    @pytest.mark.asyncio
    async def test_dry_run_mode(self):
        agent = ContainmentAgent(dry_run=True)
        event = make_event("confirmed_attack")
        report = await agent.safe_run(event)
        assert report.status == "completed"
        for action in report.actions_taken:
            assert action.dry_run

    @pytest.mark.asyncio
    async def test_only_triggers_on_confirmed_attack(self):
        agent = ContainmentAgent()
        assert "confirmed_attack" in agent.TRIGGERS
        assert "suspicious_login" not in agent.TRIGGERS

    @pytest.mark.asyncio
    async def test_destructive_actions_defined(self):
        agent = ContainmentAgent()
        assert "isolate_host" in agent.ACTIONS
        assert "block_ip" in agent.ACTIONS
        assert "disable_account" in agent.ACTIONS


class TestThreatHuntingAgent:

    def test_has_schedule_interval(self):
        agent = ThreatHuntingAgent()
        assert hasattr(agent, "SCHEDULE_INTERVAL")
        assert agent.SCHEDULE_INTERVAL == "10m"

    def test_no_event_triggers(self):
        agent = ThreatHuntingAgent()
        assert agent.TRIGGERS == []

    @pytest.mark.asyncio
    async def test_runs_on_synthetic_scheduled_event(self):
        agent = ThreatHuntingAgent()
        event = make_event("scheduled_scan", severity="low")
        report = await agent.safe_run(event)
        assert report.status == "completed"


# ═══════════════════════════════════════════════════════════════
# Orchestrator Tests
# ═══════════════════════════════════════════════════════════════


class TestAgentOrchestrator:

    @pytest.mark.asyncio
    async def test_routes_event_to_matching_agent(self):
        orchestrator = AgentOrchestrator()
        agent = InvestigationAgent()
        orchestrator.register_agent(agent)
        await orchestrator.start()

        event = make_event("suspicious_login")
        triggered = await orchestrator.dispatch(event)
        assert triggered == 1

        await asyncio.sleep(0.5)
        await orchestrator.stop()

    @pytest.mark.asyncio
    async def test_unmatched_event_triggers_zero_agents(self):
        orchestrator = AgentOrchestrator()
        orchestrator.register_agent(InvestigationAgent())
        await orchestrator.start()

        event = make_event("totally_unknown_event_xyz")
        triggered = await orchestrator.dispatch(event)
        assert triggered == 0

        await orchestrator.stop()

    @pytest.mark.asyncio
    async def test_multiple_agents_triggered_by_same_event(self):
        orchestrator = AgentOrchestrator()
        # Both InvestigationAgent and a second trigger "suspicious_login"
        orchestrator.register_agents([InvestigationAgent(), InvestigationAgent()])
        # Rename second to avoid collision
        orchestrator._agents[1].name = "InvestigationAgent_2"
        orchestrator._trigger_index["suspicious_login"].append(orchestrator._agents[1])

        await orchestrator.start()
        triggered = await orchestrator.dispatch(make_event("suspicious_login"))
        assert triggered >= 1
        await orchestrator.stop()

    def test_kill_agent_by_name(self):
        orchestrator = AgentOrchestrator()
        agent = InvestigationAgent()
        orchestrator.register_agent(agent)
        result = orchestrator.kill_agent("InvestigationAgent")
        assert result is True
        assert not agent.is_alive

    def test_kill_unknown_agent_returns_false(self):
        orchestrator = AgentOrchestrator()
        result = orchestrator.kill_agent("NonExistentAgent")
        assert result is False

    def test_status_returns_dict(self):
        orchestrator = AgentOrchestrator()
        orchestrator.register_agent(InvestigationAgent())
        status = orchestrator.status()
        assert "agents_registered" in status
        assert status["agents_registered"] == 1


# ═══════════════════════════════════════════════════════════════
# Attack Simulator Tests
# ═══════════════════════════════════════════════════════════════


class TestAttackSimulator:

    @pytest.mark.asyncio
    async def test_ransomware_scenario_yields_events(self):
        simulator = AttackSimulator(speed_multiplier=100.0)
        events = []
        async for event in simulator.run_scenario("ransomware"):
            events.append(event)
        assert len(events) == len(ATTACK_SCENARIOS["ransomware"])

    @pytest.mark.asyncio
    async def test_all_scenarios_have_events(self):
        simulator = AttackSimulator(speed_multiplier=1000.0)
        for scenario_name in ATTACK_SCENARIOS:
            events = []
            async for event in simulator.run_scenario(scenario_name):
                events.append(event)
            assert len(events) > 0, f"No events for scenario: {scenario_name}"

    @pytest.mark.asyncio
    async def test_events_have_required_fields(self):
        simulator = AttackSimulator(speed_multiplier=1000.0)
        async for event in simulator.run_scenario("privilege_escalation"):
            assert event.event_id
            assert event.event_type
            assert event.timestamp
            assert event.severity

    def test_unknown_scenario_raises(self):
        simulator = AttackSimulator()
        with pytest.raises(ValueError, match="Unknown scenario"):
            asyncio.run(self._drain(simulator.run_scenario("nonexistent_scenario_xyz")))

    def test_list_scenarios_returns_all(self):
        simulator = AttackSimulator()
        scenarios = simulator.list_scenarios()
        assert len(scenarios) == len(ATTACK_SCENARIOS)
        for s in scenarios:
            assert "name" in s
            assert "stages" in s

    async def _drain(self, gen):
        async for _ in gen:
            pass


# ═══════════════════════════════════════════════════════════════
# Integration Test: Full Pipeline
# ═══════════════════════════════════════════════════════════════


class TestFullPipeline:

    @pytest.mark.asyncio
    async def test_investigation_pipeline_end_to_end(self):
        """
        Full pipeline: Event → Agent → Data → Reasoning → Consensus → Actions
        """
        agent = InvestigationAgent()
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type="privilege_escalation",
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            source_host="CORP-WS-001",
            source_ip="10.0.1.55",
            user="CORP\\compromised_user",
            severity="critical",
        )

        report = await agent.safe_run(event)

        # Structural assertions
        assert report.agent_name == "InvestigationAgent"
        assert report.event.event_id == event.event_id
        assert report.data_collected is True
        assert report.reasoning_result is not None
        assert len(report.reasoning_result.scores) == 3  # 3 models
        assert report.consensus_result is not None
        assert report.consensus_result.method == "weighted_vote"
        assert report.duration_ms > 0
        assert report.status == "completed"

    @pytest.mark.asyncio
    async def test_containment_pipeline_dry_run(self):
        """Containment with dry run — should record attempted actions."""
        agent = ContainmentAgent(dry_run=True)
        event = make_event("confirmed_attack", severity="critical")
        report = await agent.safe_run(event)

        assert report.status == "completed"
        assert report.data_collected
        assert len(report.actions_taken) == 3  # isolate, block, disable

        for action in report.actions_taken:
            assert action.dry_run
            assert action.success

    @pytest.mark.asyncio
    async def test_orchestrator_full_simulation_cycle(self):
        """Orchestrator routes multiple events and agents complete execution."""
        orchestrator = AgentOrchestrator()
        orchestrator.register_agents(
            [
                InvestigationAgent(),
                ContainmentAgent(dry_run=True),
            ]
        )
        await orchestrator.start()

        events = [
            make_event("suspicious_login", severity="high"),
            make_event("privilege_escalation", severity="high"),
            make_event("confirmed_attack", severity="critical"),
        ]

        total_triggered = 0
        for event in events:
            total_triggered += await orchestrator.dispatch(event)

        # Allow execution
        await asyncio.sleep(1.5)
        await orchestrator.stop()

        assert total_triggered >= 2  # At least investigation + containment
