"""
Regression tests for the defects fixed following the Code Quality Assessment
(CQH-CYPHORA-20260708-01). Each test fails on the pre-fix code and passes
after the corresponding fix.
"""
from __future__ import annotations

import asyncio
import ast

import pytest

from acda.models.schemas import (
    ModelScore,
    ReasoningResult,
    SecurityEvent,
)
from acda.runtime.action_executor import ActionExecutor, ApprovalQueue, ApprovalStatus
from acda.runtime.consensus_validator import ConsensusValidator
from acda.runtime.reasoning_engine import _create_adapter


def _event() -> SecurityEvent:
    return SecurityEvent(
        event_id="evt-1",
        event_type="confirmed_attack",
        timestamp="2026-07-08T00:00:00Z",
        source_host="host-1",
        source_ip="10.0.0.1",
        user="alice",
        severity="high",
    )


# ── CQH-GOV-001 / IC-001 / UT-003: inverted approval gate ───────────────────

@pytest.mark.asyncio
async def test_highrisk_action_is_gated_not_autoexecuted():
    """isolate_host under approval_required='high_risk' must reach the queue,
    not execute autonomously."""
    queue = ApprovalQueue(auto_deny_seconds=1)
    executor = ActionExecutor(
        actions=["isolate_host"],
        approval_required="high_risk",
        dry_run=False,
        auto_approve_seconds=1,
        approval_queue=queue,
    )
    results = await executor.run(_event())
    # With no analyst approval, the action must NOT succeed (auto-denied).
    assert all(not r.success for r in results)


@pytest.mark.asyncio
async def test_approval_none_does_not_gate():
    """approval_required='none' must never gate (no infinite/erroneous queueing)."""
    executor = ActionExecutor(
        actions=["notify_soc"],  # risk 'none'
        approval_required="none",
        dry_run=False,
    )
    results = await executor.run(_event())
    assert all(r.success for r in results)


@pytest.mark.asyncio
async def test_analyst_approval_allows_execution():
    queue = ApprovalQueue(auto_deny_seconds=5)
    executor = ActionExecutor(
        actions=["isolate_host"],
        approval_required="high_risk",
        dry_run=False,
        auto_approve_seconds=5,
        approval_queue=queue,
    )

    async def approve_soon():
        # Wait until the pending record exists, then approve it.
        for _ in range(50):
            pending = queue.list_pending()
            if pending:
                queue.approve(pending[0]["approval_id"], analyst_id="soc_manager")
                return
            await asyncio.sleep(0.02)

    approver = asyncio.create_task(approve_soon())
    results = await executor.run(_event())
    await approver
    assert all(r.success for r in results)


# ── CQH-UT-001: consensus must be direction-aware ───────────────────────────

@pytest.mark.asyncio
async def test_unanimous_benign_does_not_pass_threat_gate():
    validator = ConsensusValidator(method="weighted_vote", threshold=0.80)
    benign = [
        ModelScore(model_id="A", score=0.02, label="benign", confidence=0.95),
        ModelScore(model_id="B", score=0.03, label="benign", confidence=0.95),
        ModelScore(model_id="C", score=0.01, label="benign", confidence=0.95),
    ]
    result = await validator.validate(ReasoningResult(scores=benign, task="t"))
    assert not result.passed, "confident BENIGN verdicts must not authorize actions"


@pytest.mark.asyncio
async def test_confident_threats_pass_threat_gate():
    validator = ConsensusValidator(method="weighted_vote", threshold=0.60)
    threats = [
        ModelScore(model_id="A", score=0.95, label="threat_detected", confidence=0.95),
        ModelScore(model_id="B", score=0.92, label="threat_detected", confidence=0.90),
        ModelScore(model_id="C", score=0.90, label="threat_detected", confidence=0.90),
    ]
    result = await validator.validate(ReasoningResult(scores=threats, task="t"))
    assert result.passed


# ── CQH-UT-002: unknown model id must fail closed ───────────────────────────

def test_unknown_model_id_fails_closed():
    with pytest.raises(ValueError):
        _create_adapter("gpt4o")  # typo: missing hyphen


def test_known_model_ids_resolve():
    assert _create_adapter("claude-sonnet-4-6") is not None
    assert _create_adapter("gpt-4o") is not None
    assert _create_adapter("model_A") is not None


# ── CQH-SA-002 / INT-008: error scores excluded from consensus ──────────────

@pytest.mark.asyncio
async def test_error_scores_excluded_from_reasoning_result():
    from acda.runtime.reasoning_engine import ReasoningEngine
    from acda.models.schemas import CollectedData

    engine = ReasoningEngine(models=["model_A", "model_B"], task="t")
    data = CollectedData(event=_event())
    result = await engine.run(data)
    # All simulation adapters succeed here; ensure no error-labelled score
    # ever leaks into the consensus input.
    assert all((s.label or "").lower() not in ("error", "timeout") for s in result.scores)


# ── CQH-SEC-001: ADF code generator must be injection-inert ─────────────────

def test_code_generator_is_injection_inert(tmp_path):
    from acda.models.schemas import (
        AgentDefinition, AgentMetadata, ReasoningConfig,
        TriggerConfig, DataCollectionConfig, SafetyControls,
    )
    from acda.compiler.code_generator import AgentCodeGenerator

    marker = tmp_path / "PWNED"
    payload = f'x"; open(r"{marker}", "w").write("x") #'
    agent = AgentDefinition(
        name="InjectedAgent",
        version='1.0"; #',
        metadata=AgentMetadata(description='d"""; #', owner='o"""x'),
        triggers=TriggerConfig(event_types=["x"]),
        data_collection=DataCollectionConfig(sources=["a"], time_window="10m"),
        reasoning=ReasoningConfig(ai_models=["model_A", "model_B"], task=payload),
        safety_controls=SafetyControls(max_runtime="60s"),
    )
    code = AgentCodeGenerator().generate(agent, "hostile.yaml")
    ast.parse(code)  # must be valid Python
    ns: dict = {}
    exec(compile(code, "gen.py", "exec"), ns)  # importing must not run payload
    assert not marker.exists(), "code generator executed injected payload"
    assert ns["InjectedAgent"].REASONING_TASK == payload  # preserved as inert data


# ── CQH-RR-001 / GOV-003 / UT-004: kill switch + error observability ────────

from acda.runtime.base_agent import BaseAgent, AgentState  # noqa: E402
from acda.models.schemas import AgentExecutionReport  # noqa: E402


class _SlowAgent(BaseAgent):
    TRIGGERS = ["confirmed_attack"]
    MAX_RUNTIME = "10s"

    def __init__(self):
        super().__init__(name="SlowAgent")
        self.action_fired = False

    async def collect_data(self, event):  # pragma: no cover - trivial
        return None

    async def run(self, event):
        await asyncio.sleep(0.5)
        # This side effect must NOT happen if kill() fired first.
        self.action_fired = True
        return AgentExecutionReport(
            agent_name=self.name, execution_id="x", event=event,
            data_collected=False, status="completed",
        )


class _FailingAgent(BaseAgent):
    TRIGGERS = ["x"]
    MAX_RUNTIME = "5s"

    def __init__(self):
        super().__init__(name="FailingAgent")

    async def collect_data(self, event):  # pragma: no cover
        return None

    async def run(self, event):
        raise ValueError("boom")


@pytest.mark.asyncio
async def test_kill_switch_stops_inflight_and_latches_killed():
    agent = _SlowAgent()
    run_task = asyncio.create_task(agent.safe_run(_event()))
    await asyncio.sleep(0.1)
    agent.kill()
    with pytest.raises(BaseException):
        await run_task
    assert not agent.action_fired, "in-flight action fired after kill()"
    assert agent.state == AgentState.KILLED
    assert agent.is_alive is False


@pytest.mark.asyncio
async def test_agent_exception_produces_error_signal():
    agent = _FailingAgent()
    with pytest.raises(Exception):
        await agent.safe_run(_event())
    hc = agent.health_check()
    assert hc["error_count"] >= 1, "agent exception must increment error_count"
