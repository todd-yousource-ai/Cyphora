"""
ACDA-SDK — BaseAgent
Abstract base class for all generated and hand-crafted cyber defense agents.
Provides lifecycle management, health checks, metrics, and kill-switch support.
"""

from __future__ import annotations

import abc
import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from prometheus_client import Counter, Gauge, Histogram

from acda.models.schemas import (
    AgentExecutionReport,
    SecurityEvent,
)

logger = structlog.get_logger(__name__)

# ─────────────────────────────────────────────
# Prometheus Metrics
# ─────────────────────────────────────────────

AGENT_EXECUTIONS = Counter(
    "acda_agent_executions_total",
    "Total agent executions",
    ["agent_name", "status"],
)

AGENT_DURATION = Histogram(
    "acda_agent_duration_seconds",
    "Agent execution duration in seconds",
    ["agent_name"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
)

AGENT_ACTIONS = Counter(
    "acda_agent_actions_total",
    "Total agent actions executed",
    ["agent_name", "action", "success"],
)

ACTIVE_AGENTS = Gauge(
    "acda_active_agents",
    "Currently running agent executions",
    ["agent_name"],
)

# Regex for parsing runtime strings like '120s', '2m', '1h'
_RUNTIME_PATTERN = re.compile(r"^(\d+)([smhd])$")
_RUNTIME_MULTIPLIERS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_DEFAULT_MAX_RUNTIME_SECONDS = 120


# ─────────────────────────────────────────────
# Agent State
# ─────────────────────────────────────────────


class _KillSwitchInterrupt(BaseException):
    """Raised inside safe_run when kill() fires during an in-flight run.

    Subclasses BaseException (not Exception) so agent run() bodies that catch
    'except Exception' cannot accidentally swallow a kill.
    """


class AgentState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    ERROR = "error"
    STOPPED = "stopped"
    KILLED = "killed"


@dataclass
class AgentContext:
    """Mutable context passed through an agent's execution lifecycle."""

    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time: float = field(default_factory=time.perf_counter)
    event: Optional[SecurityEvent] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────
# BaseAgent
# ─────────────────────────────────────────────


class BaseAgent(abc.ABC):
    """
    Abstract base for all ACDA cyber defense agents.

    Subclasses must implement:
      - collect_data(event) -> CollectedData
      - run(event) -> AgentExecutionReport

    Optionally override:
      - analyze(data) -> ReasoningResult
      - validate_consensus(reasoning) -> ConsensusResult
      - execute_actions(event, consensus) -> List[ActionResult]
    """

    # Subclasses declare their own values
    TRIGGERS: List[str] = []
    ACTIONS: List[str] = []
    MAX_RUNTIME: str = "120s"
    DRY_RUN_MODE: bool = False
    APPROVAL_REQUIRED: str = "none"

    def __init__(self, name: str, version: str = "1.0") -> None:
        self.name = name
        self.version = version
        self._state = AgentState.IDLE
        self._kill_switch = asyncio.Event()
        self._execution_count = 0
        self._error_count = 0
        self._last_execution: Optional[float] = None
        self._log = logger.bind(agent=self.name, version=self.version)

    # ─── Properties ────────────────────────────────────────────

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def is_alive(self) -> bool:
        return self._state not in (AgentState.STOPPED, AgentState.KILLED)

    @property
    def max_runtime_seconds(self) -> int:
        """
        Parse MAX_RUNTIME string (e.g. '120s', '2m') to integer seconds.

        FIX: Added input validation with a safe fallback. Previously a malformed
        MAX_RUNTIME string (e.g. '2minutes') caused an unhandled ValueError,
        crashing the entire safe_run() timeout calculation.
        """
        raw = (self.MAX_RUNTIME or "").strip()
        match = _RUNTIME_PATTERN.match(raw)
        if not match:
            self._log.warning(
                "invalid_max_runtime_using_default",
                value=self.MAX_RUNTIME,
                default_seconds=_DEFAULT_MAX_RUNTIME_SECONDS,
            )
            return _DEFAULT_MAX_RUNTIME_SECONDS
        value, unit = int(match.group(1)), match.group(2)
        return value * _RUNTIME_MULTIPLIERS.get(unit, 1)

    # ─── Kill switch ────────────────────────────────────────────

    def kill(self) -> None:
        """Immediately signal all running coroutines to stop."""
        self._state = AgentState.KILLED
        self._kill_switch.set()
        self._log.warning("kill_switch_activated")

    def reset_kill_switch(self) -> None:
        self._kill_switch.clear()
        if self._state == AgentState.KILLED:
            self._state = AgentState.IDLE

    # ─── Abstract interface ─────────────────────────────────────

    @abc.abstractmethod
    async def collect_data(self, event: SecurityEvent) -> Any:
        """Gather telemetry for the triggering event."""

    @abc.abstractmethod
    async def run(self, event: SecurityEvent) -> AgentExecutionReport:
        """Execute the full agent lifecycle and return a report."""

    # ─── Lifecycle wrapper ──────────────────────────────────────

    async def safe_run(self, event: SecurityEvent) -> AgentExecutionReport:
        """
        Wraps run() with:
          - kill-switch checking
          - timeout enforcement
          - Prometheus metrics recording
        """
        if not self.is_alive:
            raise RuntimeError(f"Agent {self.name} is {self._state} and cannot run.")

        self._state = AgentState.RUNNING
        ACTIVE_AGENTS.labels(agent_name=self.name).inc()

        # Race the run against the kill switch. asyncio.wait_for enforces the
        # runtime budget; the inner race lets kill() cancel work already in
        # flight instead of merely being checked once before run() starts.
        run_task: Optional[asyncio.Task] = None
        try:
            with AGENT_DURATION.labels(agent_name=self.name).time():
                report = await asyncio.wait_for(
                    self._guarded_run_racing_kill(event),
                    timeout=self.max_runtime_seconds,
                )
            AGENT_EXECUTIONS.labels(agent_name=self.name, status=report.status).inc()

            # Record per-action metrics
            for action_result in report.actions_taken:
                AGENT_ACTIONS.labels(
                    agent_name=self.name,
                    action=action_result.action,
                    success=str(action_result.success),
                ).inc()

            return report

        except asyncio.TimeoutError:
            self._error_count += 1
            AGENT_EXECUTIONS.labels(agent_name=self.name, status="timeout").inc()
            self._log.error("execution_timeout", max_runtime=self.MAX_RUNTIME)
            raise

        except _KillSwitchInterrupt:
            # kill() fired mid-run: surface an error signal and latch KILLED.
            self._error_count += 1
            AGENT_EXECUTIONS.labels(agent_name=self.name, status="killed").inc()
            self._log.warning("execution_killed_in_flight")
            raise

        except Exception:
            # BUG FIX (OBS): a generic agent exception previously produced NO
            # error signal — error_count stayed 0 and no metric was emitted,
            # so a 100%-failing agent reported healthy. Record it now.
            self._error_count += 1
            AGENT_EXECUTIONS.labels(agent_name=self.name, status="error").inc()
            self._log.error("execution_error", exc_info=True)
            raise

        finally:
            ACTIVE_AGENTS.labels(agent_name=self.name).dec()
            # BUG FIX (kill switch): only reset to IDLE from a live RUNNING
            # state. A KILLED/STOPPED terminal state must be sticky so
            # health_check()/orchestrator.status() do not report a killed
            # agent as idle/alive.
            if self._state == AgentState.RUNNING:
                self._state = AgentState.IDLE
            self._last_execution = time.time()
            self._execution_count += 1

    async def _guarded_run_racing_kill(self, event: SecurityEvent) -> AgentExecutionReport:
        """
        Run the agent while concurrently watching the kill switch. If kill()
        fires, the in-flight run task is cancelled and a _KillSwitchInterrupt
        is raised so no further pipeline stages execute.
        """
        if self._kill_switch.is_set():
            raise RuntimeError("Kill switch is active.")

        run_task = asyncio.ensure_future(self.run(event))
        kill_task = asyncio.ensure_future(self._kill_switch.wait())
        try:
            done, pending = await asyncio.wait(
                {run_task, kill_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if kill_task in done and run_task not in done:
                # Kill fired first — cancel the in-flight run and stop.
                run_task.cancel()
                try:
                    await run_task
                except (asyncio.CancelledError, Exception):
                    pass
                raise _KillSwitchInterrupt()
            # run finished first
            return run_task.result()
        finally:
            if not kill_task.done():
                kill_task.cancel()
            # Ensure run_task is not left dangling on the timeout/kill paths.
            if not run_task.done():
                run_task.cancel()
                try:
                    await run_task
                except (asyncio.CancelledError, Exception):
                    pass

    async def _guarded_run(self, event: SecurityEvent) -> AgentExecutionReport:
        """Check kill switch, then delegate to run()."""
        if self._kill_switch.is_set():
            raise RuntimeError("Kill switch is active.")
        return await self.run(event)

    # ─── Health ─────────────────────────────────────────────────

    def health_check(self) -> Dict[str, Any]:
        return {
            "agent": self.name,
            "version": self.version,
            "state": self._state.value,
            "is_alive": self.is_alive,
            "execution_count": self._execution_count,
            "error_count": self._error_count,
            "last_execution": self._last_execution,
            "triggers": self.TRIGGERS,
            "actions": self.ACTIONS,
            "dry_run_mode": self.DRY_RUN_MODE,
        }

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} name={self.name!r} state={self._state.value}>"
        )
