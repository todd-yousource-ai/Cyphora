"""
ACDA-SDK — Agent Orchestrator

Central coordinator for all running cyber defense agents.

Responsibilities:
  - Receive security events from the streaming bus
  - Route events to matching agents based on trigger definitions
  - Manage a priority-based execution queue
  - Enforce concurrency limits and retry policies
  - Maintain agent health and provide kill-switch control
  - Emit orchestration metrics
"""

from __future__ import annotations

import asyncio
import collections
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set, Type

import structlog
from prometheus_client import Counter, Gauge, Histogram

from acda.models.schemas import (
    AgentExecutionReport,
    OrchestratorConfig,
    SecurityEvent,
)
from acda.runtime.base_agent import BaseAgent, AgentState

logger = structlog.get_logger(__name__)


# ── Metrics ──────────────────────────────────────────────────
EVENTS_RECEIVED = Counter(
    "acda_orchestrator_events_total",
    "Total security events received by orchestrator",
    ["event_type"],
)
EVENTS_ROUTED = Counter(
    "acda_orchestrator_events_routed_total",
    "Events routed to at least one agent",
)
EVENTS_DROPPED = Counter(
    "acda_orchestrator_events_dropped_total",
    "Events dropped (no matching agent or queue full)",
)
QUEUE_SIZE = Gauge(
    "acda_orchestrator_queue_size",
    "Current number of events in the execution queue",
)
ORCHESTRATOR_UPTIME = Gauge(
    "acda_orchestrator_uptime_seconds",
    "Orchestrator uptime in seconds",
)

# FIX: Cap execution history to prevent unbounded memory growth.
_MAX_EXECUTION_HISTORY = 10_000


# ─────────────────────────────────────────────
# Queue Item
# ─────────────────────────────────────────────


@dataclass(order=True)
class QueueItem:
    priority: int  # lower = higher priority (0 = critical)
    enqueue_time: float  # monotonic time for FIFO within same priority
    item_id: str = field(compare=False)
    event: SecurityEvent = field(compare=False)
    agent: BaseAgent = field(compare=False)
    retries_remaining: int = field(compare=False, default=3)


# ─────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────

PRIORITY_MAP = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


class AgentOrchestrator:
    """
    Central event dispatcher and agent lifecycle manager.

    Usage:
        orchestrator = AgentOrchestrator()
        orchestrator.register_agent(InvestigationAgent())
        orchestrator.register_agent(ContainmentAgent())
        await orchestrator.start()
        await orchestrator.dispatch(event)
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None) -> None:
        self._config = config or OrchestratorConfig()
        self._agents: List[BaseAgent] = []
        self._trigger_index: Dict[str, List[BaseAgent]] = defaultdict(list)
        self._scheduled_agents: List[BaseAgent] = []

        self._queue: asyncio.PriorityQueue[QueueItem] = asyncio.PriorityQueue(
            maxsize=self._config.max_concurrent_agents * 10
        )
        self._semaphore = asyncio.Semaphore(self._config.max_concurrent_agents)

        self._running = False
        self._start_time: Optional[float] = None
        self._workers: List[asyncio.Task] = []
        self._schedule_tasks: List[asyncio.Task] = []

        # FIX: Use a bounded deque instead of an unbounded list.
        # Previously execution_history grew forever, causing memory leaks
        # in long-running deployments processing millions of events.
        self._execution_history: Deque[AgentExecutionReport] = collections.deque(
            maxlen=_MAX_EXECUTION_HISTORY
        )

        self._log = logger.bind(component="orchestrator")

    # ─── Agent Registration ─────────────────────────────────────

    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent and index its triggers."""
        self._agents.append(agent)

        # Index event-driven triggers
        for trigger in getattr(agent, "TRIGGERS", []):
            self._trigger_index[trigger].append(agent)
            self._log.info("trigger_indexed", agent=agent.name, trigger=trigger)

        # Track scheduled agents
        if hasattr(agent, "SCHEDULE_INTERVAL"):
            self._scheduled_agents.append(agent)
            self._log.info(
                "scheduled_agent_registered",
                agent=agent.name,
                interval=agent.SCHEDULE_INTERVAL,
            )

        self._log.info("agent_registered", agent=agent.name, version=agent.version)

    def register_agents(self, agents: List[BaseAgent]) -> None:
        for agent in agents:
            self.register_agent(agent)

    # ─── Lifecycle ──────────────────────────────────────────────

    async def start(self) -> None:
        """Start the orchestrator worker pool and scheduler."""
        self._running = True
        self._start_time = time.monotonic()

        num_workers = min(
            self._config.max_concurrent_agents,
            max(4, len(self._agents) * 2),
        )

        self._log.info(
            "orchestrator_starting", workers=num_workers, agents=len(self._agents)
        )

        # Worker pool
        self._workers = [
            asyncio.create_task(self._worker(i), name=f"orchestrator-worker-{i}")
            for i in range(num_workers)
        ]

        # Schedule-based agent timers
        for agent in self._scheduled_agents:
            task = asyncio.create_task(
                self._schedule_loop(agent),
                name=f"scheduler-{agent.name}",
            )
            self._schedule_tasks.append(task)

        # Metrics updater
        asyncio.create_task(self._metrics_loop(), name="orchestrator-metrics")

        self._log.info("orchestrator_started")

    async def stop(self) -> None:
        """Gracefully stop the orchestrator."""
        self._running = False
        self._log.info("orchestrator_stopping")

        # Cancel schedulers
        for task in self._schedule_tasks:
            task.cancel()

        # Wait for queue to drain (up to 30s)
        try:
            await asyncio.wait_for(self._queue.join(), timeout=30.0)
        except asyncio.TimeoutError:
            self._log.warning("queue_drain_timeout")

        # Cancel workers
        for task in self._workers:
            task.cancel()

        self._log.info("orchestrator_stopped")

    # ─── Event Dispatch ─────────────────────────────────────────

    async def dispatch(self, event: SecurityEvent) -> int:
        """
        Dispatch a security event to all matching agents.
        Returns the number of agents triggered.
        """
        EVENTS_RECEIVED.labels(event_type=event.event_type).inc()

        matched_agents = self._route_event(event)
        if not matched_agents:
            EVENTS_DROPPED.inc()
            self._log.debug("event_no_matching_agents", event_type=event.event_type)
            return 0

        EVENTS_ROUTED.inc()
        enqueued = 0

        for agent in matched_agents:
            item = QueueItem(
                priority=PRIORITY_MAP.get(getattr(agent, "PRIORITY", "medium"), 2),
                enqueue_time=time.monotonic(),
                item_id=str(uuid.uuid4()),
                event=event,
                agent=agent,
                retries_remaining=self._config.retry_policy_max_retries,
            )
            try:
                self._queue.put_nowait(item)
                QUEUE_SIZE.set(self._queue.qsize())
                enqueued += 1
                self._log.debug(
                    "event_enqueued",
                    agent=agent.name,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    queue_size=self._queue.qsize(),
                )
            except asyncio.QueueFull:
                EVENTS_DROPPED.inc()
                self._log.warning(
                    "queue_full_event_dropped",
                    agent=agent.name,
                    event_id=event.event_id,
                )

        return enqueued

    def _route_event(self, event: SecurityEvent) -> List[BaseAgent]:
        """Find all agents whose triggers match the event type."""
        matched = list(self._trigger_index.get(event.event_type, []))
        # Also check wildcard agents (TRIGGERS = ["*"])
        matched += [a for a in self._agents if "*" in getattr(a, "TRIGGERS", [])]
        # Deduplicate while preserving order
        seen: Set[str] = set()
        unique = []
        for a in matched:
            if a.name not in seen:
                seen.add(a.name)
                unique.append(a)
        return unique

    # ─── Worker ─────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        """Worker coroutine: pulls items from queue and executes agents."""
        self._log.debug("worker_started", worker_id=worker_id)

        while self._running or not self._queue.empty():
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            async with self._semaphore:
                await self._execute_item(item, worker_id)

            self._queue.task_done()
            QUEUE_SIZE.set(self._queue.qsize())

        self._log.debug("worker_stopped", worker_id=worker_id)

    async def _execute_item(self, item: QueueItem, worker_id: int) -> None:
        start = time.perf_counter()
        self._log.info(
            "***** agent_execution_start",
            worker_id=worker_id,
            agent=item.agent.name,
            event_id=item.event.event_id,
            event_type=item.event.event_type,
        )

        try:
            report = await asyncio.wait_for(
                item.agent.safe_run(item.event),
                timeout=self._config.timeout_seconds,
            )
            # FIX: _execution_history is now a bounded deque — oldest entries
            # are automatically evicted when maxlen is reached.
            self._execution_history.append(report)
            elapsed = (time.perf_counter() - start) * 1000
            self._log.info(
                "----- agent_execution_complete",
                agent=item.agent.name,
                status=report.status,
                actions=len(report.actions_taken),
                elapsed_ms=round(elapsed, 2),
            )

        except asyncio.TimeoutError:
            self._log.error(
                "agent_execution_timeout",
                agent=item.agent.name,
                timeout=self._config.timeout_seconds,
            )
            # FIX: Only re-queue if retries remain AND queue isn't full.
            if item.retries_remaining > 0:
                item.retries_remaining -= 1
                try:
                    self._queue.put_nowait(item)
                    self._log.info(
                        "agent_retrying",
                        agent=item.agent.name,
                        retries_remaining=item.retries_remaining,
                    )
                except asyncio.QueueFull:
                    self._log.warning(
                        "retry_dropped_queue_full",
                        agent=item.agent.name,
                    )

        except Exception as exc:
            self._log.error(
                "agent_execution_error",
                agent=item.agent.name,
                error=str(exc),
                exc_info=True,
            )
            if item.retries_remaining > 0:
                item.retries_remaining -= 1
                try:
                    self._queue.put_nowait(item)
                    self._log.info(
                        "agent_retrying",
                        agent=item.agent.name,
                        retries_remaining=item.retries_remaining,
                    )
                except asyncio.QueueFull:
                    self._log.warning(
                        "retry_dropped_queue_full",
                        agent=item.agent.name,
                    )

    # ─── Scheduler ──────────────────────────────────────────────

    async def _schedule_loop(self, agent: BaseAgent) -> None:
        """Periodically fires synthetic events for scheduled agents."""
        from acda.runtime.data_collector import parse_time_window

        interval_str = getattr(agent, "SCHEDULE_INTERVAL", "10m")
        delta = parse_time_window(interval_str)
        interval_secs = delta.total_seconds()

        self._log.info(
            "scheduler_loop_started",
            agent=agent.name,
            interval_seconds=interval_secs,
        )

        while self._running:
            await asyncio.sleep(interval_secs)

            synthetic_event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type="scheduled_scan",
                timestamp=datetime.now(tz=timezone.utc).isoformat(),
                severity="low",
                raw_data={"trigger": "scheduled", "agent": agent.name},
            )

            item = QueueItem(
                priority=PRIORITY_MAP.get("low", 3),
                enqueue_time=time.monotonic(),
                item_id=str(uuid.uuid4()),
                event=synthetic_event,
                agent=agent,
            )

            try:
                self._queue.put_nowait(item)
            except asyncio.QueueFull:
                self._log.warning(
                    "scheduled_event_dropped_queue_full", agent=agent.name
                )

    # ─── Kill Switch ─────────────────────────────────────────────

    def kill_agent(self, agent_name: str) -> bool:
        for agent in self._agents:
            if agent.name == agent_name:
                agent.kill()
                self._log.warning("kill_switch_activated_for_agent", agent=agent_name)
                return True
        return False

    def kill_all_agents(self) -> None:
        for agent in self._agents:
            agent.kill()
        self._log.warning("kill_switch_all_agents_activated")

    # ─── Metrics ────────────────────────────────────────────────

    async def _metrics_loop(self) -> None:
        while self._running:
            await asyncio.sleep(15)
            if self._start_time:
                ORCHESTRATOR_UPTIME.set(time.monotonic() - self._start_time)

    # ─── Status ─────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "uptime_seconds": (
                time.monotonic() - self._start_time if self._start_time else 0
            ),
            "agents_registered": len(self._agents),
            "queue_size": self._queue.qsize(),
            "executions_completed": len(self._execution_history),
            "agents": [a.health_check() for a in self._agents],
        }
