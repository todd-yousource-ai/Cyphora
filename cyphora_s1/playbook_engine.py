"""
Cyphora-S1 — Automated Response Playbook Engine

BUG 8 FIX: PlaybookEngine.rollback() is now fully implemented.
  - Each executed step is recorded in a rollback log with its inverse action.
  - rollback() executes inverse actions in reverse chronological order.
  - Inverse action map covers all four destructive action types:
      isolate_host      → un_isolate_host
      disable_account   → re_enable_account
      block_ip          → unblock_ip
      revoke_token      → reissue_token
  - PlaybookResult.rollback_available reflects whether there are
    reversible steps to undo.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx
import structlog

from acda.models.schemas import ActionResult, SecurityEvent
from acda.runtime.action_executor import ActionExecutor, ApprovalQueue

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────
# Playbook Step Models
# ─────────────────────────────────────────────

@dataclass
class PlaybookCondition:
    field:    str
    operator: str   # eq, neq, in, gte, lte, contains
    value:    Any

    def evaluate(self, event: SecurityEvent) -> bool:
        actual = getattr(event, self.field, None)
        if actual is None:
            return False
        if self.operator == "eq":
            return str(actual).lower() == str(self.value).lower()
        elif self.operator == "neq":
            return str(actual).lower() != str(self.value).lower()
        elif self.operator == "in":
            return str(actual).lower() in [str(v).lower() for v in self.value]
        elif self.operator == "contains":
            return str(self.value).lower() in str(actual).lower()
        elif self.operator == "gte":
            order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            return order.get(str(actual).lower(), 0) >= order.get(str(self.value).lower(), 0)
        return False


@dataclass
class PlaybookStep:
    step_id:              str
    name:                 str
    action:               str
    description:          str = ""
    conditions:           List[PlaybookCondition] = field(default_factory=list)
    timeout_seconds:      float = 30.0
    continue_on_failure:  bool  = True
    approval_required:    str   = "none"
    dry_run_override:     bool  = False


# ─────────────────────────────────────────────
# BUG 8 FIX: Rollback support data classes
# ─────────────────────────────────────────────

@dataclass
class ExecutedStep:
    """
    Record of a successfully executed playbook step, including the
    inverse action needed to undo it.
    """
    step_id:         str
    action:          str
    inverse_action:  Optional[str]   # None for non-reversible actions
    output:          Dict[str, Any]
    executed_at:     str
    event_snapshot:  Dict[str, Any]  # snapshot of SecurityEvent fields


@dataclass
class RollbackResult:
    """Result of a rollback operation."""
    playbook_name:    str
    original_event_id:str
    rollback_id:      str
    started_at:       str
    completed_at:     str
    steps_rolled_back:int
    steps_failed:     int
    step_results:     List[Dict[str, Any]] = field(default_factory=list)
    duration_ms:      float = 0.0

    @property
    def success(self) -> bool:
        return self.steps_failed == 0

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


@dataclass
class PlaybookResult:
    playbook_name:     str
    execution_id:      str
    event_id:          str
    started_at:        str
    completed_at:      str
    status:            str
    steps_total:       int
    steps_executed:    int
    steps_skipped:     int
    steps_failed:      int
    step_results:      List[Dict[str, Any]] = field(default_factory=list)
    duration_ms:       float = 0.0
    rollback_available:bool  = False        # True when ≥1 reversible step executed

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


# ─────────────────────────────────────────────
# BUG 8 FIX: Inverse action map
# ─────────────────────────────────────────────

# Maps each destructive action to its reversal action name.
# Actions not listed here are considered non-reversible (they are
# idempotent notifications/reports that do not need undoing).
INVERSE_ACTIONS: Dict[str, str] = {
    "isolate_host":    "un_isolate_host",
    "disable_account": "re_enable_account",
    "block_ip":        "unblock_ip",
    "revoke_token":    "reissue_token",
    "quarantine_file": "restore_file",
    "kill_process":    None,           # type: ignore[assignment]  # cannot undo
}

# Inverse action handlers (simulation — replace with real API calls in prod)

async def _un_isolate_host(event: SecurityEvent, **kw) -> Dict[str, Any]:
    host_id = event.source_host or kw.get("host_id", "unknown_host")
    await asyncio.sleep(0.1)
    logger.info("rollback_un_isolate_host", host_id=host_id)
    return {"action": "un_isolate_host", "host_id": host_id,
            "message": f"Host {host_id} network isolation removed.",
            "platform": "EDR_SIM"}

async def _re_enable_account(event: SecurityEvent, **kw) -> Dict[str, Any]:
    user = event.user or kw.get("user_id", "unknown_user")
    await asyncio.sleep(0.08)
    logger.info("rollback_re_enable_account", user=user)
    return {"action": "re_enable_account", "user_id": user,
            "message": f"Account {user} re-enabled.", "platform": "IAM_SIM"}

async def _unblock_ip(event: SecurityEvent, **kw) -> Dict[str, Any]:
    ip = event.source_ip or kw.get("ip_address", "0.0.0.0")
    await asyncio.sleep(0.05)
    logger.info("rollback_unblock_ip", ip=ip)
    return {"action": "unblock_ip", "ip_address": ip,
            "message": f"IP {ip} firewall block removed.", "platform": "FIREWALL_SIM"}

async def _reissue_token(event: SecurityEvent, **kw) -> Dict[str, Any]:
    user = event.user or kw.get("user_id", "unknown_user")
    await asyncio.sleep(0.03)
    logger.info("rollback_reissue_token", user=user)
    return {"action": "reissue_token", "user_id": user,
            "message": f"New session token issued for {user}.", "platform": "OAUTH_SIM"}

async def _restore_file(event: SecurityEvent, **kw) -> Dict[str, Any]:
    host = event.source_host or "unknown_host"
    await asyncio.sleep(0.04)
    logger.info("rollback_restore_file", host=host)
    return {"action": "restore_file", "host": host,
            "message": "Quarantined file restored.", "platform": "EDR_SIM"}

_INVERSE_HANDLERS: Dict[str, Any] = {
    "un_isolate_host":   _un_isolate_host,
    "re_enable_account": _re_enable_account,
    "unblock_ip":        _unblock_ip,
    "reissue_token":     _reissue_token,
    "restore_file":      _restore_file,
}


# ─────────────────────────────────────────────
# Built-in Playbook Definitions
# ─────────────────────────────────────────────

BUILT_IN_PLAYBOOKS: Dict[str, List[PlaybookStep]] = {
    "ransomware_response": [
        PlaybookStep("rs_01","Snapshot Memory","snapshot_memory",
                     "Preserve volatile memory before isolation."),
        PlaybookStep("rs_02","Isolate Affected Host","isolate_host",
                     "Cut infected host from network.", approval_required="high_risk"),
        PlaybookStep("rs_03","Quarantine Suspicious Files","quarantine_file",
                     "Move encrypted files to quarantine.", approval_required="medium_risk"),
        PlaybookStep("rs_04","Notify SOC","notify_soc","Alert SOC via Slack and email."),
        PlaybookStep("rs_05","Create PagerDuty Incident","pagerduty_incident",
                     "Escalate to on-call.",
                     conditions=[PlaybookCondition("severity","gte","high")]),
        PlaybookStep("rs_06","Generate Incident Report","generate_incident_report",
                     "Create formal IR document."),
    ],
    "credential_compromise": [
        PlaybookStep("cc_01","Revoke All Active Tokens","revoke_token",
                     "Invalidate all active sessions.", approval_required="medium_risk"),
        PlaybookStep("cc_02","Disable User Account","disable_account",
                     "Lock the account.", approval_required="high_risk"),
        PlaybookStep("cc_03","Block Source IP","block_ip",
                     "Block attacking IP at perimeter.", approval_required="medium_risk",
                     conditions=[PlaybookCondition("source_ip","neq",None)]),
        PlaybookStep("cc_04","Notify SOC","notify_soc","Alert SOC."),
        PlaybookStep("cc_05","Create PagerDuty Incident","pagerduty_incident",
                     "Page on-call.",
                     conditions=[PlaybookCondition("severity","gte","high")]),
        PlaybookStep("cc_06","Generate Incident Report","generate_incident_report",
                     "Document the compromise."),
    ],
    "data_exfiltration_response": [
        PlaybookStep("de_01","Block Exfiltration IP","block_ip",
                     "Stop ongoing exfiltration.", approval_required="medium_risk"),
        PlaybookStep("de_02","Kill Suspicious Process","kill_process",
                     "Terminate data transfer process.", approval_required="medium_risk",
                     conditions=[PlaybookCondition("process","neq",None)]),
        PlaybookStep("de_03","Isolate Source Host","isolate_host",
                     "Prevent further data loss.", approval_required="high_risk",
                     conditions=[PlaybookCondition("severity","gte","high")]),
        PlaybookStep("de_04","Snapshot Memory","snapshot_memory","Capture volatile memory."),
        PlaybookStep("de_05","PagerDuty Escalation","pagerduty_incident","Page CISO."),
        PlaybookStep("de_06","Notify SOC","notify_soc",""),
        PlaybookStep("de_07","Generate Incident Report","generate_incident_report",""),
    ],
    "lateral_movement_response": [
        PlaybookStep("lm_01","Block Lateral Movement IPs","block_ip",
                     "Block pivot IPs.", approval_required="medium_risk"),
        PlaybookStep("lm_02","Isolate Pivot Host","isolate_host",
                     "Isolate originating host.", approval_required="high_risk"),
        PlaybookStep("lm_03","Revoke Tokens","revoke_token",
                     "Revoke tokens for involved users.", approval_required="medium_risk"),
        PlaybookStep("lm_04","Snapshot Pivot Host Memory","snapshot_memory",""),
        PlaybookStep("lm_05","Escalate to PagerDuty","pagerduty_incident","Page incident commander."),
        PlaybookStep("lm_06","Notify SOC","notify_soc",""),
        PlaybookStep("lm_07","Generate Incident Report","generate_incident_report",""),
    ],
}


# ─────────────────────────────────────────────
# PagerDuty Integration
# ─────────────────────────────────────────────

class PagerDutyIntegration:
    _EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, integration_key: Optional[str] = None) -> None:
        self._key = integration_key or os.getenv("PAGERDUTY_INTEGRATION_KEY")

    async def create_incident(self, event: SecurityEvent, summary: Optional[str] = None,
                              severity: str = "critical",
                              component: str = "Cyphora-S1 SIEM") -> Dict[str, Any]:
        if not self._key:
            logger.info("pagerduty_key_missing_simulating")
            return {"status": "simulated",
                    "dedup_key": f"PGDT-SIM-{uuid.uuid4().hex[:8].upper()}",
                    "message": "PagerDuty key not configured — simulated incident"}

        sev_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}
        payload = {
            "routing_key": self._key,
            "event_action": "trigger",
            "dedup_key": f"cyphora-{event.event_id}",
            "payload": {
                "summary": summary or f"[Cyphora-S1] {event.severity.upper()} — "
                           f"{event.event_type} on {event.source_host or 'unknown host'}",
                "severity": sev_map.get(event.severity.lower(), "error"),
                "source": component,
                "timestamp": event.timestamp,
                "component": component,
                "custom_details": {
                    "event_id": event.event_id,
                    "source_host": event.source_host,
                    "source_ip": event.source_ip,
                    "user": event.user,
                },
            },
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(self._EVENTS_URL, json=payload)
                resp.raise_for_status()
                result = resp.json()
                if not isinstance(result, dict):
                    raise ValueError(f"PagerDuty returned {type(result).__name__}")
                logger.info("pagerduty_incident_created", event_id=event.event_id,
                            dedup_key=result.get("dedup_key"))
                return result
        except Exception as exc:
            logger.error("pagerduty_create_failed", error=str(exc))
            return {"status": "error", "error": str(exc)}

    async def resolve_incident(self, dedup_key: str) -> Dict[str, Any]:
        if not self._key:
            return {"status": "simulated"}
        payload = {"routing_key": self._key, "event_action": "resolve", "dedup_key": dedup_key}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(self._EVENTS_URL, json=payload)
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.error("pagerduty_resolve_failed", error=str(exc))
            return {"status": "error", "error": str(exc)}


# ─────────────────────────────────────────────
# PlaybookEngine
# ─────────────────────────────────────────────

class PlaybookEngine:
    """
    BUG 8 FIX: rollback() is now fully implemented.

    Implementation details:
    - Every successfully executed step whose action appears in
      INVERSE_ACTIONS is recorded in self._rollback_log as an
      ExecutedStep containing the inverse action name.
    - rollback(execution_id) retrieves those steps and executes
      their inverses in reverse order using the _INVERSE_HANDLERS map.
    - Non-reversible actions (snapshot_memory, generate_incident_report,
      notify_soc, create_threat_alert) are skipped during rollback.
    - PlaybookResult.rollback_available is True only when at least one
      reversible step was executed.
    """

    def __init__(
        self,
        dry_run: bool = False,
        approval_mode: str = "auto",
        pagerduty_key: Optional[str] = None,
        approval_queue: Optional[ApprovalQueue] = None,
    ) -> None:
        self._dry_run          = dry_run
        self._approval_mode    = approval_mode
        self._pagerduty        = PagerDutyIntegration(integration_key=pagerduty_key)
        self._custom_playbooks: Dict[str, List[PlaybookStep]] = {}
        self._approval_queue   = approval_queue

        # BUG 8 FIX: per-execution rollback log
        # execution_id → list of ExecutedStep (in execution order)
        self._rollback_log: Dict[str, List[ExecutedStep]] = {}

    def register_playbook(self, name: str, steps: List[PlaybookStep]) -> None:
        self._custom_playbooks[name] = steps
        logger.info("custom_playbook_registered", name=name, steps=len(steps))

    def list_playbooks(self) -> List[str]:
        return sorted(set(BUILT_IN_PLAYBOOKS.keys()) | set(self._custom_playbooks.keys()))

    # ── Run playbook ─────────────────────────────────────────────

    async def run_playbook(self, playbook_name: str, event: SecurityEvent) -> PlaybookResult:
        steps = (self._custom_playbooks.get(playbook_name)
                 or BUILT_IN_PLAYBOOKS.get(playbook_name))
        if not steps:
            raise ValueError(
                f"Playbook '{playbook_name}' not found. "
                f"Available: {', '.join(self.list_playbooks())}"
            )

        execution_id = str(uuid.uuid4())
        started_at   = datetime.now(tz=timezone.utc).isoformat()
        start        = time.perf_counter()
        self._rollback_log[execution_id] = []           # BUG 8 FIX: init rollback log

        logger.info("playbook_started", playbook=playbook_name, event_id=event.event_id,
                    steps=len(steps), dry_run=self._dry_run)

        step_results: List[Dict[str, Any]] = []
        executed = skipped = failed = 0

        for step in steps:
            step_start = time.perf_counter()

            if not self._evaluate_conditions(step, event):
                skipped += 1
                step_results.append({"step_id": step.step_id, "name": step.name,
                                     "status": "skipped", "reason": "Conditions not met",
                                     "duration_ms": 0.0})
                continue

            if (self._approval_mode == "manual"
                    and step.approval_required in ("high_risk", "critical")
                    and not self._dry_run):
                skipped += 1
                step_results.append({"step_id": step.step_id, "name": step.name,
                                     "status": "pending_approval",
                                     "reason": f"Step requires {step.approval_required} approval"})
                logger.warning("playbook_step_awaiting_approval", step=step.name)
                continue

            result = await self._execute_step(step, event)
            elapsed_ms = (time.perf_counter() - step_start) * 1000

            step_result = {
                "step_id":    step.step_id,
                "name":       step.name,
                "action":     step.action,
                "status":     "success" if result.success else "failed",
                "output":     result.output,
                "error":      result.error,
                "dry_run":    result.dry_run,
                "duration_ms":round(elapsed_ms, 2),
            }
            step_results.append(step_result)

            if result.success:
                executed += 1
                # BUG 8 FIX: record reversible steps for rollback
                inverse = INVERSE_ACTIONS.get(step.action)
                self._rollback_log[execution_id].append(ExecutedStep(
                    step_id        = step.step_id,
                    action         = step.action,
                    inverse_action = inverse,
                    output         = result.output or {},
                    executed_at    = datetime.now(tz=timezone.utc).isoformat(),
                    event_snapshot = {
                        "event_id":   event.event_id,
                        "event_type": event.event_type,
                        "source_host":event.source_host,
                        "source_ip":  event.source_ip,
                        "user":       event.user,
                    },
                ))
            else:
                failed += 1
                if not step.continue_on_failure:
                    logger.error("playbook_aborted_step_failed", step=step.name,
                                 error=result.error)
                    break

        completed_at = datetime.now(tz=timezone.utc).isoformat()
        total_ms     = (time.perf_counter() - start) * 1000
        status = "completed" if failed == 0 else ("partial" if executed > 0 else "failed")

        # BUG 8 FIX: rollback_available only when reversible steps were executed
        reversible_steps = [s for s in self._rollback_log[execution_id]
                            if s.inverse_action is not None]
        rollback_available = len(reversible_steps) > 0 and not self._dry_run

        logger.info("playbook_executed", playbook=playbook_name, status=status,
                    steps=f"{executed}/{len(steps)}",
                    rollback_available=rollback_available)

        return PlaybookResult(
            playbook_name     = playbook_name,
            execution_id      = execution_id,
            event_id          = event.event_id,
            started_at        = started_at,
            completed_at      = completed_at,
            status            = status,
            steps_total       = len(steps),
            steps_executed    = executed,
            steps_skipped     = skipped,
            steps_failed      = failed,
            step_results      = step_results,
            duration_ms       = round(total_ms, 1),
            rollback_available= rollback_available,
        )

    # ── BUG 8 FIX: rollback() implementation ────────────────────

    async def rollback(self, execution_id: str) -> RollbackResult:
        """
        Undo all reversible actions from a previous playbook execution.

        Steps are reversed in reverse chronological order (last executed,
        first rolled back).  Non-reversible actions (notify_soc,
        snapshot_memory, etc.) are skipped with a 'not_reversible' status.

        Args:
            execution_id: the execution_id from a PlaybookResult

        Returns:
            RollbackResult with per-step outcomes.

        Raises:
            ValueError: if execution_id is not found in rollback log.
        """
        executed_steps = self._rollback_log.get(execution_id)
        if executed_steps is None:
            raise ValueError(
                f"Rollback log not found for execution_id '{execution_id}'. "
                "Rollback is only possible within the same process lifetime."
            )

        rollback_id  = str(uuid.uuid4())
        started_at   = datetime.now(tz=timezone.utc).isoformat()
        start        = time.perf_counter()
        step_results: List[Dict[str, Any]] = []
        rolled_back  = 0
        rb_failed    = 0

        # Determine original event from first executed step snapshot
        original_event_id = (executed_steps[0].event_snapshot.get("event_id", "unknown")
                              if executed_steps else "unknown")

        logger.info("playbook_rollback_started", execution_id=execution_id,
                    rollback_id=rollback_id, steps_to_reverse=len(executed_steps))

        # Reverse order: last action undone first
        for step in reversed(executed_steps):
            inverse = step.inverse_action

            if inverse is None:
                step_results.append({
                    "original_action": step.action,
                    "status":          "skipped",
                    "reason":          "not_reversible",
                })
                continue

            handler = _INVERSE_HANDLERS.get(inverse)
            if handler is None:
                step_results.append({
                    "original_action": step.action,
                    "inverse_action":  inverse,
                    "status":          "error",
                    "reason":          f"No handler registered for '{inverse}'",
                })
                rb_failed += 1
                continue

            # Reconstruct a minimal SecurityEvent from the snapshot
            from acda.models.schemas import SecurityEvent as SE
            snap = step.event_snapshot
            rollback_event = SE(
                event_id    = snap.get("event_id", str(uuid.uuid4())),
                event_type  = snap.get("event_type", "rollback"),
                severity    = "low",
                timestamp   = datetime.now(tz=timezone.utc).isoformat(),
                source_host = snap.get("source_host"),
                source_ip   = snap.get("source_ip"),
                user        = snap.get("user"),
            )

            try:
                if self._dry_run:
                    output = {"dry_run": True, "would_execute": inverse}
                    success = True
                else:
                    output  = await asyncio.wait_for(
                        handler(rollback_event, **step.output),
                        timeout=30.0
                    )
                    success = True

                rolled_back += 1
                logger.info("rollback_step_executed",
                            original_action=step.action, inverse_action=inverse,
                            success=success)
                step_results.append({
                    "original_action": step.action,
                    "inverse_action":  inverse,
                    "status":          "success",
                    "output":          output,
                })

            except asyncio.TimeoutError:
                rb_failed += 1
                logger.error("rollback_step_timeout",
                             original_action=step.action, inverse_action=inverse)
                step_results.append({
                    "original_action": step.action,
                    "inverse_action":  inverse,
                    "status":          "timeout",
                    "error":           "Rollback step timed out after 30s",
                })
            except Exception as exc:
                rb_failed += 1
                logger.error("rollback_step_failed", original_action=step.action,
                             inverse_action=inverse, error=str(exc))
                step_results.append({
                    "original_action": step.action,
                    "inverse_action":  inverse,
                    "status":          "error",
                    "error":           str(exc),
                })

        completed_at = datetime.now(tz=timezone.utc).isoformat()
        total_ms     = (time.perf_counter() - start) * 1000

        result = RollbackResult(
            playbook_name     = f"rollback:{execution_id[:8]}",
            original_event_id = original_event_id,
            rollback_id       = rollback_id,
            started_at        = started_at,
            completed_at      = completed_at,
            steps_rolled_back = rolled_back,
            steps_failed      = rb_failed,
            step_results      = step_results,
            duration_ms       = round(total_ms, 1),
        )

        logger.info("playbook_rollback_complete", rollback_id=rollback_id,
                    steps_rolled_back=rolled_back, steps_failed=rb_failed,
                    success=result.success, duration_ms=round(total_ms, 1))

        # Clean up rollback log after successful rollback
        if result.success:
            del self._rollback_log[execution_id]

        return result

    # ── Helpers ──────────────────────────────────────────────────

    def _evaluate_conditions(self, step: PlaybookStep, event: SecurityEvent) -> bool:
        return all(c.evaluate(event) for c in step.conditions)

    async def _execute_step(self, step: PlaybookStep, event: SecurityEvent) -> ActionResult:
        now = datetime.now(tz=timezone.utc).isoformat()
        dry = self._dry_run or step.dry_run_override

        if step.action == "pagerduty_incident":
            if dry:
                return ActionResult(action="pagerduty_incident", success=True, timestamp=now,
                                    output={"dry_run": True}, dry_run=True)
            try:
                result = await asyncio.wait_for(
                    self._pagerduty.create_incident(event), timeout=step.timeout_seconds)
                if not isinstance(result, dict):
                    raise ValueError(f"PagerDuty returned {type(result).__name__}")
                return ActionResult(action="pagerduty_incident",
                                    success=result.get("status") != "error",
                                    timestamp=now, output=result)
            except asyncio.TimeoutError:
                return ActionResult(action="pagerduty_incident", success=False, timestamp=now,
                                    error=f"PagerDuty timed out after {step.timeout_seconds}s")
            except Exception as exc:
                return ActionResult(action="pagerduty_incident", success=False,
                                    timestamp=now, error=str(exc))

        executor = ActionExecutor(
            actions=[step.action], approval_required=step.approval_required,
            dry_run=dry, rate_limit_per_minute=120,
            approval_queue=self._approval_queue,
        )
        try:
            results = await asyncio.wait_for(
                executor.run(event), timeout=step.timeout_seconds)
            return (results[0] if results else
                    ActionResult(action=step.action, success=False, timestamp=now,
                                 error="No result returned from executor"))
        except asyncio.TimeoutError:
            return ActionResult(action=step.action, success=False, timestamp=now,
                                error=f"Step timed out after {step.timeout_seconds}s")

    async def select_playbook(self, event: SecurityEvent) -> Optional[str]:
        mapping = {
            "abnormal_file_encryption": "ransomware_response",
            "data_exfiltration":        "data_exfiltration_response",
            "lateral_movement":         "lateral_movement_response",
            "credential_dump":          "credential_compromise",
            "suspicious_login":         "credential_compromise",
            "privilege_escalation":     "lateral_movement_response",
        }
        playbook = mapping.get(event.event_type.lower())
        if not playbook and event.severity.lower() in ("critical", "high"):
            playbook = "credential_compromise"
        return playbook
