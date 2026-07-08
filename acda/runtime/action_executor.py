"""
ACDA-SDK — Action Executor

Executes defense actions through platform integrations.
Enforces approval workflows, rate limits, dry-run mode, and audit logging.

BUG 6 FIX: High-risk actions (isolate_host, disable_account) no longer
proceed automatically after logging a warning.  They are now submitted
to an ApprovalQueue and execution is suspended until an analyst approves
or denies, or the auto-deny timeout expires.  This satisfies compliance
requirements in regulated industries where autonomous high-risk actions
are prohibited without human approval.
"""

from __future__ import annotations

import asyncio
import collections
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

import structlog

from acda.models.schemas import ActionResult, SecurityEvent

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────
# Action Risk Classification
# ─────────────────────────────────────────────

ACTION_RISK_LEVELS: Dict[str, str] = {
    "generate_incident_report": "none",
    "notify_soc":               "none",
    "create_threat_alert":      "none",
    "snapshot_memory":          "none",
    "quarantine_file":          "medium_risk",
    "kill_process":             "medium_risk",
    "block_ip":                 "medium_risk",
    "revoke_token":             "medium_risk",
    "isolate_host":             "high_risk",
    "disable_account":          "high_risk",
}

APPROVAL_HIERARCHY = ["none", "low_risk", "medium_risk", "high_risk", "critical"]


# ─────────────────────────────────────────────
# BUG 6 FIX: Approval Queue
# ─────────────────────────────────────────────

from enum import Enum
from dataclasses import dataclass, field as dc_field


class ApprovalStatus(str, Enum):
    PENDING      = "pending"
    APPROVED     = "approved"
    DENIED       = "denied"
    AUTO_DENIED  = "auto_denied"   # timed out without analyst response
    AUTO_APPROVED = "auto_approved" # configured for autonomous mode


@dataclass
class PendingApproval:
    """A high-risk action waiting for analyst review."""
    approval_id:  str
    action_name:  str
    event_id:     str
    event_type:   str
    source_host:  Optional[str]
    source_ip:    Optional[str]
    user:         Optional[str]
    risk_level:   str
    requested_at: str
    status:       ApprovalStatus = ApprovalStatus.PENDING
    analyst_id:   Optional[str]  = None
    analyst_note: Optional[str]  = None
    resolved_at:  Optional[str]  = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id":  self.approval_id,
            "action_name":  self.action_name,
            "event_id":     self.event_id,
            "event_type":   self.event_type,
            "source_host":  self.source_host,
            "source_ip":    self.source_ip,
            "user":         self.user,
            "risk_level":   self.risk_level,
            "requested_at": self.requested_at,
            "status":       self.status.value,
            "analyst_id":   self.analyst_id,
            "analyst_note": self.analyst_note,
            "resolved_at":  self.resolved_at,
        }


class ApprovalQueue:
    """
    In-memory approval queue for high-risk actions.

    In production this would be backed by Redis so that multiple
    Cyphora-S1 replicas and the SOC UI all share the same queue.
    The interface is identical — only the storage backend changes.

    Usage:
        queue = ApprovalQueue(auto_deny_seconds=300)
        approval = await queue.submit(action_name, event)
        # analyst calls queue.approve(approval_id) or queue.deny(...)
        result = await queue.wait_for_decision(approval_id, timeout=300)
    """

    def __init__(self, auto_deny_seconds: int = 300) -> None:
        self._queue:    Dict[str, PendingApproval]     = {}
        self._events:   Dict[str, asyncio.Event]       = {}
        self._auto_deny_seconds = auto_deny_seconds

    # ── Submit ──────────────────────────────────────────────────

    async def submit(self, action_name: str, event: SecurityEvent) -> PendingApproval:
        """Create a pending approval record and return it."""
        approval_id = str(uuid.uuid4())
        now = datetime.now(tz=timezone.utc).isoformat()
        pending = PendingApproval(
            approval_id  = approval_id,
            action_name  = action_name,
            event_id     = event.event_id,
            event_type   = event.event_type,
            source_host  = event.source_host,
            source_ip    = event.source_ip,
            user         = event.user,
            risk_level   = ACTION_RISK_LEVELS.get(action_name, "medium_risk"),
            requested_at = now,
        )
        self._queue[approval_id]  = pending
        self._events[approval_id] = asyncio.Event()

        logger.info(
            "approval_required",
            approval_id  = approval_id,
            action       = action_name,
            event_id     = event.event_id,
            risk_level   = pending.risk_level,
            auto_deny_in = f"{self._auto_deny_seconds}s",
        )
        return pending

    # ── Analyst decisions ────────────────────────────────────────

    def approve(self, approval_id: str, analyst_id: str = "analyst",
                note: str = "") -> bool:
        """Mark a pending approval as approved. Returns False if not found."""
        pending = self._queue.get(approval_id)
        if not pending or pending.status != ApprovalStatus.PENDING:
            return False
        pending.status      = ApprovalStatus.APPROVED
        pending.analyst_id  = analyst_id
        pending.analyst_note = note
        pending.resolved_at = datetime.now(tz=timezone.utc).isoformat()
        logger.info("approval_approved", approval_id=approval_id, analyst=analyst_id)
        if ev := self._events.get(approval_id):
            ev.set()
        return True

    def deny(self, approval_id: str, analyst_id: str = "analyst",
             note: str = "") -> bool:
        """Mark a pending approval as denied. Returns False if not found."""
        pending = self._queue.get(approval_id)
        if not pending or pending.status != ApprovalStatus.PENDING:
            return False
        pending.status       = ApprovalStatus.DENIED
        pending.analyst_id   = analyst_id
        pending.analyst_note = note
        pending.resolved_at  = datetime.now(tz=timezone.utc).isoformat()
        logger.info("approval_denied", approval_id=approval_id, analyst=analyst_id)
        if ev := self._events.get(approval_id):
            ev.set()
        return True

    # ── Wait for decision ────────────────────────────────────────

    async def wait_for_decision(
        self, approval_id: str, timeout: Optional[float] = None
    ) -> ApprovalStatus:
        """
        Suspend until an analyst approves/denies, or the timeout fires.
        Returns the final ApprovalStatus.
        """
        wait_secs = timeout if timeout is not None else float(self._auto_deny_seconds)
        ev = self._events.get(approval_id)
        if ev is None:
            return ApprovalStatus.DENIED

        try:
            await asyncio.wait_for(ev.wait(), timeout=wait_secs)
        except asyncio.TimeoutError:
            pending = self._queue.get(approval_id)
            if pending and pending.status == ApprovalStatus.PENDING:
                pending.status      = ApprovalStatus.AUTO_DENIED
                pending.resolved_at = datetime.now(tz=timezone.utc).isoformat()
                logger.warning(
                    "approval_auto_denied_timeout",
                    approval_id = approval_id,
                    action      = pending.action_name,
                    timeout     = wait_secs,
                )
            return ApprovalStatus.AUTO_DENIED

        pending = self._queue.get(approval_id)
        return pending.status if pending else ApprovalStatus.DENIED

    def list_pending(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self._queue.values()
                if p.status == ApprovalStatus.PENDING]

    def get(self, approval_id: str) -> Optional[PendingApproval]:
        return self._queue.get(approval_id)


# Module-level default queue (replaced per-tenant in production)
_DEFAULT_APPROVAL_QUEUE = ApprovalQueue(auto_deny_seconds=300)


# ─────────────────────────────────────────────
# Action Implementations (Simulation)
# ─────────────────────────────────────────────

class ActionLibrary:
    async def isolate_host(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        host_id = event.source_host or "unknown_host"
        logger.info("action_isolate_host", host_id=host_id, dry_run=kw.get("dry_run"))
        await asyncio.sleep(0.1)
        return {"action": "isolate_host", "host_id": host_id,
                "isolation_id": str(uuid.uuid4()), "platform": "EDR_SIM",
                "message": f"Host {host_id} isolated from network."}

    async def block_ip(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        ip = event.source_ip or "0.0.0.0"
        logger.info("action_block_ip", ip=ip, dry_run=kw.get("dry_run"))
        await asyncio.sleep(0.05)
        return {"action": "block_ip", "ip_address": ip,
                "rule_id": f"FW-RULE-{uuid.uuid4().hex[:8].upper()}",
                "platform": "FIREWALL_SIM",
                "message": f"IP {ip} blocked at network perimeter."}

    async def disable_account(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        user = event.user or "unknown_user"
        logger.info("action_disable_account", user=user, dry_run=kw.get("dry_run"))
        await asyncio.sleep(0.08)
        return {"action": "disable_account", "user_id": user,
                "ticket_id": f"INC-{uuid.uuid4().hex[:6].upper()}",
                "platform": "IAM_SIM",
                "message": f"Account {user} disabled and sessions revoked."}

    async def revoke_token(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        user = event.user or "unknown_user"
        await asyncio.sleep(0.03)
        return {"action": "revoke_token", "user_id": user, "tokens_revoked": 3,
                "platform": "OAUTH_SIM",
                "message": f"All active tokens revoked for {user}."}

    async def kill_process(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        process = event.process or "unknown.exe"
        host = event.source_host or "unknown_host"
        await asyncio.sleep(0.05)
        return {"action": "kill_process", "process": process, "host": host,
                "pid": "12345", "platform": "EDR_SIM",
                "message": f"Process {process} terminated on {host}."}

    async def quarantine_file(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        host = event.source_host or "unknown_host"
        await asyncio.sleep(0.04)
        return {"action": "quarantine_file", "host": host, "files_quarantined": 1,
                "platform": "EDR_SIM", "message": "Suspicious file quarantined."}

    async def notify_soc(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        await asyncio.sleep(0.01)
        ticket_id = f"SOC-{uuid.uuid4().hex[:6].upper()}"
        return {"action": "notify_soc", "ticket_id": ticket_id,
                "channel": "slack::#soc-alerts", "email": "soc@company.com",
                "message": f"SOC notified. Ticket {ticket_id} created."}

    async def generate_incident_report(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        await asyncio.sleep(0.02)
        report_id = f"IR-{datetime.now(tz=timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        return {"action": "generate_incident_report", "report_id": report_id,
                "event_id": event.event_id, "severity": event.severity,
                "message": f"Incident report {report_id} generated and filed."}

    async def create_threat_alert(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        await asyncio.sleep(0.01)
        alert_id = f"ALERT-{uuid.uuid4().hex[:8].upper()}"
        return {"action": "create_threat_alert", "alert_id": alert_id,
                "event_type": event.event_type, "severity": event.severity,
                "message": f"Threat alert {alert_id} raised in SIEM."}

    async def snapshot_memory(self, event: SecurityEvent, **kw) -> Dict[str, Any]:
        host = event.source_host or "unknown_host"
        await asyncio.sleep(0.15)
        return {"action": "snapshot_memory", "host": host,
                "snapshot_id": str(uuid.uuid4()), "platform": "FORENSICS_SIM",
                "message": f"Memory snapshot captured from {host}."}


_ACTION_LIBRARY = ActionLibrary()
_ACTION_METHODS: Dict[str, Any] = {
    "isolate_host":            _ACTION_LIBRARY.isolate_host,
    "block_ip":                _ACTION_LIBRARY.block_ip,
    "disable_account":         _ACTION_LIBRARY.disable_account,
    "revoke_token":            _ACTION_LIBRARY.revoke_token,
    "kill_process":            _ACTION_LIBRARY.kill_process,
    "quarantine_file":         _ACTION_LIBRARY.quarantine_file,
    "notify_soc":              _ACTION_LIBRARY.notify_soc,
    "generate_incident_report":_ACTION_LIBRARY.generate_incident_report,
    "create_threat_alert":     _ACTION_LIBRARY.create_threat_alert,
    "snapshot_memory":         _ACTION_LIBRARY.snapshot_memory,
}


# ─────────────────────────────────────────────
# Action Executor
# ─────────────────────────────────────────────

class ActionExecutor:
    """
    Executes a list of named defense actions.

    BUG 6 FIX: High-risk actions now submit to ApprovalQueue and wait
    for an analyst decision instead of blindly proceeding.  The
    approval_mode parameter controls behaviour:
      "auto"   — actions above the configured approval_required level
                 are submitted to the queue; execution waits up to
                 auto_approve_seconds, then auto-denies if no response.
      "manual" — same but with a longer default timeout.

    Callers can inject a custom ApprovalQueue (e.g. per-tenant) via
    the approval_queue parameter.
    """

    def __init__(
        self,
        actions: List[str],
        approval_required: str = "none",
        dry_run: bool = False,
        rate_limit_per_minute: int = 60,
        approval_mode: str = "auto",
        auto_approve_seconds: int = 300,
        approval_queue: Optional[ApprovalQueue] = None,
    ) -> None:
        self.actions               = actions
        self.approval_required     = approval_required
        self.dry_run               = dry_run
        self.rate_limit_per_minute = rate_limit_per_minute
        self.approval_mode         = approval_mode
        self.auto_approve_seconds  = auto_approve_seconds
        self._approval_queue       = approval_queue or _DEFAULT_APPROVAL_QUEUE
        self._execution_log: List[ActionResult] = []
        self._rate_window: Deque[float] = collections.deque()

    def _check_rate_limit(self) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0
        while self._rate_window and self._rate_window[0] < cutoff:
            self._rate_window.popleft()
        if len(self._rate_window) >= self.rate_limit_per_minute:
            return False
        self._rate_window.append(now)
        return True

    async def run(
        self,
        event: SecurityEvent,
        action_names: Optional[List[str]] = None,
    ) -> List[ActionResult]:
        targets = action_names or self.actions
        if not targets:
            return []

        tasks = [self._execute_single(action, event) for action in targets]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        results: List[ActionResult] = []
        now = datetime.now(tz=timezone.utc).isoformat()
        for action_name, outcome in zip(targets, raw_results):
            if isinstance(outcome, BaseException):
                logger.error("action_executor_unexpected_error",
                             action=action_name, error=str(outcome))
                results.append(ActionResult(action=action_name, success=False,
                                            timestamp=now, error=f"Unexpected: {outcome}"))
            else:
                results.append(outcome)
        self._execution_log.extend(results)
        return results

    async def _execute_single(self, action_name: str, event: SecurityEvent) -> ActionResult:
        now = datetime.now(tz=timezone.utc).isoformat()

        # ── Rate limit ──────────────────────────────────────────
        if not self._check_rate_limit():
            logger.warning("action_rate_limit_exceeded", action=action_name,
                           limit=self.rate_limit_per_minute)
            return ActionResult(action=action_name, success=False, timestamp=now,
                                error=f"Rate limit exceeded: max {self.rate_limit_per_minute}/min")

        # ── Dry-run ─────────────────────────────────────────────
        if self.dry_run:
            logger.info("dry_run_action", action=action_name, event_id=event.event_id)
            return ActionResult(action=action_name, success=True, timestamp=now,
                                output={"dry_run": True, "would_execute": action_name},
                                dry_run=True)

        # ── Unknown action ──────────────────────────────────────
        handler = _ACTION_METHODS.get(action_name)
        if handler is None:
            logger.error("unknown_action", action=action_name)
            return ActionResult(action=action_name, success=False, timestamp=now,
                                error=f"Unknown action: '{action_name}'")

        # ── BUG 6 FIX: Approval gate for high-risk actions ──────
        action_risk = ACTION_RISK_LEVELS.get(action_name, "medium_risk")
        required_idx = APPROVAL_HIERARCHY.index(
            self.approval_required if self.approval_required in APPROVAL_HIERARCHY else "none"
        )
        action_risk_idx = APPROVAL_HIERARCHY.index(
            action_risk if action_risk in APPROVAL_HIERARCHY else "medium_risk"
        )

        if action_risk_idx > required_idx:
            # Action risk exceeds the configured approval threshold —
            # submit to queue and wait for analyst decision.
            pending = await self._approval_queue.submit(action_name, event)
            decision = await self._approval_queue.wait_for_decision(
                pending.approval_id, timeout=float(self.auto_approve_seconds)
            )

            if decision in (ApprovalStatus.DENIED, ApprovalStatus.AUTO_DENIED):
                reason = ("auto-denied: timeout" if decision == ApprovalStatus.AUTO_DENIED
                          else f"denied by analyst {pending.analyst_id}")
                logger.warning(
                    "action_denied_by_approval_queue",
                    action      = action_name,
                    approval_id = pending.approval_id,
                    reason      = reason,
                )
                return ActionResult(
                    action    = action_name,
                    success   = False,
                    timestamp = now,
                    error     = f"Action {action_name} was {reason}.",
                    output    = {"approval_id": pending.approval_id, "status": decision.value},
                )

            # APPROVED or AUTO_APPROVED — fall through to execute
            logger.info(
                "action_approved_proceeding",
                action      = action_name,
                approval_id = pending.approval_id,
                decision    = decision.value,
            )
        # ── END BUG 6 FIX ───────────────────────────────────────

        # ── Execute ─────────────────────────────────────────────
        try:
            import time as _time
            start = _time.perf_counter()
            output = await handler(event, dry_run=self.dry_run)
            elapsed_ms = (_time.perf_counter() - start) * 1000
            logger.info("action_executed", action=action_name,
                        event_id=event.event_id, elapsed_ms=round(elapsed_ms, 2))
            return ActionResult(action=action_name, success=True,
                                timestamp=now, output=output)
        except Exception as exc:
            logger.error("action_failed", action=action_name,
                         event_id=event.event_id, error=str(exc))
            return ActionResult(action=action_name, success=False,
                                timestamp=now, error=str(exc))

    @property
    def execution_log(self) -> List[ActionResult]:
        return list(self._execution_log)

    @property
    def approval_queue(self) -> ApprovalQueue:
        return self._approval_queue
