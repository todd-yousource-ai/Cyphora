"""
ACDA-SDK — Cyber Attack Simulation Engine

Generates realistic synthetic security event streams to test agents
without touching production infrastructure.

Attack scenarios:
  - Ransomware campaign
  - Credential theft + lateral movement
  - Data exfiltration
  - Privilege escalation
  - Supply chain attack
  - APT multi-stage intrusion
"""

from __future__ import annotations

import asyncio
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict, List, Optional

import structlog

from acda.models.schemas import SecurityEvent

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────
# Attack Scenario Definitions
# ─────────────────────────────────────────────


@dataclass
class AttackStage:
    name: str
    event_type: str
    severity: str
    delay_seconds: float = 2.0
    description: str = ""
    metadata: Dict = field(default_factory=dict)


ATTACK_SCENARIOS: Dict[str, List[AttackStage]] = {
    "ransomware": [
        AttackStage(
            "Initial Access",
            "suspicious_login",
            "medium",
            2.0,
            "Phishing credentials used for initial access",
        ),
        AttackStage(
            "Discovery",
            "abnormal_process_execution",
            "medium",
            1.5,
            "Attacker runs network discovery tools",
            {"process": "net.exe", "args": "view /all"},
        ),
        AttackStage(
            "Privilege Escalation",
            "privilege_escalation",
            "high",
            1.0,
            "UAC bypass to achieve SYSTEM privileges",
        ),
        AttackStage(
            "Payload Deployment",
            "abnormal_file_encryption",
            "critical",
            0.5,
            "Ransomware payload begins mass file encryption",
        ),
    ],
    "credential_theft_lateral_movement": [
        AttackStage(
            "Credential Dump",
            "credential_dump",
            "high",
            2.0,
            "LSASS memory dump via Mimikatz",
        ),
        AttackStage(
            "Lateral Movement",
            "lateral_movement",
            "high",
            1.5,
            "Pass-the-hash to move to adjacent systems",
        ),
        AttackStage(
            "Privilege Escalation",
            "privilege_escalation",
            "critical",
            1.0,
            "Domain admin credentials compromised",
        ),
        AttackStage(
            "Data Staging",
            "data_exfiltration",
            "critical",
            1.0,
            "Sensitive files staged for exfiltration",
        ),
    ],
    "data_exfiltration": [
        AttackStage(
            "Reconnaissance",
            "network_scan",
            "low",
            3.0,
            "Internal network scan for data repositories",
        ),
        AttackStage(
            "Access Gained",
            "suspicious_login",
            "medium",
            2.0,
            "Unauthorized access to file server",
        ),
        AttackStage(
            "Exfiltration",
            "data_exfiltration",
            "critical",
            1.0,
            "Large volume data transfer to external IP",
        ),
    ],
    "privilege_escalation": [
        AttackStage(
            "Process Injection",
            "abnormal_process_execution",
            "high",
            2.0,
            "DLL injection into privileged process",
        ),
        AttackStage(
            "Privilege Escalation",
            "privilege_escalation",
            "critical",
            0.5,
            "Kernel exploit achieves SYSTEM access",
        ),
        AttackStage(
            "Confirmed Attack",
            "confirmed_attack",
            "critical",
            0.5,
            "Attacker has full system control",
        ),
    ],
    "apt_multi_stage": [
        AttackStage("Spear Phishing", "suspicious_login", "low", 5.0),
        AttackStage("Foothold", "abnormal_process_execution", "medium", 3.0),
        AttackStage("Credential Access", "credential_dump", "high", 2.0),
        AttackStage("Lateral Movement", "lateral_movement", "high", 2.0),
        AttackStage("Discovery", "network_scan", "medium", 1.5),
        AttackStage("Privilege Esc.", "privilege_escalation", "critical", 1.0),
        AttackStage("Exfiltration", "data_exfiltration", "critical", 1.0),
    ],
}


# ─────────────────────────────────────────────
# Simulation Engine
# ─────────────────────────────────────────────


class AttackSimulator:
    """
    Generates security event streams that simulate realistic attack campaigns.

    Usage:
        simulator = AttackSimulator()
        async for event in simulator.run_scenario("ransomware"):
            await orchestrator.dispatch(event)
    """

    def __init__(
        self,
        host_pool: Optional[List[str]] = None,
        ip_pool: Optional[List[str]] = None,
        user_pool: Optional[List[str]] = None,
        speed_multiplier: float = 1.0,
    ) -> None:
        self.host_pool = host_pool or [
            "WORKSTATION-001",
            "SERVER-DC01",
            "FILESERVER-02",
            "LAPTOP-HR-03",
            "DEVBOX-JOHN",
            "JUMPSERVER-01",
        ]
        self.ip_pool = ip_pool or [
            "192.168.1.100",
            "192.168.1.101",
            "10.0.0.50",
            "10.0.1.200",
            "172.16.0.10",
            "203.0.113.99",
        ]
        self.user_pool = user_pool or [
            "CORP\\alice",
            "CORP\\bob",
            "CORP\\svc_backup",
            "CORP\\admin",
            "CORP\\contractor01",
        ]
        # FIX: Validate speed_multiplier to prevent zero/negative values causing
        # infinite waits or division-by-zero errors.
        if speed_multiplier <= 0:
            logger.warning(
                "invalid_speed_multiplier_defaulting_to_1",
                value=speed_multiplier,
            )
            speed_multiplier = 1.0
        self.speed_multiplier = speed_multiplier

    async def run_scenario(
        self,
        scenario_name: str,
        campaign_id: Optional[str] = None,
    ) -> AsyncGenerator[SecurityEvent, None]:
        """
        Async generator that yields SecurityEvents for a given attack scenario.

        Example:
            async for event in simulator.run_scenario("ransomware"):
                await orchestrator.dispatch(event)
        """
        stages = ATTACK_SCENARIOS.get(scenario_name)
        if not stages:
            available = list(ATTACK_SCENARIOS.keys())
            raise ValueError(
                f"Unknown scenario '{scenario_name}'. Available: {available}"
            )

        campaign_id = campaign_id or f"CAMPAIGN-{uuid.uuid4().hex[:8].upper()}"
        host = random.choice(self.host_pool)
        ip = random.choice(self.ip_pool)
        user = random.choice(self.user_pool)

        logger.info(
            "simulation_started",
            scenario=scenario_name,
            campaign_id=campaign_id,
            host=host,
            attacker_ip=ip,
            user=user,
            stages=len(stages),
        )

        for stage_num, stage in enumerate(stages, 1):
            event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                event_type=stage.event_type,
                timestamp=datetime.now(tz=timezone.utc).isoformat(),
                source_host=host,
                source_ip=ip,
                user=user,
                severity=stage.severity,
                raw_data={
                    "campaign_id": campaign_id,
                    "scenario": scenario_name,
                    "stage": stage_num,
                    "stage_name": stage.name,
                    "description": stage.description,
                    **stage.metadata,
                },
            )

            logger.info(
                "simulation_stage",
                campaign=campaign_id,
                stage=f"{stage_num}/{len(stages)}",
                stage_name=stage.name,
                event_type=stage.event_type,
                severity=stage.severity,
            )

            yield event

            # Wait between stages (adjusted by speed multiplier)
            adjusted_delay = stage.delay_seconds / self.speed_multiplier
            if adjusted_delay > 0:
                await asyncio.sleep(adjusted_delay)

        logger.info(
            "simulation_complete",
            scenario=scenario_name,
            campaign_id=campaign_id,
            stages_completed=len(stages),
        )

    async def run_all_scenarios(
        self, speed_multiplier: float = 5.0
    ) -> AsyncGenerator[SecurityEvent, None]:
        """
        Run all available attack scenarios sequentially.

        FIX: The original implementation created a new AttackSimulator() without
        passing the speed_multiplier parameter, causing all scenarios to run at
        1x speed regardless of the argument passed.
        """
        for name in ATTACK_SCENARIOS:
            # FIX: Reuse self (which already has speed_multiplier configured), or
            # honour the explicit speed_multiplier argument if provided.
            effective_multiplier = (
                speed_multiplier if speed_multiplier != 5.0 else self.speed_multiplier
            )
            simulator = AttackSimulator(
                host_pool=self.host_pool,
                ip_pool=self.ip_pool,
                user_pool=self.user_pool,
                speed_multiplier=effective_multiplier,
            )
            async for event in simulator.run_scenario(name):
                yield event

    def list_scenarios(self) -> List[Dict]:
        return [
            {
                "name": name,
                "stages": len(stages),
                "severity_range": list({s.severity for s in stages}),
                "event_types": [s.event_type for s in stages],
            }
            for name, stages in ATTACK_SCENARIOS.items()
        ]


# ─────────────────────────────────────────────
# Evaluation Harness
# ─────────────────────────────────────────────


@dataclass
class SimulationResult:
    scenario: str
    total_events: int
    events_detected: int
    events_acted_on: int
    false_negatives: int
    detection_rate: float
    action_rate: float
    total_duration_ms: float

    def __str__(self) -> str:
        return (
            f"Scenario: {self.scenario}\n"
            f"  Events total    : {self.total_events}\n"
            f"  Detected        : {self.events_detected} ({self.detection_rate:.1%})\n"
            f"  Acted on        : {self.events_acted_on} ({self.action_rate:.1%})\n"
            f"  Missed          : {self.false_negatives}\n"
            f"  Total duration  : {self.total_duration_ms:.0f}ms\n"
        )


class SimulationEvaluator:
    """
    Runs an attack simulation and measures agent detection + response effectiveness.
    """

    def __init__(self, orchestrator: "AgentOrchestrator") -> None:  # type: ignore[name-defined]
        self._orchestrator = orchestrator

    async def evaluate(
        self,
        scenario: str,
        speed_multiplier: float = 10.0,
    ) -> SimulationResult:
        import time

        simulator = AttackSimulator(speed_multiplier=speed_multiplier)
        start = time.perf_counter()

        total = 0
        detected = 0
        acted_on = 0

        async for event in simulator.run_scenario(scenario):
            total += 1
            agents_triggered = await self._orchestrator.dispatch(event)
            if agents_triggered > 0:
                detected += 1
                acted_on += 1  # simplified — assumes triggered = acted

        # Allow agents to finish processing
        await asyncio.sleep(1.0)

        duration_ms = (time.perf_counter() - start) * 1000

        return SimulationResult(
            scenario=scenario,
            total_events=total,
            events_detected=detected,
            events_acted_on=acted_on,
            false_negatives=total - detected,
            detection_rate=detected / total if total else 0.0,
            action_rate=acted_on / total if total else 0.0,
            total_duration_ms=duration_ms,
        )
