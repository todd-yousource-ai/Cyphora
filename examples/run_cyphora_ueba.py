"""
Cyphora-S1 — Example: UEBA (User & Entity Behavior Analytics)
==============================================================
Demonstrates the CyphoraUEBAAgent and the UEBAEngine directly:

  • register production log-source adapters
  • run the UEBA agent against a suspicious-login event
  • call UEBAEngine standalone to score a custom user session
  • print anomaly details and risk scores

Run from the project root:
    python examples/run_cyphora_ueba.py

REDIS_URL is optional — in-memory baseline store is used as fallback.
"""

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyphora_s1.cyphora_ingest import register_all_adapters
from cyphora_s1.ueba_engine import UEBAEngine
from acda.agents.cyphora_agents import CyphoraUEBAAgent
from acda.orchestrator.orchestrator import AgentOrchestrator
from acda.models.schemas import SecurityEvent, CollectedData


async def demo_direct_ueba() -> None:
    """
    Use UEBAEngine standalone (no agent/orchestrator needed).
    Useful for one-off analysis or integration into other pipelines.
    """
    print("\n── Direct UEBAEngine Usage ──────────────────────────────")

    engine = UEBAEngine(redis_url=os.getenv("REDIS_URL"))

    # Build a synthetic event: user logging in at 3 AM from an unknown IP
    event = SecurityEvent(
        event_id="demo-ueba-001",
        event_type="suspicious_login",
        severity="high",
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source_ip="203.0.113.99",  # RFC 5737 documentation IP
        user_id="alice@corp.example",
        host="workstation-17",
        raw_data={
            "login_hour": 3,
            "failed_logins": 0,
            "bytes_transferred": 0,
            "files_written": 0,
        },
    )

    # Minimal CollectedData (normally populated by DataCollector)
    data = CollectedData(
        sources_queried=["identity_logs"],
        records=[
            {
                "source": "identity_logs",
                "event_type": "login",
                "user": "alice@corp.example",
                "source_ip": "203.0.113.99",
                "login_hour": 3,
                "success": True,
            }
        ],
        time_window_start=event.timestamp,
        time_window_end=event.timestamp,
    )

    ueba_report = await engine.analyze(event, data)

    print(f"  Entity      : {ueba_report.entity_id}")
    print(f"  Risk score  : {ueba_report.risk_score:.2f}  ({ueba_report.risk_label})")
    print(f"  Anomalous   : {ueba_report.is_anomalous}")

    if ueba_report.anomalies:
        print(f"\n  Anomalies detected ({len(ueba_report.anomalies)}):")
        for anomaly in ueba_report.anomalies:
            print(f"    • [{anomaly.feature}] score={anomaly.deviation_score:.2f}")
            print(f"      {anomaly.explanation}")
    else:
        print("  No anomalies detected (baseline may not yet be established).")


async def demo_ueba_agent() -> None:
    """
    Run CyphoraUEBAAgent through the full ACDA-SDK orchestrator pipeline.
    """
    print("\n── CyphoraUEBAAgent via Orchestrator ────────────────────")

    register_all_adapters()

    agent = CyphoraUEBAAgent(redis_url=os.getenv("REDIS_URL"))
    orchestrator = AgentOrchestrator()
    orchestrator.register_agents([agent])
    await orchestrator.start()

    # Dispatch a privilege escalation event — one of the UEBA triggers
    event = SecurityEvent(
        event_id="demo-ueba-002",
        event_type="privilege_escalation",
        severity="high",
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source_ip="10.0.1.55",
        user_id="bob@corp.example",
        host="dc-server-01",
        raw_data={"sudo_command": "sudo su -", "process": "bash"},
    )

    triggered = await orchestrator.dispatch(event)
    print(f"  Event dispatched: {event.event_type!r} → {triggered} agent(s)")

    await asyncio.sleep(8)

    status = orchestrator.status()
    for agent_name, stats in status.items():
        print(f"\n  Agent   : {agent_name}")
        print(
            f"  Status  : completed={stats.get('completed', 0)}  errors={stats.get('errors', 0)}"
        )

    await orchestrator.stop()


async def main() -> None:
    print("\n" + "=" * 60)
    print("  Cyphora-S1  |  UEBA Demo")
    print("=" * 60)

    await demo_direct_ueba()
    await demo_ueba_agent()

    print("\n[✓] UEBA demo complete.\n")


if __name__ == "__main__":
    asyncio.run(main())
