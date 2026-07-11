"""
Cyphora-S1 — Example: AI Threat Investigation
==============================================
Demonstrates the full CyphoraInvestigationAgent pipeline:

  • register production log-source adapters
  • start the orchestrator with the Cyphora investigation agent
  • simulate a data-exfiltration scenario via AttackSimulator
  • print the MITRE ATT&CK techniques, kill chain, and plain-English report

Run from the project root:
    python examples/run_cyphora_investigation.py

Set at least ANTHROPIC_API_KEY (or OPENAI_API_KEY) in your environment
for LLM-powered features.  All log-source adapters fall back to simulated
data when their credentials are absent.
"""

import asyncio
import os
import sys
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ── Cyphora-S1 imports ────────────────────────────────────────
from cyphora_s1.cyphora_ingest import register_all_adapters
from acda.agents.cyphora_agents import CyphoraInvestigationAgent
from acda.orchestrator.orchestrator import AgentOrchestrator
from acda.simulation.attack_simulator import AttackSimulator


async def main() -> None:
    print("\n" + "=" * 60)
    print("  Cyphora-S1  |  AI Threat Investigation Demo")
    print("=" * 60 + "\n")

    # 1. Register production log-source adapters (reads env vars).
    #    Adapters without credentials fall back to simulated data.
    register_all_adapters()
    print("[✓] Production log-source adapters registered\n")

    # 2. Instantiate the agent.
    #    Set playbook_dry_run=True to preview playbook steps without
    #    executing real containment actions.
    agent = CyphoraInvestigationAgent(
        ueba_redis_url=os.getenv("REDIS_URL"),  # None → in-memory fallback
        playbook_dry_run=True,  # safe for demos
    )

    # 3. Start the orchestrator.
    orchestrator = AgentOrchestrator()
    orchestrator.register_agents([agent])
    await orchestrator.start()
    print("[✓] Orchestrator started\n")

    # 4. Simulate a data-exfiltration attack scenario.
    simulator = AttackSimulator(speed_multiplier=5.0)
    print("[→] Running data_exfiltration scenario …\n")

    async for event in simulator.run_scenario("data_exfiltration"):
        triggered = await orchestrator.dispatch(event)
        print(
            f"    Event dispatched: {event.event_type!r}  →  {triggered} agent(s) triggered"
        )

    # 5. Let agents finish processing.
    await asyncio.sleep(10)

    # 6. Print results from the last execution report.
    print("\n" + "─" * 60)
    print("  Investigation Results")
    print("─" * 60)

    status = orchestrator.status()
    per_agent = status.get("per_agent", {})
    for agent_name, stats in per_agent.items():
        print(f"\nAgent : {agent_name}")
        print(f"  Executions  : {stats.get('total_executions', 0)}")
        print(f"  Completed   : {stats.get('completed', 0)}")
        print(f"  Errors      : {stats.get('errors', 0)}")

        last_report = stats.get("last_report")
        if last_report:
            extras = getattr(last_report, "__dict__", {}).get("extras", {})

            attack_intel = extras.get("attack_intelligence")
            if attack_intel:
                print(f"\n  ── MITRE ATT&CK Techniques ──")
                for ttp in getattr(attack_intel, "ttps_identified", []):
                    print(
                        f"    {ttp.technique_id}: {ttp.technique} "
                        f"[{ttp.tactic}] — confidence {ttp.confidence:.2f}"
                    )

                kill_chain = getattr(attack_intel, "kill_chain_steps", [])
                if kill_chain:
                    print(f"\n  ── Kill Chain ({len(kill_chain)} steps) ──")
                    for step in kill_chain:
                        print(
                            f"    Step {step.step_number}: {step.tactic} / "
                            f"{step.technique}"
                        )

                report_md = getattr(attack_intel, "plain_english_report", "")
                if report_md:
                    print("\n  ── Plain-English Incident Report ──")
                    # Print first 800 chars of the report
                    print(report_md[:800])
                    if len(report_md) > 800:
                        print("  … (truncated — full report in production output)")

            ueba = extras.get("ueba_report")
            if ueba and getattr(ueba, "is_anomalous", False):
                print(f"\n  ── UEBA Anomaly ──")
                print(
                    f"    Entity  : {ueba.entity_id}  "
                    f"Risk: {ueba.risk_label} ({ueba.risk_score:.2f})"
                )
                for anomaly in getattr(ueba, "anomalies", []):
                    print(f"    • {anomaly.feature}: {anomaly.explanation}")

            playbook = extras.get("playbook_result")
            if playbook:
                print(f"\n  ── Playbook Execution ──")
                print(f"    Status : {playbook.status}")
                print(f"    Steps  : {playbook.steps_executed}/{playbook.steps_total}")

    await orchestrator.stop()
    print("\n[✓] Orchestrator stopped.  Demo complete.\n")


if __name__ == "__main__":
    asyncio.run(main())
