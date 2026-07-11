"""
Cyphora-S1 — Example: Compliance Evidence Automation
=====================================================
Demonstrates ComplianceEngine used standalone and via the
CyphoraComplianceAgent through the ACDA-SDK orchestrator:

  • generate a SOC 2 Type II evidence report directly
  • generate all 5 framework reports in parallel
  • run the compliance agent via a compliance_check event
  • export a markdown report to disk

Run from the project root:
    python examples/run_cyphora_compliance.py

No external credentials are required — the engine uses simulated
telemetry when live connectors are not configured.
"""

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyphora_s1.cyphora_ingest import register_all_adapters
from cyphora_s1.compliance_engine import ComplianceEngine
from acda.agents.cyphora_agents import CyphoraComplianceAgent
from acda.orchestrator.orchestrator import AgentOrchestrator
from acda.models.schemas import SecurityEvent

# Supported framework keys
FRAMEWORKS = ["soc2", "iso27001", "pci_dss", "hipaa", "nis2"]


async def demo_single_framework() -> None:
    """Generate a SOC 2 evidence report using ComplianceEngine directly."""
    print("\n── Single Framework: SOC 2 Type II ─────────────────────")

    engine = ComplianceEngine()
    report = await engine.generate_report("soc2", lookback_days=90)

    print(f"  Framework  : {report.framework}")
    print(f"  Period     : {report.period_start}  →  {report.period_end}")
    print(f"  Compliance : {report.compliance_percentage:.1f}%")
    print(
        f"  Controls   : {report.controls_satisfied} / {report.controls_total} satisfied"
    )

    # FrameworkReport exposes per-control `findings`; a "gap" is a finding
    # whose status == "gap". Derive the gap list from findings rather than a
    # non-existent report.gaps attribute.
    gaps = [f for f in report.findings if f.status == "gap"]
    if gaps:
        print(f"\n  Gaps ({len(gaps)}):")
        for gap in gaps[:5]:  # show first 5
            print(
                f"    • [{gap.control.control_id}] {gap.control.title} — "
                f"{gap.recommendation}"
            )

    # Export to markdown
    md = engine.export_markdown(report)
    output_path = Path("soc2_compliance_report.md")
    output_path.write_text(md)
    print(f"\n  [✓] Markdown report saved to: {output_path}")


async def demo_all_frameworks() -> None:
    """Generate all 5 framework reports in parallel."""
    print("\n── All Frameworks (parallel) ────────────────────────────")

    engine = ComplianceEngine()
    all_reports = await engine.generate_all_frameworks(lookback_days=90)

    print(f"\n  {'Framework':<18}  {'Compliance':>11}  {'Controls':>15}")
    print("  " + "-" * 50)
    for fw, rpt in all_reports.items():
        bar_len = int(rpt.compliance_percentage / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(
            f"  {fw:<18}  {rpt.compliance_percentage:>9.1f}%  "
            f"  {rpt.controls_satisfied:>3}/{rpt.controls_total:<3}  {bar}"
        )


async def demo_compliance_agent() -> None:
    """Run CyphoraComplianceAgent through the full orchestrator pipeline."""
    print("\n── CyphoraComplianceAgent via Orchestrator ──────────────")

    register_all_adapters()

    agent = CyphoraComplianceAgent(lookback_days=90)
    orchestrator = AgentOrchestrator()
    orchestrator.register_agents([agent])
    await orchestrator.start()

    # compliance_check is the event that triggers this agent
    event = SecurityEvent(
        event_id="demo-compliance-001",
        event_type="compliance_check",
        severity="low",
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source_ip="127.0.0.1",
        user_id="system",
        host="cyphora-scheduler",
        raw_data={"frameworks": FRAMEWORKS, "triggered_by": "weekly_schedule"},
    )

    triggered = await orchestrator.dispatch(event)
    print(f"  Event dispatched: {event.event_type!r} → {triggered} agent(s)")

    # Compliance reports take longer — give up to 30s in demo
    await asyncio.sleep(30)

    status = orchestrator.status()
    per_agent = status.get("per_agent", {})
    for agent_name, stats in per_agent.items():
        print(f"\n  Agent : {agent_name}")
        print(
            f"  Status: completed={stats.get('completed', 0)}  errors={stats.get('errors', 0)}"
        )

        last_report = stats.get("last_report")
        if last_report:
            extras = getattr(last_report, "__dict__", {}).get("extras", {})
            fw_reports = extras.get("compliance_reports", {})
            if fw_reports:
                print(f"\n  Compliance summary ({len(fw_reports)} frameworks):")
                for fw, rpt in fw_reports.items():
                    print(f"    {fw:<18}  {rpt.compliance_percentage:.1f}%")

    await orchestrator.stop()


async def main() -> None:
    print("\n" + "=" * 60)
    print("  Cyphora-S1  |  Compliance Automation Demo")
    print("=" * 60)

    await demo_single_framework()
    await demo_all_frameworks()
    await demo_compliance_agent()

    print("\n[✓] Compliance demo complete.\n")


if __name__ == "__main__":
    asyncio.run(main())
