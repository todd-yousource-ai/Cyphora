"""
Cyphora-S1 — Example: Natural Language Query Interface
=======================================================
Demonstrates NLQueryEngine used both standalone and via the
CyphoraNLQueryAgent through the ACDA-SDK orchestrator:

  • direct NLQueryEngine.query() for ad-hoc queries
  • interactive terminal session for SOC demos
  • agent-based dispatch via nl_query events

Run from the project root:
    python examples/run_cyphora_nl_query.py

Set ANTHROPIC_API_KEY for Claude-powered NL parsing.
"""

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyphora_s1.cyphora_ingest import register_all_adapters
from cyphora_s1.nl_query_engine import NLQueryEngine
from acda.agents.cyphora_agents import CyphoraNLQueryAgent
from acda.orchestrator.orchestrator import AgentOrchestrator
from acda.models.schemas import SecurityEvent

# ── Sample queries used in the demo ──────────────────────────
SAMPLE_QUERIES = [
    "Show me all failed logins from external IPs in the last 6 hours",
    "Which users accessed production S3 buckets after 10 PM last week?",
    "Find any CrowdStrike alerts rated high or critical today",
    "List every privilege escalation event on Windows hosts in the last 30 minutes",
]


async def demo_direct_nl_query() -> None:
    """Use NLQueryEngine directly — no orchestrator needed."""
    print("\n── Direct NLQueryEngine Usage ───────────────────────────")

    engine = NLQueryEngine(llm_model="claude-sonnet-4-6")

    for query_text in SAMPLE_QUERIES:
        print(f"\n  Query : {query_text!r}")
        try:
            result = await engine.query(query_text)
            print(f"  Records  : {result.record_count}")
            print(f"  Time (ms): {result.execution_time_ms:.0f}")
            # Print a snippet of the formatted output
            output_preview = (
                result.formatted_output[:400]
                if result.formatted_output
                else "(no output)"
            )
            print(f"  Output preview:\n{output_preview}")
        except Exception as exc:
            print(f"  [!] Query failed: {exc}")


async def demo_interactive_session() -> None:
    """
    Launch an interactive terminal session.
    Type security questions at the prompt; enter 'quit' to exit.
    Ideal for POC demonstrations with a live audience.
    """
    print("\n── Interactive NL Query Session ─────────────────────────")
    print("  Type a plain-English security question and press Enter.")
    print("  Type 'quit' to exit.\n")

    engine = NLQueryEngine(llm_model="claude-sonnet-4-6")

    # interactive_session() handles the REPL loop internally
    await engine.interactive_session()


async def demo_nl_query_agent() -> None:
    """
    Dispatch an nl_query event through the CyphoraNLQueryAgent.
    Shows how the dashboard/API would trigger a natural language query.
    """
    print("\n── CyphoraNLQueryAgent via Orchestrator ─────────────────")

    register_all_adapters()

    agent = CyphoraNLQueryAgent()
    orchestrator = AgentOrchestrator()
    orchestrator.register_agents([agent])
    await orchestrator.start()

    # The NL query text lives in event.raw_data["query"]
    event = SecurityEvent(
        event_id="demo-nlq-001",
        event_type="nl_query",
        severity="low",
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source_ip="192.168.1.1",
        user_id="analyst@corp.example",
        host="soc-dashboard",
        raw_data={
            "query": "Show me all failed logins from external IPs in the last 6 hours"
        },
    )

    triggered = await orchestrator.dispatch(event)
    print(f"  Event dispatched: {event.event_type!r} → {triggered} agent(s)")

    await asyncio.sleep(8)

    status = orchestrator.status()
    for agent_name, stats in status.items():
        print(f"\n  Agent : {agent_name}")
        print(
            f"  Status: completed={stats.get('completed', 0)}  errors={stats.get('errors', 0)}"
        )

    await orchestrator.stop()


async def main() -> None:
    print("\n" + "=" * 60)
    print("  Cyphora-S1  |  Natural Language Query Demo")
    print("=" * 60)

    await demo_direct_nl_query()
    await demo_nl_query_agent()

    # Uncomment to launch the interactive REPL:
    # await demo_interactive_session()

    print("\n[✓] NL Query demo complete.\n")


if __name__ == "__main__":
    asyncio.run(main())
