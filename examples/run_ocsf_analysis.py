"""
Cyphora-S1 — OCSF Event Analysis Runner
==========================================
End-to-end pipeline that mirrors examples/run_cef_analysis.py but for
the OCSF (Open Cybersecurity Schema Framework) ingestion path added
in this release. Demonstrates:

  1. Parsing a native OCSF file (JSON array / NDJSON / single object)
     spanning multiple vendors and multiple OCSF categories
  2. Registering category-partitioned OCSF DataCollector adapters
  3. Building SecurityEvent objects and dispatching them through the
     same AgentOrchestrator used by the CEF and live-API paths
  4. (--from-cef) Demonstrating the CEF -> OCSF bridge: converting the
     existing CEF sample file through format_normalizer.CEFToOCSFConverter
     before feeding it through the OCSF pipeline, to show that CEF,
     OCSF, and proprietary JSON all converge on one code path

Usage
-----
    # Analyse the bundled multi-vendor OCSF NDJSON sample
    python examples/run_ocsf_analysis.py

    # Analyse your own OCSF export (.json / .ndjson / .jsonl)
    python examples/run_ocsf_analysis.py --log-file /path/to/events.ndjson

    # Demonstrate CEF -> OCSF -> SecurityEvent bridging
    python examples/run_ocsf_analysis.py --from-cef data/sample_security_logs.cef

    # Dry run + verbose
    python examples/run_ocsf_analysis.py --dry-run --verbose
"""

from __future__ import annotations

import argparse
import asyncio

from acda.orchestrator.orchestrator import AgentOrchestrator
from acda.agents.cyphora_agents import (
    CyphoraInvestigationAgent,
    CyphoraUEBAAgent,
    CyphoraComplianceAgent,
    CyphoraNLQueryAgent,
)
from cyphora_s1.ocsf_adapters import OCSFSecurityEventFactory, register_ocsf_adapters
from cyphora_s1.format_normalizer import CEFToOCSFConverter
from cyphora_s1.sim_adapters import register_simulated_adapters


def build_events(args):
    if args.from_cef:
        print(f"[*] Converting CEF file via CEF->OCSF bridge: {args.from_cef}")
        converter = CEFToOCSFConverter()
        ocsf_dicts = converter.convert_file(args.from_cef)
        register_ocsf_adapters(ocsf_dicts=ocsf_dicts)
        return OCSFSecurityEventFactory.from_dicts(ocsf_dicts)

    log_file = args.log_file or "data/sample_security_logs.ocsf.ndjson"
    print(f"[*] Loading native OCSF events: {log_file}")
    register_ocsf_adapters(mixed_file=log_file)
    return OCSFSecurityEventFactory.from_file(log_file)


async def main():
    ap = argparse.ArgumentParser(description="Cyphora-S1 OCSF Analysis Runner")
    ap.add_argument("--log-file", help="Path to an OCSF .json/.ndjson/.jsonl file")
    ap.add_argument("--from-cef", help="Path to a CEF file to bridge through CEF->OCSF first")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    events = build_events(args)
    print(f"[*] {len(events)} SecurityEvent(s) ready for dispatch\n")

    # Fill in any sources not covered by OCSF telemetry with the
    # product-faithful simulated adapters, same as the CEF runner.
    register_simulated_adapters()

    orchestrator = AgentOrchestrator()
    orchestrator.register_agents([
        CyphoraInvestigationAgent(playbook_dry_run=args.dry_run or True),
        CyphoraUEBAAgent(),
        CyphoraComplianceAgent(lookback_days=90),
        CyphoraNLQueryAgent(),
    ])
    await orchestrator.start()

    completed = 0
    for event in events:
        triggered = await orchestrator.dispatch(event)
        status = "✓" if triggered else "·"
        print(f"  {status} {event.event_id:<28} {event.event_type:<28} sev={event.severity:<8} host={event.source_host or '-'}")
        if args.verbose:
            print(f"      raw_data: ocsf_class_uid={event.raw_data.get('ocsf_class_uid')} "
                  f"category={event.raw_data.get('ocsf_category_name')} vendor={event.raw_data.get('product')}")
        completed += 1 if triggered else 0

    print(f"\n[*] Done — {completed}/{len(events)} events triggered at least one agent")
    await orchestrator.stop()


if __name__ == "__main__":
    asyncio.run(main())
