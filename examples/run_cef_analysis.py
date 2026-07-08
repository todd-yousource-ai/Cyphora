"""
Cyphora-S1 — CEF Log Analysis Runner
======================================
End-to-end pipeline that:
  1. Reads a CEF log file (CrowdStrike, Cortex XDR, Okta — single or mixed)
  2. Parses every CEF record into a SecurityEvent
  3. Registers CEF-backed DataCollector adapters so the LLM reasoning
     ensemble receives real product telemetry during investigation
  4. Dispatches each SecurityEvent through the full Cyphora-S1 agent
     pipeline (Investigation, UEBA, Compliance, NLQuery)
  5. Prints a structured, colour-coded results report

Usage
-----
    # Analyse the bundled sample log file
    python examples/run_cef_analysis.py

    # Analyse your own CEF export
    python examples/run_cef_analysis.py --log-file /path/to/export.cef

    # Separate per-vendor files
    python examples/run_cef_analysis.py \\
        --crowdstrike /var/log/cs.cef \\
        --cortex-xdr  /var/log/cortex.cef \\
        --okta        /var/log/okta.cef

    # Dry run — no real containment actions
    python examples/run_cef_analysis.py --dry-run

    # Show MITRE TTPs, UEBA scores, playbook steps
    python examples/run_cef_analysis.py --verbose

Environment
-----------
    ANTHROPIC_API_KEY   — required for AI reasoning
    OPENAI_API_KEY      — optional (GPT-4o third model)
    REDIS_URL           — optional (UEBA baseline persistence)
    CYPHORA_DRY_RUN=1   — same as --dry-run flag
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── path setup ────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ── Cyphora-S1 imports ────────────────────────────────────────────
from cyphora_s1.cef_parser import CEFParser, CEFRecord, CEFVendor
from cyphora_s1.cef_adapters import (
    register_cef_adapters,
    SecurityEventFactory,
    CrowdStrikeCEFAdapter,
    CortexXDRCEFAdapter,
    OktaCEFAdapter,
)
from cyphora_s1.cyphora_ingest import register_all_adapters
from acda.agents.cyphora_agents import (
    CyphoraInvestigationAgent,
    CyphoraUEBAAgent,
    CyphoraComplianceAgent,
    CyphoraNLQueryAgent,
)
from acda.orchestrator.orchestrator import AgentOrchestrator
from acda.models.schemas import SecurityEvent

# ── ANSI colours ──────────────────────────────────────────────────
R = "\033[91m"  # red
G = "\033[92m"  # green
Y = "\033[93m"  # yellow
C = "\033[96m"  # cyan
M = "\033[95m"  # magenta
B = "\033[94m"  # blue
DIM = "\033[2m"
BD = "\033[1m"
RS = "\033[0m"

# Vendor badge colours
VENDOR_COLOUR = {
    CEFVendor.CROWDSTRIKE: "\033[91m",  # red
    CEFVendor.PALO_ALTO: "\033[38;5;208m",  # orange
    CEFVendor.OKTA: "\033[94m",  # blue
    CEFVendor.UNKNOWN: "\033[2m",
}
VENDOR_LABEL = {
    CEFVendor.CROWDSTRIKE: "CrowdStrike Falcon",
    CEFVendor.PALO_ALTO: "Palo Alto Cortex XDR",
    CEFVendor.OKTA: "Okta",
    CEFVendor.UNKNOWN: "Unknown",
}

SEV_COLOUR = {"critical": R + BD, "high": Y + BD, "medium": C, "low": DIM, "info": DIM}


# ══════════════════════════════════════════════════════════════════
# Banner
# ══════════════════════════════════════════════════════════════════


def print_banner() -> None:
    print(f"\n{BD}{C}{'═'*72}{RS}")
    print(f"{BD}{C}  Cyphora-S1  |  CEF Log Analysis{RS}")
    print(f"{C}  {'─'*70}{RS}")
    print(
        f"  Products: {VENDOR_COLOUR[CEFVendor.CROWDSTRIKE]}CrowdStrike Falcon{RS}  "
        f"{VENDOR_COLOUR[CEFVendor.PALO_ALTO]}Palo Alto Cortex XDR{RS}  "
        f"{VENDOR_COLOUR[CEFVendor.OKTA]}Okta{RS}"
    )
    print(f"{BD}{C}{'═'*72}{RS}\n")


# ══════════════════════════════════════════════════════════════════
# CEF parsing + summary
# ══════════════════════════════════════════════════════════════════


def parse_and_summarise(records: List[CEFRecord]) -> None:
    """Print a grouped summary of parsed CEF records before dispatch."""
    by_vendor: Dict[str, List[CEFRecord]] = defaultdict(list)
    for r in records:
        by_vendor[r.vendor].append(r)

    print(f"{BD}Parsed CEF Records{RS}  ({len(records)} total)\n")
    for vendor, vrecs in sorted(by_vendor.items()):
        vc = VENDOR_COLOUR.get(vendor, "")
        vl = VENDOR_LABEL.get(vendor, vendor)
        print(f"  {vc}▶  {vl}{RS}  ({len(vrecs)} events)")
        for r in vrecs:
            sc = SEV_COLOUR.get(r.severity, "")
            print(
                f"     {DIM}{r.timestamp[:19]}{RS}  "
                f"{sc}{r.severity:<8}{RS}  "
                f"{r.event_class:<32}  {r.name[:50]}"
            )
        print()


# ══════════════════════════════════════════════════════════════════
# Agent dispatch loop
# ══════════════════════════════════════════════════════════════════


async def dispatch_events(
    orchestrator: AgentOrchestrator,
    events: List[SecurityEvent],
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """Dispatch all events through the orchestrator and collect results."""
    results = []

    print(f"{BD}Dispatching {len(events)} events through Cyphora-S1 agents …{RS}\n")
    print(
        f"  {'Timestamp':<22}  {'Event Type':<32}  "
        f"{'Severity':<10}  {'Triggered':<10}  {'Host / User'}"
    )
    print(f"  {'─'*22}  {'─'*32}  {'─'*10}  {'─'*10}  {'─'*30}")

    for event in events:
        t0 = time.perf_counter()

        try:
            triggered = await orchestrator.dispatch(event)
        except Exception as exc:
            triggered = 0
            print(f"  {R}[dispatch error] {exc}{RS}")

        elapsed = (time.perf_counter() - t0) * 1000
        sc = SEV_COLOUR.get(event.severity, "")
        tc = G if triggered > 0 else DIM
        host_user = f"{event.source_host or '—'} / {event.user or '—'}"

        print(
            f"  {DIM}{event.timestamp[:19]}{RS}  "
            f"{event.event_type:<32}  "
            f"{sc}{event.severity:<10}{RS}  "
            f"{tc}{triggered:>2} agent(s){RS}   "
            f"{host_user[:35]}"
        )

        results.append(
            {
                "event": event,
                "triggered": triggered,
                "elapsed_ms": elapsed,
            }
        )

    print()
    # Give agents time to complete async processing
    await asyncio.sleep(15)
    return results


# ══════════════════════════════════════════════════════════════════
# Results report
# ══════════════════════════════════════════════════════════════════


def print_results(
    orchestrator: AgentOrchestrator,
    dispatch_results: List[Dict[str, Any]],
    records: List[CEFRecord],
    verbose: bool = False,
) -> None:
    status = orchestrator.status()
    total_triggered = sum(r["triggered"] for r in dispatch_results)
    by_type: Dict[str, int] = defaultdict(int)
    by_vendor: Dict[str, int] = defaultdict(int)
    by_sev: Dict[str, int] = defaultdict(int)

    for rec in records:
        by_vendor[VENDOR_LABEL.get(rec.vendor, rec.vendor)] += 1
        by_sev[rec.severity] += 1

    for r in dispatch_results:
        by_type[r["event"].event_type] += 1

    # ── Overview ─────────────────────────────────────────────────
    print(f"\n{BD}{C}{'═'*72}{RS}")
    print(f"{BD}{C}  ANALYSIS RESULTS{RS}")
    print(f"{C}{'═'*72}{RS}")

    print(f"\n{BD}  Source Summary{RS}")
    for vendor, count in sorted(by_vendor.items()):
        print(f"    {vendor:<30}  {count:>3} events")

    print(f"\n{BD}  Severity Distribution{RS}")
    sev_order = ["critical", "high", "medium", "low"]
    for sev in sev_order:
        count = by_sev.get(sev, 0)
        sc = SEV_COLOUR.get(sev, "")
        bar = "█" * count
        print(f"    {sc}{sev:<10}{RS}  {bar}  ({count})")

    print(f"\n{BD}  Cyphora Event Types Mapped{RS}")
    for etype, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {etype:<35}  {count:>3}")

    print(f"\n{BD}  Agent Execution Summary{RS}")
    for agent_name, stats in status.items():
        completed = stats.get("completed", 0)
        errors = stats.get("errors", 0)
        sc = G if errors == 0 else R
        print(
            f"    {agent_name:<42}  "
            f"completed={G}{completed}{RS}  "
            f"errors={sc}{errors}{RS}"
        )

    print(f"\n  Total events dispatched : {len(dispatch_results)}")
    print(f"  Total agent invocations : {total_triggered}")

    # ── Per-agent deep results ────────────────────────────────────
    print(f"\n{BD}{C}{'─'*72}{RS}")
    print(f"{BD}{C}  INVESTIGATION FINDINGS{RS}")
    print(f"{C}{'─'*72}{RS}\n")

    for agent_name, stats in status.items():
        last_report = stats.get("last_report")
        if not last_report:
            continue

        extras = getattr(last_report, "__dict__", {}).get("extras", {})
        if not extras:
            continue

        print(f"{BD}  {agent_name}{RS}")

        # ── MITRE ATT&CK ──────────────────────────────────────────
        attack_intel = extras.get("attack_intelligence")
        if attack_intel:
            ttps = getattr(attack_intel, "ttps_identified", [])
            if ttps:
                print(f"\n    {BD}MITRE ATT&CK Techniques Identified{RS}")
                seen = set()
                for ttp in ttps:
                    tid = getattr(ttp, "technique_id", "")
                    if tid in seen:
                        continue
                    seen.add(tid)
                    conf = getattr(ttp, "confidence", 0)
                    tac = getattr(ttp, "tactic", "")
                    tech = getattr(ttp, "technique", "")
                    cc = G if conf >= 0.8 else (Y if conf >= 0.5 else DIM)
                    print(
                        f"    {C}{tid:<14}{RS}  {tech:<40}  "
                        f"[{tac}]  {cc}conf={conf:.2f}{RS}"
                    )

            kill_chain = getattr(attack_intel, "kill_chain_steps", [])
            if kill_chain:
                print(f"\n    {BD}Kill Chain  ({len(kill_chain)} steps){RS}")
                for step in kill_chain:
                    snum = getattr(step, "step_number", "?")
                    tac = getattr(step, "tactic", "")
                    tech = getattr(step, "technique", "")
                    print(f"    Step {snum:<3}  {Y}{tac:<28}{RS}  {tech}")

            report_md = getattr(attack_intel, "plain_english_report", "")
            if report_md and verbose:
                print(f"\n    {BD}Incident Report (excerpt){RS}")
                for line in report_md.splitlines()[:20]:
                    print(f"    {line}")
                if len(report_md.splitlines()) > 20:
                    print(
                        f"    {DIM}… (truncated — {len(report_md.splitlines())} lines total){RS}"
                    )

        # ── UEBA ──────────────────────────────────────────────────
        ueba = extras.get("ueba_report")
        if ueba and getattr(ueba, "is_anomalous", False):
            print(f"\n    {BD}UEBA Anomaly{RS}")
            entity = getattr(ueba, "entity_id", "unknown")
            risk = getattr(ueba, "risk_label", "")
            score = getattr(ueba, "risk_score", 0.0)
            sc = R if score >= 0.8 else (Y if score >= 0.5 else C)
            print(f"    Entity  : {entity}")
            print(f"    Risk    : {sc}{risk}  ({score:.2f}){RS}")
            for anomaly in getattr(ueba, "anomalies", []):
                feat = getattr(anomaly, "feature", "")
                expl = getattr(anomaly, "explanation", "")
                print(f"    • [{feat}] {expl}")

        # ── Playbook ──────────────────────────────────────────────
        playbook = extras.get("playbook_result")
        if playbook:
            pb_status = getattr(playbook, "status", "")
            steps_ex = getattr(playbook, "steps_executed", 0)
            steps_tot = getattr(playbook, "steps_total", 0)
            sc = G if pb_status == "completed" else Y
            print(f"\n    {BD}Automated Playbook{RS}")
            print(f"    Status  : {sc}{pb_status}{RS}")
            print(f"    Steps   : {steps_ex}/{steps_tot}")

        # ── NL Query ──────────────────────────────────────────────
        nl = extras.get("nl_query_result")
        if nl:
            print(f"\n    {BD}NL Query Result{RS}")
            print(f"    Records : {getattr(nl, 'record_count', 0)}")
            out = getattr(nl, "formatted_output", "")
            if out:
                for line in str(out).splitlines()[:8]:
                    print(f"    {line}")

        print()

    # ── CEF-level event walkthrough ────────────────────────────────
    if verbose:
        print(f"{BD}{C}{'─'*72}{RS}")
        print(f"{BD}{C}  CEF EVENT WALKTHROUGH{RS}")
        print(f"{C}{'─'*72}{RS}\n")

        parser = CEFParser()
        for dr in dispatch_results:
            ev = dr["event"]
            rd = ev.raw_data or {}
            vendor = rd.get("cef_vendor", "")
            vc = VENDOR_COLOUR.get(vendor, "")
            vl = VENDOR_LABEL.get(vendor, vendor)
            sc = SEV_COLOUR.get(ev.severity, "")

            print(
                f"  {vc}{vl:<28}{RS}  "
                f"{sc}{ev.severity:<8}{RS}  "
                f"{ev.event_type:<32}  "
                f"{ev.timestamp[:19]}"
            )
            print(f"    {BD}Name{RS}    : {rd.get('event_name', '')}")
            if ev.source_host:
                print(f"    {BD}Host{RS}    : {ev.source_host}")
            if ev.source_ip:
                print(f"    {BD}Src IP{RS}  : {ev.source_ip}")
            if ev.user:
                print(f"    {BD}User{RS}    : {ev.user}")
            if rd.get("Technique") or rd.get("MitreTechnique"):
                t = rd.get("Technique") or rd.get("MitreTechnique")
                print(f"    {BD}ATT&CK{RS}  : {t}")
            if rd.get("msg"):
                print(f"    {BD}Message{RS} : {rd['msg']}")
            outcome = rd.get("outcome", "")
            if outcome:
                oc = (
                    G
                    if outcome == "success"
                    else (R if outcome in ("blocked", "failure") else Y)
                )
                print(f"    {BD}Outcome{RS} : {oc}{outcome}{RS}")
            print()


# ══════════════════════════════════════════════════════════════════
# Arg parsing + main
# ══════════════════════════════════════════════════════════════════


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Cyphora-S1 CEF Log Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--log-file",
        "-f",
        default=str(Path(__file__).parent.parent / "data" / "sample_security_logs.cef"),
        help="Mixed-vendor CEF log file to analyse (default: data/sample_security_logs.cef)",
    )
    p.add_argument("--crowdstrike", help="CrowdStrike-only CEF log file")
    p.add_argument("--cortex-xdr", help="Palo Alto Cortex XDR CEF log file")
    p.add_argument("--okta", help="Okta CEF log file")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Disable real containment actions and PagerDuty alerts",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show MITRE TTPs, UEBA details, playbook steps, CEF walkthrough",
    )
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    is_dry = args.dry_run or os.getenv("CYPHORA_DRY_RUN", "0") == "1"

    print_banner()

    # ── 1. Parse CEF logs ────────────────────────────────────────
    parser = CEFParser()
    all_records: List[CEFRecord] = []

    if args.crowdstrike or args.cortex_xdr or args.okta:
        # Separate vendor files
        log_paths: Dict[str, str] = {}
        if args.crowdstrike:
            log_paths["crowdstrike"] = args.crowdstrike
        if args.cortex_xdr:
            log_paths["cortex_xdr"] = args.cortex_xdr
        if args.okta:
            log_paths["okta"] = args.okta

        for path in log_paths.values():
            all_records.extend(parser.parse_file(path))

        stats = register_cef_adapters(log_paths=log_paths)

    else:
        # Single mixed file (default)
        log_file = Path(args.log_file)
        if not log_file.exists():
            print(f"{R}Log file not found: {log_file}{RS}")
            print(
                f"  → Run from the project root, or pass --log-file /path/to/your.cef"
            )
            sys.exit(1)

        print(f"[→] Parsing CEF log file: {log_file.name}\n")
        all_records = parser.parse_file(log_file)
        stats = register_cef_adapters(mixed_file=str(log_file))

    if not all_records:
        print(f"{R}No valid CEF records found in the specified log file(s).{RS}")
        sys.exit(1)

    print(f"[✓] CEF adapters loaded: {stats}\n")

    # ── 2. Summarise parsed records ──────────────────────────────
    parse_and_summarise(all_records)

    # ── 3. Build SecurityEvent objects from CEF records ──────────
    events: List[SecurityEvent] = []
    for rec in all_records:
        d = parser.to_security_event_dict(rec)
        valid = {
            "event_id",
            "event_type",
            "severity",
            "timestamp",
            "source_ip",
            "source_host",
            "user",
            "process",
            "raw_data",
        }
        try:
            events.append(SecurityEvent(**{k: v for k, v in d.items() if k in valid}))
        except Exception as exc:
            print(f"{Y}  [warn] Could not build SecurityEvent: {exc}{RS}")

    print(f"[✓] Built {len(events)} SecurityEvent(s) from CEF records\n")

    # ── 4. Register live product adapters (if credentials present) ─
    register_all_adapters()

    # ── 5. Start orchestrator + agents ───────────────────────────
    agents = [
        CyphoraInvestigationAgent(
            ueba_redis_url=os.getenv("REDIS_URL"),
            playbook_dry_run=is_dry,
        ),
        CyphoraUEBAAgent(redis_url=os.getenv("REDIS_URL")),
        CyphoraComplianceAgent(lookback_days=90),
        CyphoraNLQueryAgent(),
    ]

    orchestrator = AgentOrchestrator()
    orchestrator.register_agents(agents)
    await orchestrator.start()
    print(
        f"[✓] Orchestrator started  |  agents: "
        f"{', '.join(type(a).__name__ for a in agents)}\n"
    )

    # ── 6. Dispatch all events ────────────────────────────────────
    dispatch_results = await dispatch_events(orchestrator, events, verbose=args.verbose)

    # ── 7. Print results ─────────────────────────────────────────
    print_results(orchestrator, dispatch_results, all_records, verbose=args.verbose)

    await orchestrator.stop()
    print(f"{G}[✓] Analysis complete.{RS}\n")


if __name__ == "__main__":
    asyncio.run(main())
