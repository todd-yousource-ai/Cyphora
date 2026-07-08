"""
Cyphora-S1 Test Suite Runner
==============================
Exercises every Cyphora-S1 agent against the dataset in
tests/cyphora_test_events.py and prints a summary report.

Run modes
---------
  Full run (all agents, all events):
      python tests/run_cyphora_test_suite.py

  Single scenario kill-chain:
      python tests/run_cyphora_test_suite.py --scenario S1_RANSOMWARE

  Single agent only:
      python tests/run_cyphora_test_suite.py --agent CyphoraInvestigationAgent

  Dry-run (no real API calls, no playbook actions):
      python tests/run_cyphora_test_suite.py --dry-run

  Verbose output (print full AgentExecutionReport per event):
      python tests/run_cyphora_test_suite.py --verbose

Environment variables
---------------------
  ANTHROPIC_API_KEY   Required for LLM reasoning steps
  REDIS_URL           Optional — in-memory UEBA baseline used if absent
  CYPHORA_DRY_RUN=1   Same effect as --dry-run flag
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# for print and logging output mixing to work properly in redirections
sys.stdout.reconfigure(line_buffering=True)

# ── path setup ────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Cyphora-S1 imports ────────────────────────────────────────────────────
from cyphora_s1.cyphora_ingest import register_all_adapters
from acda.agents.cyphora_agents import (
    CyphoraInvestigationAgent,
    CyphoraUEBAAgent,
    CyphoraComplianceAgent,
    CyphoraNLQueryAgent,
)
from acda.orchestrator.orchestrator import AgentOrchestrator
from acda.models.schemas import OrchestratorConfig, SecurityEvent

# ── Test dataset ──────────────────────────────────────────────────────────
from tests.cyphora_test_events import (
    SCENARIOS,
    AGENT_TARGETS,
    NL_QUERIES,
    ALL_EVENTS,
    get_scenario_kill_chain,
    get_events_for_agent,
)

# ── ANSI colours ─────────────────────────────────────────────────────────
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

PRODUCT_LABELS = {
    "crowdstrike": f"{CYAN}CrowdStrike Falcon{RESET}",
    "okta": f"{CYAN}Okta{RESET}",
    "paloalto": f"{CYAN}Palo Alto Networks{RESET}",
    "cyphora": f"{CYAN}Cyphora (Synthetic){RESET}",
}


# ══════════════════════════════════════════════════════════════════════════
# Result bookkeeping
# ══════════════════════════════════════════════════════════════════════════


class TestResult:
    __slots__ = ("event_id", "agent", "status", "duration_ms", "error", "extras")

    def __init__(
        self,
        event_id: str,
        agent: str,
        status: str,
        duration_ms: float,
        error: Optional[str] = None,
        extras: Optional[Dict[str, Any]] = None,
    ):
        self.event_id = event_id
        self.agent = agent
        self.status = status
        self.duration_ms = duration_ms
        self.error = error
        self.extras = extras or {}


# ══════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════


def _product_label(raw_data: Dict[str, Any]) -> str:
    product = str(raw_data.get("product", "")).lower()
    for key, label in PRODUCT_LABELS.items():
        if product.startswith(key):
            return label
    return product


def _build_event(evt_dict: Dict[str, Any]) -> SecurityEvent:
    """
    Convert a test-dataset dict to a SecurityEvent.
    Maps legacy field aliases (user_id → user, host → source_host) for
    backwards compatibility, then filters to SecurityEvent schema fields.
    """
    aliases = {"user_id": "user", "host": "source_host"}
    remapped = {aliases.get(k, k): v for k, v in evt_dict.items()}
    return SecurityEvent(
        **{k: v for k, v in remapped.items() if k in SecurityEvent.model_fields}
    )


async def _run_single(
    orchestrator: AgentOrchestrator,
    evt_dict: Dict[str, Any],
    verbose: bool = False,
    sequential: bool = False,
) -> TestResult:
    """Dispatch one event through the orchestrator and collect the result."""
    event = _build_event(evt_dict)
    t0 = time.perf_counter()

    print(
        f"\n{CYAN}===== Dispatching event {event.event_id} ({event.event_type})...{RESET} ====="
    )

    try:
        triggered = await orchestrator.dispatch(event)
        if sequential and triggered > 0:
            retry_attempts = (
                getattr(
                    getattr(orchestrator, "_config", None),
                    "retry_policy_max_retries",
                    0,
                )
                + 1
            )
            timeout_seconds = getattr(
                getattr(orchestrator, "_config", None),
                "timeout_seconds",
                120,
            )
            await asyncio.wait_for(
                orchestrator._queue.join(),
                timeout=max(30, triggered * retry_attempts * timeout_seconds),
            )
        else:
            # Give agents up to 30 s to process
            await asyncio.sleep(min(30, 5 + triggered * 3))

        # Collect the most recent completed report for this event.
        latest_report = None
        latest_agent = "unknown"
        for report in reversed(getattr(orchestrator, "_execution_history", [])):
            if (
                getattr(report, "event", None)
                and report.event.event_id == event.event_id
            ):
                latest_report = report
                latest_agent = getattr(report, "agent_name", "unknown")
                break

        extras = {}
        if latest_report:
            extras = getattr(latest_report, "__dict__", {}).get("extras", {})

        return TestResult(
            event_id=evt_dict["event_id"],
            agent=latest_agent,
            status=(
                getattr(latest_report, "status", "dispatched")
                if latest_report
                else ("no_trigger" if triggered == 0 else "dispatched")
            ),
            duration_ms=(time.perf_counter() - t0) * 1000,
            extras=extras,
        )

    except Exception as exc:
        return TestResult(
            event_id=evt_dict["event_id"],
            agent="error",
            status="error",
            duration_ms=(time.perf_counter() - t0) * 1000,
            error=str(exc),
        )


def _print_result(result: TestResult, evt_dict: Dict[str, Any], verbose: bool) -> None:
    colour = (
        GREEN
        if result.status == "completed"
        else (YELLOW if result.status in ("dispatched", "no_trigger") else RED)
    )
    product = _product_label(evt_dict.get("raw_data", {}))
    scenario = evt_dict.get("raw_data", {}).get("scenario", "")
    step = evt_dict.get("raw_data", {}).get("scenario_step", "")
    step_str = f" [step {step}]" if step else ""

    print(
        f"  {colour}{'✓' if result.status == 'completed' else '●'}{RESET}  "
        f"{evt_dict['event_id']:<22}  "
        f"{evt_dict['event_type']:<32}  "
        f"{product}  "
        f"{colour}{result.status}{RESET}  "
        f"{result.duration_ms:>7.0f} ms"
        f"{'  ' + scenario + step_str if scenario else ''}"
    )

    if result.error:
        print(f"       {RED}Error: {result.error}{RESET}")

    if verbose and result.extras:
        attack_intel = result.extras.get("attack_intelligence")
        if attack_intel:
            ttps = getattr(attack_intel, "ttps_identified", [])
            print(
                f"       {CYAN}MITRE TTPs:{RESET} "
                + ", ".join(t.technique_id for t in ttps)
            )

        ueba = result.extras.get("ueba_report")
        if ueba and getattr(ueba, "is_anomalous", False):
            print(
                f"       {CYAN}UEBA:{RESET} {ueba.risk_label} ({ueba.risk_score:.2f})"
            )

        playbook = result.extras.get("playbook_result")
        if playbook:
            print(f"       {CYAN}Playbook:{RESET} {playbook.status}")

        nl = result.extras.get("nl_query_result")
        if nl:
            print(
                f"       {CYAN}NL Result:{RESET} {nl.record_count} records  ({nl.execution_time_ms:.0f} ms)"
            )
    print()  # extra newline


def _print_section(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─'*70}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*70}{RESET}")


def _print_summary(results: List[TestResult]) -> None:
    total = len(results)
    completed = sum(1 for r in results if r.status == "completed")
    errors = sum(1 for r in results if r.status == "error")
    other = total - completed - errors
    avg_ms = sum(r.duration_ms for r in results) / max(total, 1)

    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(f"{BOLD}  TEST SUMMARY{RESET}")
    print(f"{'═'*70}")
    print(f"  Total events  : {total}")
    print(f"  {GREEN}Completed{RESET}     : {completed}")
    print(f"  {YELLOW}Other{RESET}         : {other}  (dispatched / no_trigger)")
    print(f"  {RED}Errors{RESET}        : {errors}")
    print(f"  Avg duration  : {avg_ms:.0f} ms / event")
    print(f"{'═'*70}\n")

    # Per-agent breakdown
    by_agent: Dict[str, List[TestResult]] = defaultdict(list)
    for r in results:
        by_agent[r.agent].append(r)

    print(f"  {'Agent':<40}  {'Events':>6}  {'Completed':>9}  {'Errors':>6}")
    print(f"  {'─'*67}")
    for agent, agent_results in sorted(by_agent.items()):
        comp = sum(1 for r in agent_results if r.status == "completed")
        err = sum(1 for r in agent_results if r.status == "error")
        print(
            f"  {agent:<40}  {len(agent_results):>6}  "
            f"{GREEN}{comp:>9}{RESET}  "
            f"{(RED if err else GREEN)}{err:>6}{RESET}"
        )


# ══════════════════════════════════════════════════════════════════════════
# Main test runner
# ══════════════════════════════════════════════════════════════════════════


async def run_tests(
    scenario: Optional[str] = None,
    agent_filter: Optional[str] = None,
    dry_run: bool = False,
    verbose: bool = False,
    sequential: bool = False,
) -> List[TestResult]:
    """
    Run the Cyphora-S1 test suite.

    Parameters
    ----------
    scenario     : Run a single named scenario (e.g. 'S1_RANSOMWARE')
    agent_filter : Run events targeting a single agent class name
    dry_run      : Disable real API calls and playbook actions
    verbose      : Print ATT&CK TTPs, UEBA scores, playbook results
    """
    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(
        f"{BOLD}  Cyphora-S1 Test Suite  —  {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}{RESET}"
    )
    print(
        f"{BOLD}  Products under test: CrowdStrike Falcon · Okta · Palo Alto Networks{RESET}"
    )
    print(f"{'═'*70}\n")

    # ── Setup ──────────────────────────────────────────────────────────
    register_all_adapters()
    # Register product-faithful simulated adapters for sources without live credentials
    from cyphora_s1.sim_adapters import register_simulated_adapters

    register_simulated_adapters()
    is_dry = dry_run or os.getenv("CYPHORA_DRY_RUN", "0") == "1"

    agents = [
        CyphoraInvestigationAgent(
            ueba_redis_url=os.getenv("REDIS_URL"),
            playbook_dry_run=is_dry,
        ),
        CyphoraUEBAAgent(redis_url=os.getenv("REDIS_URL")),
        CyphoraComplianceAgent(lookback_days=90),
        CyphoraNLQueryAgent(),
    ]

    if agent_filter:
        agents = [a for a in agents if type(a).__name__ == agent_filter]
        if not agents:
            print(f"{RED}No agent named '{agent_filter}' found.{RESET}")
            return []

    orchestrator = (
        AgentOrchestrator(config=OrchestratorConfig(max_concurrent_agents=1))
        if sequential
        else AgentOrchestrator()
    )
    orchestrator.register_agents(agents)
    await orchestrator.start()
    print(
        f"[✓] Orchestrator started  |  mode: "
        f"{'sequential' if sequential else 'default'}"
        f"  |  agents: {', '.join(type(a).__name__ for a in agents)}\n"
    )

    all_results: List[TestResult] = []

    # ── Scenario tests ────────────────────────────────────────────────
    scenarios_to_run = (
        {scenario: SCENARIOS[scenario]}
        if scenario and scenario in SCENARIOS
        else SCENARIOS
    )

    if not agent_filter:
        _print_section("SCENARIO KILL-CHAIN TESTS")
        SCENARIO_LABELS = {
            "S1_RANSOMWARE": "S1  Ransomware (CrowdStrike + PAN)",
            "S2_INSIDER_EXFIL": "S2  Insider Threat / Exfil (Okta + CS + PAN)",
            "S3_CREDENTIAL_LATERAL": "S3  Credential Compromise + Lateral (Okta + CS + PAN)",
            "S4_LOLBIN_DNS_TUNNEL": "S4  LOLBin + DNS Tunnelling (CS + PAN)",
            "S5_CLOUD_TAKEOVER": "S5  Cloud Account Takeover (Okta + PAN)",
        }
        for sname, sevents in scenarios_to_run.items():
            print(f"\n  {BOLD}{SCENARIO_LABELS.get(sname, sname)}{RESET}")
            for evt_dict in get_scenario_kill_chain(sname):
                result = await _run_single(
                    orchestrator,
                    evt_dict,
                    verbose,
                    sequential=sequential,
                )
                all_results.append(result)
                _print_result(result, evt_dict, verbose)

    # ── Individual capability tests ───────────────────────────────────
    if not scenario:
        _print_section("INDIVIDUAL AGENT CAPABILITY TESTS")

        cap_events: Dict[str, List[Dict[str, Any]]] = {
            "CyphoraInvestigationAgent — trigger coverage": [
                e
                for e in AGENT_TARGETS["CyphoraInvestigationAgent"]
                if e.get("raw_data", {}).get("test_case", "").startswith("T-INV")
            ],
            "CyphoraUEBAAgent — trigger coverage": [
                e
                for e in AGENT_TARGETS["CyphoraUEBAAgent"]
                if e.get("raw_data", {}).get("test_case", "").startswith("T-UBA")
            ],
            "CyphoraComplianceAgent — scheduled + on-demand": AGENT_TARGETS[
                "CyphoraComplianceAgent"
            ],
            "CyphoraNLQueryAgent — 10 NL queries": NL_QUERIES,
            "Negative tests — should not fire": AGENT_TARGETS["NEGATIVE_TESTS"],
        }

        for section_label, events in cap_events.items():
            if agent_filter:
                # Skip sections not relevant to the filtered agent
                if (
                    agent_filter not in section_label
                    and "Negative" not in section_label
                ):
                    continue

            print(f"\n  {BOLD}{section_label}{RESET}")
            for evt_dict in events:
                result = await _run_single(
                    orchestrator,
                    evt_dict,
                    verbose,
                    sequential=sequential,
                )
                all_results.append(result)
                _print_result(result, evt_dict, verbose)

    await orchestrator.stop()
    print(f"\n[✓] Orchestrator stopped.\n")

    _print_summary(all_results)
    return all_results


# ══════════════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════════════


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Cyphora-S1 test suite runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scenarios:  S1_RANSOMWARE  S2_INSIDER_EXFIL  S3_CREDENTIAL_LATERAL
            S4_LOLBIN_DNS_TUNNEL  S5_CLOUD_TAKEOVER

Agents:     CyphoraInvestigationAgent  CyphoraUEBAAgent
            CyphoraComplianceAgent     CyphoraNLQueryAgent
        """,
    )
    p.add_argument(
        "--scenario", metavar="NAME", help="Run a single named scenario kill-chain"
    )
    p.add_argument(
        "--agent", metavar="CLASS", help="Run events for a single agent class only"
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Disable real API calls and playbook actions",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print ATT&CK TTPs, UEBA scores, and playbook details",
    )
    p.add_argument(
        "--sequential",
        action="store_true",
        help="Run the orchestrator with max_concurrent_agents=1 for easier debugging",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    asyncio.run(
        run_tests(
            scenario=args.scenario,
            agent_filter=args.agent,
            dry_run=args.dry_run,
            verbose=args.verbose,
            sequential=args.sequential,
        )
    )
