"""
ACDA-SDK — Command Line Interface

Usage:
  acda init   <name>           Create a new agent definition
  acda validate <file>         Validate a YAML/JSON agent definition
  acda build  <file>           Compile a definition to Python
  acda run    <agent> <event>  Run an agent against a synthetic event
  acda simulate <scenario>     Run an attack simulation
  acda deploy  <agent>         Deploy agent to Kubernetes
  acda status                  Show orchestrator status
  acda registry list           List all registered agents
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()

LOGO = """
[bold cyan]
╔═══════════════════════════════════════════════════╗
║   ACDA-SDK  —  Autonomous Cyber Defense Agents    ║
║   Consensus-Validated AI Security Architecture    ║
╚═══════════════════════════════════════════════════╝
[/bold cyan]"""

NEW_AGENT_TEMPLATE = """\
agent:
  name: {name}
  version: 1.0

  metadata:
    description: "{name} — cyber defense agent"
    priority: medium
    owner: security_platform

  triggers:
    event_types:
      - suspicious_login
      - abnormal_process_execution

  data_collection:
    sources:
      - endpoint_logs
      - network_logs
    time_window: 30m

  reasoning:
    ai_models:
      - model_A
      - model_B
      - model_C
    task: attack_chain_analysis
    temperature: 0.2

  consensus_validation:
    method: weighted_vote
    threshold: 0.80
    weights:
      model_A: 0.40
      model_B: 0.35
      model_C: 0.25

  actions:
    - generate_incident_report
    - notify_soc

  safety_controls:
    max_runtime: 120s
    approval_required: none
    dry_run_mode: false
    escalation_required: false
"""


# ─────────────────────────────────────────────
# CLI Group
# ─────────────────────────────────────────────


@click.group()
@click.version_option("1.0.0", prog_name="acda")
def cli():
    """ACDA-SDK — Autonomous Cyber Defense Agent CLI"""
    console.print(LOGO)


# ─────────────────────────────────────────────
# acda init
# ─────────────────────────────────────────────


@cli.command("init")
@click.argument("name")
@click.option("--output-dir", "-o", default=".", help="Output directory")
def cmd_init(name: str, output_dir: str):
    """Create a new agent definition scaffold."""
    out = Path(output_dir) / f"{name.lower()}.yaml"
    out.parent.mkdir(parents=True, exist_ok=True)

    content = NEW_AGENT_TEMPLATE.format(name=name)
    out.write_text(content, encoding="utf-8")

    console.print(f"[green]✓ Created agent definition:[/green] {out}")
    console.print(
        "\nNext steps:\n"
        f"  1. Edit [bold]{out}[/bold] to configure your agent\n"
        f"  2. [bold]acda validate {out}[/bold]\n"
        f"  3. [bold]acda build {out}[/bold]\n"
    )


# ─────────────────────────────────────────────
# acda validate
# ─────────────────────────────────────────────


@cli.command("validate")
@click.argument("definition_file")
def cmd_validate(definition_file: str):
    """Validate a YAML/JSON agent definition file."""
    from acda.compiler.schema_validator import AdfValidator

    validator = AdfValidator()
    result, agent = validator.validate_file(definition_file)
    result.print_report(Path(definition_file).stem)

    sys.exit(0 if result.valid else 1)


# ─────────────────────────────────────────────
# acda build
# ─────────────────────────────────────────────


@cli.command("build")
@click.argument("definition_file")
@click.option(
    "--output-dir",
    "-o",
    default="generated_agents",
    help="Output directory for generated code",
)
@click.option("--print-code", is_flag=True, help="Print generated code to stdout")
def cmd_build(definition_file: str, output_dir: str, print_code: bool):
    """Compile a YAML/JSON agent definition into a Python agent class."""
    from acda.compiler.code_generator import AgentCodeGenerator
    from acda.compiler.schema_validator import AdfValidator

    console.print(f"[bold]Building[/bold] {definition_file}...")

    validator = AdfValidator()
    result, agent = validator.validate_file(definition_file)

    if not result.valid:
        result.print_report()
        console.print(
            "[bold red]Build failed — validation errors must be fixed first.[/bold red]"
        )
        sys.exit(1)

    generator = AgentCodeGenerator()
    output_file = generator.generate_from_file(definition_file, output_dir)

    console.print(f"[bold green]✓ Generated:[/bold green] {output_file}")
    console.print(f"  Agent : {agent.name} v{agent.version}")
    console.print(f"  Output: {output_file}")

    if print_code:
        code = output_file.read_text()
        console.print(Syntax(code, "python", theme="monokai", line_numbers=True))


# ─────────────────────────────────────────────
# acda run
# ─────────────────────────────────────────────


@cli.command("run")
@click.argument("agent_name")
@click.option(
    "--event-type", "-e", default="suspicious_login", help="Security event type"
)
@click.option("--host", default="WORKSTATION-001")
@click.option("--ip", default="192.168.1.100")
@click.option("--user", default="CORP\\user01")
@click.option(
    "--severity",
    default="high",
    type=click.Choice(["low", "medium", "high", "critical"]),
)
@click.option("--dry-run", is_flag=True, help="Dry run mode — no real actions")
def cmd_run(
    agent_name: str,
    event_type: str,
    host: str,
    ip: str,
    user: str,
    severity: str,
    dry_run: bool,
):
    """Run a named agent against a synthetic security event."""
    from acda.agents.agents import ALL_AGENTS
    from acda.models.schemas import SecurityEvent
    import uuid
    from datetime import datetime, timezone

    # Find agent class
    agent_cls = next((a for a in ALL_AGENTS if a.__name__ == agent_name), None)
    if not agent_cls:
        available = [a.__name__ for a in ALL_AGENTS]
        console.print(f"[red]Agent '{agent_name}' not found.[/red]")
        console.print(f"Available agents: {available}")
        sys.exit(1)

    event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source_host=host,
        source_ip=ip,
        user=user,
        severity=severity,
    )

    # Instantiate (with dry_run if ContainmentAgent)
    try:
        if agent_name == "ContainmentAgent":
            agent = agent_cls(dry_run=dry_run)
        else:
            agent = agent_cls()
            if dry_run:
                agent.DRY_RUN_MODE = True
    except Exception as e:
        console.print(f"[red]Failed to create agent: {e}[/red]")
        sys.exit(1)

    console.print(f"\n[bold]Running[/bold] {agent_name}")
    console.print(f"  Event : {event_type} | Severity: {severity}")
    console.print(f"  Host  : {host} | IP: {ip} | User: {user}")
    console.print(f"  Dry run: {dry_run}\n")

    async def _run():
        return await agent.safe_run(event)

    report = asyncio.run(_run())

    # Print report
    table = Table(title=f"Execution Report — {agent_name}", show_lines=True)
    table.add_column("Field", style="bold cyan", width=22)
    table.add_column("Value")

    table.add_row("Execution ID", report.execution_id)
    table.add_row(
        "Status",
        (
            f"[green]{report.status}[/green]"
            if report.status == "completed"
            else f"[red]{report.status}[/red]"
        ),
    )
    table.add_row("Duration", f"{report.duration_ms:.1f}ms")
    table.add_row("Data Collected", "✓" if report.data_collected else "✗")

    if report.reasoning_result:
        scores = ", ".join(
            f"{s.model_id}={s.score:.3f}" for s in report.reasoning_result.scores
        )
        table.add_row("Model Scores", scores)

    if report.consensus_result:
        c = report.consensus_result
        status_icon = "[green]PASSED[/green]" if c.passed else "[red]FAILED[/red]"
        table.add_row(
            "Consensus", f"{status_icon} (score={c.score:.4f}, threshold={c.threshold})"
        )

    actions_str = (
        "\n".join(
            f"{'✓' if a.success else '✗'} {a.action}" for a in report.actions_taken
        )
        or "None"
    )
    table.add_row("Actions", actions_str)

    if report.errors:
        table.add_row("Errors", "\n".join(report.errors))

    console.print(table)


# ─────────────────────────────────────────────
# acda simulate
# ─────────────────────────────────────────────


@cli.command("simulate")
@click.argument("scenario", default="ransomware")
@click.option("--speed", default=5.0, type=float, help="Speed multiplier (>1 = faster)")
@click.option("--dry-run", is_flag=True, help="Run all agents in dry-run mode")
def cmd_simulate(scenario: str, speed: float, dry_run: bool):
    """Run a cyber attack simulation and test agent response."""
    from acda.simulation.attack_simulator import AttackSimulator, ATTACK_SCENARIOS
    from acda.orchestrator.orchestrator import AgentOrchestrator
    from acda.agents.agents import (
        InvestigationAgent,
        ThreatHuntingAgent,
        ContainmentAgent,
        RansomwareInvestigationAgent,
    )

    if scenario not in ATTACK_SCENARIOS and scenario != "all":
        available = list(ATTACK_SCENARIOS.keys())
        console.print(f"[red]Unknown scenario '{scenario}'[/red]")
        console.print(f"Available: {available + ['all']}")
        sys.exit(1)

    async def _simulate():
        orchestrator = AgentOrchestrator()
        orchestrator.register_agents(
            [
                InvestigationAgent(),
                ThreatHuntingAgent(),
                ContainmentAgent(dry_run=dry_run),
                RansomwareInvestigationAgent(),
            ]
        )
        await orchestrator.start()

        simulator = AttackSimulator(speed_multiplier=speed)

        console.print(
            f"\n[bold yellow]⚡ Running attack simulation: {scenario}[/bold yellow]"
        )
        console.print(f"   Speed multiplier: {speed}x | Dry run: {dry_run}\n")

        scenarios = list(ATTACK_SCENARIOS.keys()) if scenario == "all" else [scenario]

        for sc in scenarios:
            console.print(f"[cyan]── Scenario: {sc} ──[/cyan]")
            async for event in simulator.run_scenario(sc):
                triggered = await orchestrator.dispatch(event)
                console.print(
                    f"  [dim]{event.event_type}[/dim] "
                    f"→ [bold]{triggered}[/bold] agent(s) triggered"
                )

        # Allow execution to finish
        await asyncio.sleep(2.0)
        await orchestrator.stop()

        status = orchestrator.status()
        console.print(
            Panel(
                f"[bold green]Simulation complete[/bold green]\n"
                f"Executions completed: {status['executions_completed']}\n"
                f"Total events processed via orchestrator",
                title="Results",
            )
        )

    asyncio.run(_simulate())


# ─────────────────────────────────────────────
# acda registry
# ─────────────────────────────────────────────


@cli.group("registry")
def registry():
    """Agent registry commands."""
    pass


@registry.command("list")
def registry_list():
    """List all available agents."""
    from acda.agents.agents import ALL_AGENTS

    table = Table(title="ACDA Agent Registry", show_lines=True)
    table.add_column("Agent", style="bold cyan")
    table.add_column("Triggers")
    table.add_column("Actions")
    table.add_column("Consensus Threshold")
    table.add_column("Dry Run")

    for agent_cls in ALL_AGENTS:
        agent = agent_cls()
        table.add_row(
            agent.name,
            "\n".join(agent.TRIGGERS) or "schedule",
            "\n".join(agent.ACTIONS),
            str(getattr(agent_cls, "CONSENSUS_THRESHOLD", "N/A")),
            str(agent.DRY_RUN_MODE),
        )

    console.print(table)


# ─────────────────────────────────────────────
# acda status
# ─────────────────────────────────────────────


@cli.command("status")
def cmd_status():
    """Show agent health status."""
    from acda.agents.agents import ALL_AGENTS

    table = Table(title="Agent Health Status", show_lines=True)
    table.add_column("Agent", style="bold")
    table.add_column("State")
    table.add_column("Executions")
    table.add_column("Errors")
    table.add_column("Triggers")

    for agent_cls in ALL_AGENTS:
        agent = agent_cls()
        h = agent.health_check()
        table.add_row(
            h["agent"],
            f"[green]{h['state']}[/green]",
            str(h["execution_count"]),
            str(h["error_count"]),
            str(len(h["triggers"])),
        )

    console.print(table)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    cli()
