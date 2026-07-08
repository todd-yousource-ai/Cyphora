import asyncio
from pathlib import Path
import sys

working_dir = str(Path.cwd())
if working_dir not in sys.path:
    sys.path.insert(0, working_dir)


from acda.orchestrator.orchestrator import AgentOrchestrator

# from acda.agents.agents import InvestigationAgent
from generated_agents.investigationagent import InvestigationAgent


async def main():
    orchestrator = AgentOrchestrator()

    # Register all agents
    orchestrator.register_agents(
        [
            InvestigationAgent(),
        ]
    )

    await orchestrator.start()
    print("Orchestrator running. Press Ctrl+C to stop.")

    # In production: hook into a Kafka/Kinesis consumer here
    # For testing: dispatch synthetic events
    from acda.simulation.attack_simulator import AttackSimulator

    simulator = AttackSimulator(speed_multiplier=3.0)
    async for event in simulator.run_scenario("data_exfiltration"):
        triggered = await orchestrator.dispatch(event)
        print(f"Event {event.event_type} → {triggered} agent(s) triggered")

    await asyncio.sleep(5)  # let agents finish
    await orchestrator.stop()
    print(orchestrator.status())


if __name__ == "__main__":
    asyncio.run(main())
