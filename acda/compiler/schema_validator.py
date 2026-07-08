"""
ACDA-SDK — Schema Validator
Validates ADF YAML/JSON agent definition files against the formal JSON Schema
and Pydantic models before compilation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from acda.models.schemas import AdfDocument, AgentDefinition

console = Console()

# ─────────────────────────────────────────────
# JSON Schema (structural validation layer 1)
# ─────────────────────────────────────────────

ADF_JSON_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Agent Definition Framework Schema",
    "type": "object",
    "required": ["agent"],
    "properties": {
        "agent": {
            "type": "object",
            "required": ["name", "triggers"],
            "properties": {
                "name": {"type": "string", "minLength": 3},
                "version": {"type": "string"},
                "metadata": {
                    "type": "object",
                    "properties": {
                        "description": {"type": "string"},
                        "priority": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"],
                        },
                        "owner": {"type": "string"},
                    },
                },
                "triggers": {
                    "type": "object",
                    "anyOf": [
                        {"required": ["event_types"]},
                        {"required": ["schedule"]},
                    ],
                    "properties": {
                        "event_types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                        },
                        "schedule": {
                            "type": "object",
                            "required": ["interval"],
                            "properties": {
                                "interval": {
                                    "type": "string",
                                    "pattern": r"^\d+[smhd]$",
                                },
                            },
                        },
                    },
                },
                "data_collection": {
                    "type": "object",
                    "properties": {
                        "sources": {"type": "array", "items": {"type": "string"}},
                        "time_window": {"type": "string", "pattern": r"^\d+[smhd]$"},
                    },
                },
                "reasoning": {
                    "type": "object",
                    "required": ["task"],
                    "properties": {
                        "ai_models": {"type": "array", "items": {"type": "string"}},
                        "task": {"type": "string"},
                        "temperature": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                },
                "consensus_validation": {
                    "type": "object",
                    "required": ["threshold"],
                    "properties": {
                        "method": {"type": "string"},
                        "threshold": {"type": "number", "minimum": 0, "maximum": 1},
                        "weights": {"type": "object"},
                    },
                },
                "actions": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "safety_controls": {
                    "type": "object",
                    "properties": {
                        "max_runtime": {"type": "string"},
                        "escalation_required": {"type": "boolean"},
                        "approval_required": {"type": "string"},
                        "dry_run_mode": {"type": "boolean"},
                    },
                },
            },
        }
    },
}


# ─────────────────────────────────────────────
# Validation Result
# ─────────────────────────────────────────────


class ValidationResult:
    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def add_info(self, msg: str) -> None:
        self.info.append(msg)

    def print_report(self, agent_name: str = "unknown") -> None:
        table = Table(title=f"Validation Report — {agent_name}", show_lines=True)
        table.add_column("Level", style="bold", width=10)
        table.add_column("Message")

        for e in self.errors:
            table.add_row("[red]ERROR[/red]", e)
        for w in self.warnings:
            table.add_row("[yellow]WARN[/yellow]", w)
        for i in self.info:
            table.add_row("[green]INFO[/green]", i)

        console.print(table)
        if self.valid:
            console.print(f"[bold green]✓ Agent definition is VALID[/bold green]")
        else:
            console.print(
                f"[bold red]✗ Agent definition has {len(self.errors)} error(s)[/bold red]"
            )


# ─────────────────────────────────────────────
# Validator
# ─────────────────────────────────────────────


class AdfValidator:
    """
    Two-layer validator:
      Layer 1 — JSON Schema structural validation
      Layer 2 — Pydantic semantic validation
    """

    def validate_file(
        self, path: str | Path
    ) -> Tuple[ValidationResult, AgentDefinition | None]:
        result = ValidationResult()
        path = Path(path)

        if not path.exists():
            result.add_error(f"File not found: {path}")
            return result, None

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            result.add_error(f"Cannot read file: {e}")
            return result, None

        return self.validate_string(raw, file_format=path.suffix.lstrip("."))

    def validate_string(
        self, content: str, file_format: str = "yaml"
    ) -> Tuple[ValidationResult, AgentDefinition | None]:
        result = ValidationResult()

        # ── Parse ──
        try:
            if file_format in ("yaml", "yml"):
                raw_dict = yaml.safe_load(content)
            elif file_format == "json":
                raw_dict = json.loads(content)
            else:
                result.add_error(
                    f"Unsupported format: '{file_format}'. Use yaml or json."
                )
                return result, None
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            result.add_error(f"Parse error: {e}")
            return result, None

        if not isinstance(raw_dict, dict):
            result.add_error("Root document must be a YAML/JSON object (mapping).")
            return result, None

        # ── Layer 1: JSON Schema ──
        try:
            import jsonschema

            jsonschema.validate(raw_dict, ADF_JSON_SCHEMA)
            result.add_info("JSON Schema structural validation passed.")
        except jsonschema.ValidationError as e:
            result.add_error(
                f"JSON Schema violation: {e.message} at path: {list(e.absolute_path)}"
            )
        except jsonschema.SchemaError as e:
            result.add_error(f"Internal schema error: {e.message}")

        if not result.valid:
            return result, None

        # ── Layer 2: Pydantic semantic validation ──
        try:
            doc = AdfDocument.model_validate(raw_dict)
            agent = doc.agent
            result.add_info("Pydantic semantic validation passed.")
        except ValidationError as ve:
            for err in ve.errors():
                loc = " → ".join(str(x) for x in err["loc"])
                result.add_error(f"[{loc}] {err['msg']}")
            return result, None

        # ── Layer 3: Business logic warnings ──
        self._check_business_rules(agent, result)

        return result, agent

    def _check_business_rules(
        self, agent: AgentDefinition, result: ValidationResult
    ) -> None:
        """Emit warnings for non-fatal but suspicious configurations."""

        if not agent.actions:
            result.add_warning(
                "Agent has no actions defined — it will only observe, never respond."
            )

        if agent.reasoning and not agent.consensus_validation:
            result.add_warning(
                "Agent uses AI reasoning but has no consensus_validation. "
                "High-confidence single-model decisions are risky."
            )

        if agent.consensus_validation and agent.consensus_validation.threshold < 0.6:
            result.add_warning(
                f"Consensus threshold {agent.consensus_validation.threshold} is low (<0.60). "
                "Consider raising it for safety."
            )

        destructive = {"isolate_host", "disable_account", "block_ip", "kill_process"}
        if any(a in destructive for a in (agent.actions or [])):
            if agent.safety_controls.approval_required in ("none", None):
                result.add_warning(
                    "Agent executes destructive actions but approval_required is 'none'. "
                    "Set approval_required: high_risk for production."
                )

        if agent.safety_controls.dry_run_mode:
            result.add_info(
                "dry_run_mode is ENABLED — actions will be simulated, not executed."
            )

        result.add_info(f"Agent '{agent.name}' v{agent.version} ready for compilation.")
