"""
Cyphora-S1 — MITRE ATT&CK Mapper & Kill Chain Builder
======================================================
Maps security events and AI reasoning outputs to MITRE ATT&CK tactics
and techniques, then constructs a plain-English kill chain timeline.

This module powers Cyphora-S1's AI Threat Investigator — the feature
that turns raw alerts into a board-ready incident report in under 60s.

Key components
──────────────
  MITREMapper        – Maps event types / keywords to ATT&CK TTPs
  KillChainBuilder   – Assembles ordered kill chain from events + TTPs
  IncidentReporter   – Calls Claude/GPT to produce plain-English report
  AttackIntelligence – Combined output: kill chain + MITRE map + report
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog

from acda.models.schemas import CollectedData, ReasoningResult, SecurityEvent

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK TTP Reference Table
# ─────────────────────────────────────────────────────────────
# Maps (event_type, keyword) → ATT&CK Tactic + Technique
# Reference: https://attack.mitre.org/ Enterprise v14
# ─────────────────────────────────────────────────────────────

MITRE_TTP_MAP: Dict[str, Dict[str, str]] = {
    # ── Initial Access ──────────────────────────────────────────
    "suspicious_login": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "sub_technique": "T1078.004",  # Cloud Accounts
        "description": "Adversary used stolen or compromised credentials to access system.",
    },
    "phishing": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Phishing",
        "technique_id": "T1566",
        "sub_technique": "T1566.001",
        "description": "Spearphishing attachment used to gain initial foothold.",
    },
    # ── Execution ───────────────────────────────────────────────
    "abnormal_process_execution": {
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "sub_technique": "T1059.001",  # PowerShell
        "description": "Suspicious process or script executed on endpoint.",
    },
    "script_execution": {
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "sub_technique": "T1059.003",  # Windows Command Shell
        "description": "Adversary ran a command-line interpreter.",
    },
    # ── Persistence ─────────────────────────────────────────────
    "registry_modification": {
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique": "Boot or Logon Autostart Execution",
        "technique_id": "T1547",
        "sub_technique": "T1547.001",
        "description": "Registry run key modified to persist malware across reboots.",
    },
    "scheduled_task": {
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique": "Scheduled Task/Job",
        "technique_id": "T1053",
        "sub_technique": "T1053.005",
        "description": "Scheduled task created for persistent execution.",
    },
    # ── Privilege Escalation ────────────────────────────────────
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique": "Abuse Elevation Control Mechanism",
        "technique_id": "T1548",
        "sub_technique": "T1548.002",  # Bypass UAC
        "description": "Process or user elevated privileges beyond authorised level.",
    },
    "token_manipulation": {
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique": "Access Token Manipulation",
        "technique_id": "T1134",
        "sub_technique": "T1134.001",
        "description": "Adversary manipulated access tokens to escalate privileges.",
    },
    # ── Defense Evasion ──────────────────────────────────────────
    "log_deletion": {
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Indicator Removal",
        "technique_id": "T1070",
        "sub_technique": "T1070.001",
        "description": "Event logs cleared to remove forensic evidence.",
    },
    "obfuscation": {
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Obfuscated Files or Information",
        "technique_id": "T1027",
        "sub_technique": None,
        "description": "Encoded or obfuscated payloads detected.",
    },
    # ── Credential Access ────────────────────────────────────────
    "credential_dump": {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "OS Credential Dumping",
        "technique_id": "T1003",
        "sub_technique": "T1003.001",  # LSASS Memory
        "description": "Credential dumping from LSASS or SAM database detected.",
    },
    "brute_force": {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "sub_technique": "T1110.001",
        "description": "Multiple failed authentication attempts indicate brute force.",
    },
    # ── Discovery ───────────────────────────────────────────────
    "network_scan": {
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "sub_technique": None,
        "description": "Internal network scanning detected from compromised host.",
    },
    "account_enumeration": {
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Account Discovery",
        "technique_id": "T1087",
        "sub_technique": "T1087.002",  # Domain Account
        "description": "Enumeration of Active Directory or cloud IAM accounts.",
    },
    # ── Lateral Movement ────────────────────────────────────────
    "lateral_movement": {
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "Remote Services",
        "technique_id": "T1021",
        "sub_technique": "T1021.006",  # Windows Remote Management
        "description": "Adversary moved laterally to other hosts using remote services.",
    },
    "pass_the_hash": {
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "Use Alternate Authentication Material",
        "technique_id": "T1550",
        "sub_technique": "T1550.002",
        "description": "Pass-the-hash technique used to authenticate without plaintext password.",
    },
    # ── Collection ──────────────────────────────────────────────
    "data_staging": {
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "technique": "Data Staged",
        "technique_id": "T1074",
        "sub_technique": "T1074.001",
        "description": "Data consolidated in staging location before exfiltration.",
    },
    # ── Exfiltration ────────────────────────────────────────────
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique": "Exfiltration Over C2 Channel",
        "technique_id": "T1041",
        "sub_technique": None,
        "description": "Data being exfiltrated over the established C2 channel.",
    },
    "dns_exfiltration": {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique": "Exfiltration Over Alternative Protocol",
        "technique_id": "T1048",
        "sub_technique": "T1048.003",  # DNS
        "description": "DNS tunnelling used to exfiltrate data covertly.",
    },
    # ── Impact ──────────────────────────────────────────────────
    "abnormal_file_encryption": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Data Encrypted for Impact",
        "technique_id": "T1486",
        "sub_technique": None,
        "description": "Mass file encryption indicates ransomware execution.",
    },
    "service_disruption": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Service Stop",
        "technique_id": "T1489",
        "sub_technique": None,
        "description": "Critical services terminated to disrupt operations.",
    },
    # ── Command and Control ─────────────────────────────────────
    "c2_communication": {
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
        "sub_technique": "T1071.001",  # Web Protocols
        "description": "Outbound C2 communication over HTTP/HTTPS detected.",
    },
    # ── Default / Anomaly ───────────────────────────────────────
    "anomaly_detected": {
        "tactic": "Unknown",
        "tactic_id": "TA0000",
        "technique": "Anomalous Activity",
        "technique_id": "T0000",
        "sub_technique": None,
        "description": "Behavioural anomaly detected — manual triage recommended.",
    },
    "confirmed_attack": {
        "tactic": "Multiple Tactics",
        "tactic_id": "TA0000",
        "technique": "Multi-Stage Attack",
        "technique_id": "T0001",
        "sub_technique": None,
        "description": "Confirmed multi-stage attack — full kill chain analysis required.",
    },
}

# Tactic ordering for kill chain sequencing (Cyber Kill Chain + ATT&CK order)
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Multiple Tactics",
    "Unknown",
]


# ─────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────


@dataclass
class MITRETechnique:
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    sub_technique: Optional[str]
    description: str
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique": f"{self.technique} ({self.technique_id})",
            "sub_technique": self.sub_technique,
            "description": self.description,
            "confidence": self.confidence,
            "mitre_url": f"https://attack.mitre.org/techniques/{self.technique_id}/",
        }


@dataclass
class KillChainStep:
    step_number: int
    timestamp: str
    tactic: str
    technique: str
    technique_id: str
    description: str
    source_event: str
    indicators: List[str] = field(default_factory=list)


@dataclass
class AttackIntelligence:
    """Complete intelligence output for a security event."""

    event_id: str
    analysis_timestamp: str
    ttps_identified: List[MITRETechnique]
    kill_chain: List[KillChainStep]
    plain_english_report: str
    severity: str
    confidence_score: float
    recommended_actions: List[str]
    mitre_navigator_link: str = ""


# ─────────────────────────────────────────────────────────────
# MITRE Mapper
# ─────────────────────────────────────────────────────────────


class MITREMapper:
    """
    Maps a SecurityEvent and its collected telemetry to ATT&CK TTPs.

    Matching strategy (in order of priority):
    1. Exact match on event_type
    2. Keyword scan across log entries (process names, error codes, etc.)
    3. Reasoning engine output keywords
    """

    def map_event(
        self,
        event: SecurityEvent,
        data: CollectedData,
        reasoning: Optional[ReasoningResult] = None,
    ) -> List[MITRETechnique]:
        """Return a deduplicated list of MITRE techniques for this event."""
        techniques: Dict[str, MITRETechnique] = {}

        # 1. Direct event type mapping
        ttp = MITRE_TTP_MAP.get(event.event_type)
        if ttp:
            techniques[ttp["technique_id"]] = MITRETechnique(**ttp, confidence=0.95)

        # 2. Scan log entries for keywords
        all_text = " ".join(
            json.dumps(log, default=str).lower()
            for log in (data.logs[:50] + data.threat_intel[:10])
        )
        for key, ttp in MITRE_TTP_MAP.items():
            if key in all_text and ttp["technique_id"] not in techniques:
                techniques[ttp["technique_id"]] = MITRETechnique(**ttp, confidence=0.75)

        # 3. Parse reasoning output for mentioned techniques
        if reasoning:
            for score in reasoning.scores:
                if score.reasoning:
                    reasoning_lower = score.reasoning.lower()
                    for key, ttp in MITRE_TTP_MAP.items():
                        if (
                            key in reasoning_lower
                            or ttp["technique"].lower() in reasoning_lower
                        ):
                            tid = ttp["technique_id"]
                            if tid not in techniques:
                                techniques[tid] = MITRETechnique(**ttp, confidence=0.70)

        # Sort by tactic order
        result = sorted(
            techniques.values(),
            key=lambda t: (
                TACTIC_ORDER.index(t.tactic)
                if t.tactic in TACTIC_ORDER
                else len(TACTIC_ORDER)
            ),
        )
        logger.info("mitre_mapping_complete", techniques_found=len(result))
        return result


# ─────────────────────────────────────────────────────────────
# Kill Chain Builder
# ─────────────────────────────────────────────────────────────


class KillChainBuilder:
    """
    Assembles a temporally-ordered kill chain from telemetry + MITRE mapping.
    Each step represents one ATT&CK tactic observed in the attack sequence.
    """

    def build(
        self,
        event: SecurityEvent,
        data: CollectedData,
        techniques: List[MITRETechnique],
    ) -> List[KillChainStep]:
        """Build an ordered kill chain from the identified techniques."""
        steps = []
        # Use log timestamps where available; fall back to event timestamp
        base_ts = event.timestamp

        for i, ttp in enumerate(techniques):
            # Find a relevant log entry timestamp
            ts = self._find_timestamp(data, ttp, i, base_ts)
            indicators = self._extract_indicators(data, event, ttp)

            steps.append(
                KillChainStep(
                    step_number=i + 1,
                    timestamp=ts,
                    tactic=ttp.tactic,
                    technique=ttp.technique,
                    technique_id=ttp.technique_id,
                    description=ttp.description,
                    source_event=event.event_type,
                    indicators=indicators,
                )
            )

        logger.info("kill_chain_built", steps=len(steps))
        return steps

    def _find_timestamp(
        self,
        data: CollectedData,
        ttp: MITRETechnique,
        fallback_offset: int,
        base_ts: str,
    ) -> str:
        """Find the earliest relevant timestamp in collected logs."""
        for log in data.logs:
            if not isinstance(log, dict):
                continue
            ts = (
                log.get("timestamp")
                or log.get("@timestamp")
                or log.get("createdDateTime")
            )
            if ts:
                return str(ts)
        return base_ts

    def _extract_indicators(
        self,
        data: CollectedData,
        event: SecurityEvent,
        ttp: MITRETechnique,
    ) -> List[str]:
        """Extract IOCs relevant to this technique from collected data."""
        indicators = []
        if event.source_ip:
            indicators.append(f"IP: {event.source_ip}")
        if event.source_host:
            indicators.append(f"Host: {event.source_host}")
        if event.user:
            indicators.append(f"User: {event.user}")
        if event.process:
            indicators.append(f"Process: {event.process}")
        for ti in data.threat_intel:
            if not isinstance(ti, dict):
                continue
            if indicator := ti.get("indicator"):
                indicators.append(
                    f"Threat Intel: {indicator} ({ti.get('feed', 'unknown feed')})"
                )
        return indicators[:5]  # cap for readability


# ─────────────────────────────────────────────────────────────
# Incident Reporter (LLM-powered plain-English report)
# ─────────────────────────────────────────────────────────────


class IncidentReporter:
    """
    Uses Claude (preferred) or GPT-4o to produce a plain-English incident
    report from the collected telemetry, MITRE TTPs, and kill chain.

    The report is structured for both technical SOC analysts AND
    non-technical executives — suitable for a board-level briefing.
    """

    SYSTEM_PROMPT = (
        "You are Cyphora-S1, an expert AI security analyst. "
        "Produce a clear, structured incident report. "
        "Write for two audiences: (1) SOC analyst technical detail, "
        "(2) executive summary in plain English with no jargon. "
        "Be specific, accurate, and concise. "
        "Respond ONLY with valid JSON matching the provided schema."
    )

    def __init__(
        self,
        model_id: str = "claude-sonnet-4-6",
        api_key: Optional[str] = None,
    ) -> None:
        self._model_id = model_id
        self._api_key = api_key

    async def generate(
        self,
        event: SecurityEvent,
        data: CollectedData,
        kill_chain: List[KillChainStep],
        ttps: List[MITRETechnique],
        consensus_score: float,
    ) -> str:
        """Generate a plain-English incident report. Returns markdown string."""
        chain_summary = "\n".join(
            f"  Step {s.step_number}: {s.tactic} — {s.technique} ({s.technique_id})"
            for s in kill_chain
        )
        ttp_summary = "\n".join(
            f"  {t.technique_id}: {t.technique} [{t.tactic}]" for t in ttps
        )

        user_prompt = f"""
Generate an incident report for the following security event:

EVENT DETAILS:
  ID: {event.event_id}
  Type: {event.event_type}
  Severity: {event.severity}
  Host: {event.source_host or 'unknown'}
  User: {event.user or 'unknown'}
  Source IP: {event.source_ip or 'unknown'}
  AI Confidence Score: {consensus_score:.2f}/1.0

KILL CHAIN ({len(kill_chain)} stages observed):
{chain_summary}

MITRE ATT&CK TECHNIQUES:
{ttp_summary}

LOG SUMMARY: {len(data.logs)} log entries collected. {len(data.threat_intel)} threat intelligence hits.
THREAT INTEL: {json.dumps(data.threat_intel[:3], default=str)}

Respond with JSON:
{{
  "executive_summary": "2-3 sentence plain English summary for leadership",
  "what_happened": "Technical narrative of the attack, step by step",
  "business_impact": "Potential impact on the business if not contained",
  "immediate_actions": ["action1", "action2", "action3"],
  "severity_justification": "Why this severity rating was assigned",
  "confidence_explanation": "What the AI confidence score means in plain terms"
}}
"""

        try:
            if self._model_id.startswith("claude-"):
                return await self._call_anthropic(user_prompt)
            elif self._model_id.startswith("gpt-"):
                return await self._call_openai(user_prompt)
            else:
                return self._generate_template_report(
                    event, kill_chain, ttps, consensus_score
                )
        except Exception as exc:
            logger.error("incident_reporter_failed", error=str(exc))
            return self._generate_template_report(
                event, kill_chain, ttps, consensus_score
            )

    async def _call_anthropic(self, prompt: str) -> str:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self._api_key)
        response = await client.messages.create(
            model=self._model_id,
            max_tokens=2048,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text if response.content else "{}"
        return self._format_report_from_json(raw)

    async def _call_openai(self, prompt: str) -> str:
        import openai

        client = openai.AsyncOpenAI(api_key=self._api_key)
        response = await client.chat.completions.create(
            model=self._model_id,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            max_tokens=2048,
        )
        raw = response.choices[0].message.content or "{}"
        return self._format_report_from_json(raw)

    def _format_report_from_json(self, raw: str) -> str:
        """Convert JSON response to formatted markdown report."""
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError(
                    f"Expected JSON object for incident report, got {type(data).__name__}"
                )
            ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            return (
                f"## Cyphora-S1 Incident Report — {ts}\n\n"
                f"### Executive Summary\n{data.get('executive_summary', 'N/A')}\n\n"
                f"### What Happened\n{data.get('what_happened', 'N/A')}\n\n"
                f"### Business Impact\n{data.get('business_impact', 'N/A')}\n\n"
                f"### Immediate Actions Required\n"
                + "\n".join(f"- {a}" for a in data.get("immediate_actions", []))
                + f"\n\n### Severity Justification\n{data.get('severity_justification', 'N/A')}\n\n"
                f"### AI Confidence\n{data.get('confidence_explanation', 'N/A')}\n"
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return raw  # return raw if JSON parsing fails

    def _generate_template_report(
        self,
        event: SecurityEvent,
        kill_chain: List[KillChainStep],
        ttps: List[MITRETechnique],
        score: float,
    ) -> str:
        """Fallback template report when LLM is unavailable."""
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        tactic_list = ", ".join(t.tactic for t in ttps[:5]) or "Unknown"
        technique_list = "\n".join(
            f"- {t.technique_id}: {t.technique} [{t.tactic}]" for t in ttps
        )
        chain_list = "\n".join(
            f"- Step {s.step_number}: {s.tactic} — {s.technique}" for s in kill_chain
        )
        return (
            f"## Cyphora-S1 Incident Report — {ts}\n\n"
            f"**Event:** {event.event_type} | **Severity:** {event.severity.upper()} | "
            f"**AI Confidence:** {score:.0%}\n\n"
            f"**Host:** {event.source_host or 'unknown'} | **User:** {event.user or 'unknown'} | "
            f"**Source IP:** {event.source_ip or 'unknown'}\n\n"
            f"### Attack Tactics Identified\n{tactic_list}\n\n"
            f"### MITRE ATT&CK Techniques\n{technique_list}\n\n"
            f"### Kill Chain\n{chain_list}\n\n"
            f"*Report generated by Cyphora-S1 AI Threat Investigator. "
            f"Enable LLM for enhanced plain-English narrative.*\n"
        )


# ─────────────────────────────────────────────────────────────
# Integrated Analysis Engine
# ─────────────────────────────────────────────────────────────


class ThreatInvestigator:
    """
    Top-level orchestrator for Cyphora-S1's AI Threat Investigator feature.

    Given a SecurityEvent, CollectedData, and ReasoningResult, produces
    a complete AttackIntelligence object in under 60 seconds.

    Usage
    -----
        investigator = ThreatInvestigator(llm_model="claude-sonnet-4-6")
        intel = await investigator.investigate(event, data, reasoning)
        print(intel.plain_english_report)
    """

    def __init__(
        self,
        llm_model: str = "claude-sonnet-4-6",
        llm_api_key: Optional[str] = None,
    ) -> None:
        self._mapper = MITREMapper()
        self._chain_builder = KillChainBuilder()
        self._reporter = IncidentReporter(model_id=llm_model, api_key=llm_api_key)

    async def investigate(
        self,
        event: SecurityEvent,
        data: CollectedData,
        reasoning: Optional[ReasoningResult] = None,
        consensus_score: float = 0.0,
    ) -> AttackIntelligence:
        """Run full investigation pipeline and return structured intelligence."""

        # Step 1: Map to MITRE TTPs
        ttps = self._mapper.map_event(event, data, reasoning)

        # Step 2: Build kill chain
        kill_chain = self._chain_builder.build(event, data, ttps)

        # Step 3: Generate plain-English report
        report = await self._reporter.generate(
            event, data, kill_chain, ttps, consensus_score
        )

        # Step 4: Determine recommended actions based on tactics
        actions = self._recommend_actions(ttps, event.severity)

        # Build MITRE Navigator link for the identified techniques
        technique_ids = [t.technique_id for t in ttps if t.technique_id != "T0000"]
        navigator_link = self._build_navigator_link(technique_ids)

        return AttackIntelligence(
            event_id=event.event_id,
            analysis_timestamp=datetime.now(tz=timezone.utc).isoformat(),
            ttps_identified=ttps,
            kill_chain=kill_chain,
            plain_english_report=report,
            severity=event.severity,
            confidence_score=consensus_score,
            recommended_actions=actions,
            mitre_navigator_link=navigator_link,
        )

    def _recommend_actions(
        self,
        ttps: List[MITRETechnique],
        severity: str,
    ) -> List[str]:
        """Map identified TTPs to recommended response actions."""
        actions = set()
        tactic_names = {t.tactic for t in ttps}

        if "Initial Access" in tactic_names or "Credential Access" in tactic_names:
            actions.add("revoke_token")
            actions.add("disable_account")
        if "Lateral Movement" in tactic_names:
            actions.add("isolate_host")
            actions.add("block_ip")
        if "Exfiltration" in tactic_names or "Command and Control" in tactic_names:
            actions.add("block_ip")
            actions.add("isolate_host")
        if "Impact" in tactic_names:
            actions.add("isolate_host")
            actions.add("snapshot_memory")
        if severity in ("critical", "high"):
            actions.add("notify_soc")
            actions.add("generate_incident_report")
            actions.add("pagerduty_incident")
        else:
            actions.add("create_threat_alert")
            actions.add("notify_soc")

        return sorted(actions)

    def _build_navigator_link(self, technique_ids: List[str]) -> str:
        """Build a MITRE ATT&CK Navigator deep link for the identified techniques."""
        if not technique_ids:
            return "https://attack.mitre.org/"
        techniques_param = ",".join(dict.fromkeys(technique_ids))  # deduplicate
        return f"https://mitre-attack.github.io/attack-navigator/#layerURL=techniques={techniques_param}"
