"""
Cyphora-S1 — Compliance Evidence Automation Engine
===================================================
Generates framework-specific compliance evidence packages from live
security telemetry — replacing weeks of manual audit preparation.

Supported frameworks
────────────────────
  SOC 2 Type II   → Trust Services Criteria (CC series)
  ISO 27001:2022  → Annex A controls
  PCI-DSS v4.0    → 12 requirements
  HIPAA           → Technical safeguards (§164.312)
  NIS2            → EU Network & Information Systems Directive 2022/2555

Key components
──────────────
  ComplianceControl    – A single control/requirement mapped to evidence
  EvidenceItem         – A log entry or finding that satisfies a control
  FrameworkReport      – Complete compliance report for one framework
  ComplianceEngine     – Collects evidence and generates reports
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

import structlog

from acda.models.schemas import CollectedData, SecurityEvent
from acda.runtime.data_collector import DataCollector

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Framework Definitions
# ─────────────────────────────────────────────────────────────


@dataclass
class ComplianceControl:
    """A single control requirement within a compliance framework."""

    control_id: str  # e.g. "CC6.1" or "A.9.4.1"
    framework: str
    title: str
    description: str
    evidence_sources: List[str]  # which data sources satisfy this control
    evidence_keywords: List[str]  # keywords to look for in log entries
    auto_satisfiable: bool = True  # can be evidenced automatically vs. manual


# SOC 2 Trust Services Criteria (selected key controls)
SOC2_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        control_id="CC6.1",
        framework="SOC 2",
        title="Logical and Physical Access Controls",
        description="Logical access security measures restrict access to information assets.",
        evidence_sources=["identity_logs", "okta", "azure_ad"],
        evidence_keywords=["login", "access_granted", "mfa", "token_issued"],
    ),
    ComplianceControl(
        control_id="CC6.2",
        framework="SOC 2",
        title="New Access Provisioning",
        description="Prior to issuing system credentials, the entity registers and authorises new users.",
        evidence_sources=["identity_logs", "azure_ad"],
        evidence_keywords=["user_created", "account_provisioned", "access_granted"],
    ),
    ComplianceControl(
        control_id="CC6.3",
        framework="SOC 2",
        title="Access Removal",
        description="Access removed in a timely manner when no longer required.",
        evidence_sources=["identity_logs"],
        evidence_keywords=["account_disabled", "access_revoked", "token_revoked"],
    ),
    ComplianceControl(
        control_id="CC6.7",
        framework="SOC 2",
        title="Transmission Protections",
        description="Data in transit protected using cryptographic controls.",
        evidence_sources=["network_logs", "aws_cloudtrail"],
        evidence_keywords=["tls", "https", "encrypted", "ssl"],
    ),
    ComplianceControl(
        control_id="CC7.1",
        framework="SOC 2",
        title="System Monitoring",
        description="The entity monitors system components for anomalies and indicators of compromise.",
        evidence_sources=["endpoint_logs", "network_logs", "aws_cloudtrail"],
        evidence_keywords=["alert", "anomaly", "threat_detected", "monitoring"],
    ),
    ComplianceControl(
        control_id="CC7.2",
        framework="SOC 2",
        title="Security Incident Evaluation",
        description="Security incidents are identified and classified using defined criteria.",
        evidence_sources=["endpoint_logs", "identity_logs"],
        evidence_keywords=["incident", "alert", "threat", "investigated"],
    ),
    ComplianceControl(
        control_id="CC7.3",
        framework="SOC 2",
        title="Incident Response",
        description="Documented incident response procedures are followed.",
        evidence_sources=["endpoint_logs"],
        evidence_keywords=["incident_report", "contain", "remediat", "escalat"],
    ),
    ComplianceControl(
        control_id="CC8.1",
        framework="SOC 2",
        title="Change Management",
        description="Authorised, tested, and approved changes to infrastructure.",
        evidence_sources=["aws_cloudtrail", "github_audit", "gcp_audit"],
        evidence_keywords=[
            "deploy",
            "update",
            "change",
            "config_change",
            "CreateStack",
        ],
    ),
    ComplianceControl(
        control_id="CC9.1",
        framework="SOC 2",
        title="Risk Assessment",
        description="Entity identifies, selects, and develops risk mitigation activities.",
        evidence_sources=["threat_intel"],
        evidence_keywords=["risk", "vulnerability", "threat_intel"],
        auto_satisfiable=False,
    ),
]

# ISO 27001:2022 Annex A (selected technical controls)
ISO27001_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        control_id="A.5.15",
        framework="ISO 27001",
        title="Access Control",
        description="Rules to control physical and logical access to information.",
        evidence_sources=["identity_logs", "okta", "azure_ad"],
        evidence_keywords=["access_control", "login", "mfa"],
    ),
    ComplianceControl(
        control_id="A.5.23",
        framework="ISO 27001",
        title="Information Security for Cloud Services",
        description="Processes for acquisition, use, management, and exit from cloud services.",
        evidence_sources=["aws_cloudtrail", "gcp_audit", "azure_ad"],
        evidence_keywords=["cloud", "aws", "gcp", "azure"],
    ),
    ComplianceControl(
        control_id="A.8.5",
        framework="ISO 27001",
        title="Secure Authentication",
        description="Secure authentication technologies implemented based on access restrictions.",
        evidence_sources=["identity_logs", "okta"],
        evidence_keywords=["mfa", "2fa", "token_issued", "sso"],
    ),
    ComplianceControl(
        control_id="A.8.7",
        framework="ISO 27001",
        title="Protection Against Malware",
        description="Protection against malware implemented and supported by user awareness.",
        evidence_sources=["endpoint_logs", "crowdstrike"],
        evidence_keywords=["malware", "antivirus", "quarantine", "threat_blocked"],
    ),
    ComplianceControl(
        control_id="A.8.15",
        framework="ISO 27001",
        title="Logging",
        description="Logs producing evidence of activities, exceptions, and security events kept.",
        evidence_sources=["endpoint_logs", "aws_cloudtrail", "network_logs"],
        evidence_keywords=["log", "audit", "event"],
    ),
    ComplianceControl(
        control_id="A.8.16",
        framework="ISO 27001",
        title="Monitoring Activities",
        description="Networks, systems, and applications monitored for anomalous behaviour.",
        evidence_sources=["network_logs", "endpoint_logs"],
        evidence_keywords=["monitor", "alert", "anomaly"],
    ),
]

# PCI-DSS v4.0 (selected technical requirements)
PCIDSS_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        control_id="PCI-1.3",
        framework="PCI-DSS",
        title="Network Access Controls",
        description="Network access to and from the cardholder data environment is restricted.",
        evidence_sources=["network_logs", "palo_alto"],
        evidence_keywords=["firewall", "block", "allow", "network_policy"],
    ),
    ComplianceControl(
        control_id="PCI-7.2",
        framework="PCI-DSS",
        title="Access Control System",
        description="Access control system covers all system components.",
        evidence_sources=["identity_logs", "azure_ad", "okta"],
        evidence_keywords=["access_control", "rbac", "role", "permission"],
    ),
    ComplianceControl(
        control_id="PCI-8.2",
        framework="PCI-DSS",
        title="User Identification and Authentication",
        description="All users are assigned unique IDs before allowing system access.",
        evidence_sources=["identity_logs"],
        evidence_keywords=["user_id", "unique", "mfa", "token"],
    ),
    ComplianceControl(
        control_id="PCI-10.2",
        framework="PCI-DSS",
        title="Audit Log Implementation",
        description="Audit logs capture all individual user access to cardholder data.",
        evidence_sources=["aws_cloudtrail", "endpoint_logs"],
        evidence_keywords=["audit_log", "access", "read", "cardholder"],
    ),
    ComplianceControl(
        control_id="PCI-10.7",
        framework="PCI-DSS",
        title="Security Event Response",
        description="Failures of critical security controls are detected and reported promptly.",
        evidence_sources=["endpoint_logs", "network_logs"],
        evidence_keywords=["failure", "alert", "incident", "security_event"],
    ),
    ComplianceControl(
        control_id="PCI-12.10",
        framework="PCI-DSS",
        title="Incident Response Plan",
        description="Incident response plan implemented, tested, and reviewed.",
        evidence_sources=["endpoint_logs"],
        evidence_keywords=["incident_response", "ir_plan", "contain", "notify"],
        auto_satisfiable=False,
    ),
]

# HIPAA Technical Safeguards (§164.312)
HIPAA_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        control_id="HIPAA-164.312(a)(1)",
        framework="HIPAA",
        title="Access Control",
        description="Unique user identification, emergency access, automatic logoff, encryption.",
        evidence_sources=["identity_logs", "okta", "azure_ad"],
        evidence_keywords=["login", "access", "unique_user", "mfa", "token"],
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(b)",
        framework="HIPAA",
        title="Audit Controls",
        description="Hardware, software, and procedural mechanisms to record activity in systems.",
        evidence_sources=["aws_cloudtrail", "endpoint_logs", "azure_ad"],
        evidence_keywords=["audit", "log", "access_log", "activity"],
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(c)(1)",
        framework="HIPAA",
        title="Integrity",
        description="PHI not improperly altered or destroyed.",
        evidence_sources=["file_activity_logs", "aws_cloudtrail"],
        evidence_keywords=["integrity", "hash", "checksum", "unaltered", "write"],
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(e)(1)",
        framework="HIPAA",
        title="Transmission Security",
        description="Technical security measures to guard against unauthorised access during ePHI transmission.",
        evidence_sources=["network_logs"],
        evidence_keywords=["tls", "ssl", "encrypted", "https", "secure_channel"],
    ),
]

# NIS2 Directive (EU 2022/2555) — Selected Article 21 measures
NIS2_CONTROLS: List[ComplianceControl] = [
    ComplianceControl(
        control_id="NIS2-Art21(a)",
        framework="NIS2",
        title="Risk Analysis and Information System Security Policies",
        description="Policies on risk analysis and information system security.",
        evidence_sources=["threat_intel", "endpoint_logs"],
        evidence_keywords=["risk", "policy", "security_assessment"],
        auto_satisfiable=False,
    ),
    ComplianceControl(
        control_id="NIS2-Art21(b)",
        framework="NIS2",
        title="Incident Handling",
        description="Policies and procedures for handling security incidents.",
        evidence_sources=["endpoint_logs", "network_logs"],
        evidence_keywords=["incident", "handle", "response", "report"],
    ),
    ComplianceControl(
        control_id="NIS2-Art21(e)",
        framework="NIS2",
        title="Supply Chain Security",
        description="Security in network and information systems supply chain.",
        evidence_sources=["github_audit", "aws_cloudtrail"],
        evidence_keywords=["supply_chain", "third_party", "vendor", "dependency"],
    ),
    ComplianceControl(
        control_id="NIS2-Art21(g)",
        framework="NIS2",
        title="Cyber Hygiene and Training",
        description="Basic cyber hygiene practices and cybersecurity training.",
        evidence_sources=["identity_logs"],
        evidence_keywords=["mfa", "password_change", "training"],
        auto_satisfiable=False,
    ),
    ComplianceControl(
        control_id="NIS2-Art21(h)",
        framework="NIS2",
        title="Cryptography and Encryption",
        description="Policies on use of cryptography and encryption.",
        evidence_sources=["network_logs", "aws_cloudtrail"],
        evidence_keywords=["encrypt", "tls", "kms", "ssl", "crypto"],
    ),
    ComplianceControl(
        control_id="NIS2-Art21(i)",
        framework="NIS2",
        title="Human Resources Security and Access Control",
        description="Security of human resources and access control policies.",
        evidence_sources=["identity_logs", "okta", "azure_ad"],
        evidence_keywords=[
            "access_control",
            "rbac",
            "mfa",
            "offboard",
            "account_disabled",
        ],
    ),
]

FRAMEWORK_CONTROLS: Dict[str, List[ComplianceControl]] = {
    "soc2": SOC2_CONTROLS,
    "iso27001": ISO27001_CONTROLS,
    "pcidss": PCIDSS_CONTROLS,
    "hipaa": HIPAA_CONTROLS,
    "nis2": NIS2_CONTROLS,
}


# ─────────────────────────────────────────────────────────────
# Evidence and Report Models
# ─────────────────────────────────────────────────────────────


@dataclass
class EvidenceItem:
    control_id: str
    source: str
    timestamp: str
    description: str
    log_entry: Dict[str, Any] = field(default_factory=dict)
    relevance_score: float = 1.0


@dataclass
class ControlFinding:
    control: ComplianceControl
    status: str  # "satisfied" | "partial" | "gap" | "manual_required"
    evidence_count: int
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    gap_description: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class FrameworkReport:
    report_id: str
    framework: str
    generated_at: str
    period_start: str
    period_end: str
    controls_total: int
    controls_satisfied: int
    controls_partial: int
    controls_gap: int
    controls_manual: int
    compliance_percentage: float
    findings: List[ControlFinding]
    evidence_collection_time_ms: float
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "framework": self.framework,
            "generated_at": self.generated_at,
            "period": f"{self.period_start} – {self.period_end}",
            "compliance_score": f"{self.compliance_percentage:.1f}%",
            "controls": {
                "total": self.controls_total,
                "satisfied": self.controls_satisfied,
                "partial": self.controls_partial,
                "gaps": self.controls_gap,
                "manual_required": self.controls_manual,
            },
            "findings": [
                {
                    "control_id": f.control.control_id,
                    "title": f.control.title,
                    "status": f.status,
                    "evidence_count": f.evidence_count,
                    "gap": f.gap_description,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "summary": self.summary,
        }


# ─────────────────────────────────────────────────────────────
# Compliance Engine
# ─────────────────────────────────────────────────────────────


class ComplianceEngine:
    """
    Cyphora-S1 Compliance Evidence Automation Engine.

    Automatically collects evidence from live security telemetry and
    generates framework-specific compliance reports.

    Reduces audit preparation from 3 weeks to under 3 hours.

    Usage
    -----
        engine = ComplianceEngine()
        report = await engine.generate_report("soc2", lookback_days=90)
        print(report.compliance_percentage)
        print(engine.export_markdown(report))
    """

    def __init__(self) -> None:
        pass

    async def generate_report(
        self,
        framework: str,
        lookback_days: int = 90,
    ) -> FrameworkReport:
        """
        Generate a compliance evidence report for the specified framework.

        Parameters
        ----------
        framework : str
            One of: soc2, iso27001, pcidss, hipaa, nis2
        lookback_days : int
            How many days of telemetry to collect evidence from (default: 90)

        Returns
        -------
        FrameworkReport with evidence-backed findings for each control.
        """
        import time

        start = time.perf_counter()

        framework_key = framework.lower().replace("-", "").replace(" ", "")
        controls = FRAMEWORK_CONTROLS.get(framework_key)
        if not controls:
            raise ValueError(
                f"Unknown framework '{framework}'. "
                f"Supported: {', '.join(FRAMEWORK_CONTROLS.keys())}"
            )

        period_end = datetime.now(tz=timezone.utc)
        period_start = period_end - timedelta(days=lookback_days)
        time_window = f"{lookback_days * 24}h"

        # Collect evidence for all controls
        findings = []
        for control in controls:
            finding = await self._evaluate_control(control, time_window)
            findings.append(finding)

        # Tally scores
        satisfied = sum(1 for f in findings if f.status == "satisfied")
        partial = sum(1 for f in findings if f.status == "partial")
        gaps = sum(1 for f in findings if f.status == "gap")
        manual = sum(1 for f in findings if f.status == "manual_required")
        total = len(findings)

        # Compliance % = satisfied + 0.5 * partial / total (manual = not counted)
        scoreable = total - manual
        compliance_pct = (
            ((satisfied + partial * 0.5) / scoreable * 100) if scoreable > 0 else 0.0
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        report = FrameworkReport(
            report_id=f"{framework_key.upper()}-{period_end.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            framework=framework.upper(),
            generated_at=period_end.isoformat(),
            period_start=period_start.strftime("%Y-%m-%d"),
            period_end=period_end.strftime("%Y-%m-%d"),
            controls_total=total,
            controls_satisfied=satisfied,
            controls_partial=partial,
            controls_gap=gaps,
            controls_manual=manual,
            compliance_percentage=round(compliance_pct, 1),
            findings=findings,
            evidence_collection_time_ms=elapsed_ms,
            summary=self._build_summary(
                framework, satisfied, total, manual, compliance_pct
            ),
        )

        logger.info(
            "compliance_report_generated",
            framework=framework,
            controls=total,
            satisfied=satisfied,
            compliance_pct=round(compliance_pct, 1),
            elapsed_ms=round(elapsed_ms, 0),
        )

        return report

    async def _evaluate_control(
        self,
        control: ComplianceControl,
        time_window: str,
    ) -> ControlFinding:
        """Collect evidence for a single compliance control."""

        if not control.auto_satisfiable:
            return ControlFinding(
                control=control,
                status="manual_required",
                evidence_count=0,
                gap_description="This control requires manual evidence (policy documents, training records, etc.).",
                recommendation=f"Provide manual evidence for {control.control_id} during audit preparation.",
            )

        # Create synthetic event to drive data collection
        event = SecurityEvent(
            event_id=f"COMP-{control.control_id}-{uuid.uuid4().hex[:6]}",
            event_type="compliance_check",
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            severity="info",
        )

        collector = DataCollector(
            sources=control.evidence_sources,
            time_window=time_window,
            max_records=200,
            enrich_with_threat_intel=False,
        )

        try:
            data = await collector.collect(event)
        except Exception as exc:
            logger.error(
                "compliance_collection_failed",
                control=control.control_id,
                error=str(exc),
            )
            return ControlFinding(
                control=control,
                status="gap",
                evidence_count=0,
                gap_description=f"Data collection failed: {exc}",
            )

        # Match evidence keywords against logs
        evidence_items: List[EvidenceItem] = []
        for log in data.logs[:50]:
            log_text = json.dumps(log, default=str).lower()
            matches = [kw for kw in control.evidence_keywords if kw in log_text]
            if matches:
                ts = (
                    log.get("timestamp")
                    or log.get("@timestamp")
                    or log.get("createdDateTime")
                    or datetime.now(tz=timezone.utc).isoformat()
                )
                evidence_items.append(
                    EvidenceItem(
                        control_id=control.control_id,
                        source=log.get("source", "unknown"),
                        timestamp=str(ts),
                        description=f"Evidence matched keywords: {', '.join(matches[:3])}",
                        log_entry={k: v for k, v in list(log.items())[:8]},
                        relevance_score=len(matches) / len(control.evidence_keywords),
                    )
                )

        # Determine status
        if len(evidence_items) >= 5:
            status = "satisfied"
            gap = None
            recommendation = None
        elif len(evidence_items) >= 1:
            status = "partial"
            gap = f"Only {len(evidence_items)} evidence items found. Recommend at least 5 for audit confidence."
            recommendation = (
                f"Increase logging verbosity for {', '.join(control.evidence_sources)}."
            )
        else:
            status = "gap"
            gap = f"No evidence found for {control.control_id} across {', '.join(control.evidence_sources)}."
            recommendation = f"Ensure {', '.join(control.evidence_sources)} are connected and generating logs."

        return ControlFinding(
            control=control,
            status=status,
            evidence_count=len(evidence_items),
            evidence_items=evidence_items[:10],  # keep top 10 for report
            gap_description=gap,
            recommendation=recommendation,
        )

    def _build_summary(
        self,
        framework: str,
        satisfied: int,
        total: int,
        manual: int,
        pct: float,
    ) -> str:
        status = "PASS" if pct >= 80.0 else ("REVIEW" if pct >= 60.0 else "FAIL")
        return (
            f"{framework.upper()} compliance assessment complete. "
            f"Status: {status}. "
            f"{satisfied}/{total} controls satisfied ({pct:.1f}% automated score). "
            f"{manual} controls require manual evidence (policy documents, training records). "
            f"Report generated by Cyphora-S1 Compliance Engine."
        )

    def export_markdown(self, report: FrameworkReport) -> str:
        """Export the compliance report as a formatted markdown document."""
        status_emoji = {
            "satisfied": "✅",
            "partial": "⚠️",
            "gap": "❌",
            "manual_required": "📋",
        }

        lines = [
            f"# {report.framework} Compliance Report",
            f"**Report ID:** {report.report_id}  ",
            f"**Generated:** {report.generated_at}  ",
            f"**Period:** {report.period_start} to {report.period_end}  ",
            f"**Compliance Score:** {report.compliance_percentage:.1f}%  ",
            "",
            "## Summary",
            f"> {report.summary}",
            "",
            "## Control Results",
            "",
            "| Control ID | Title | Status | Evidence |",
            "|------------|-------|--------|----------|",
        ]

        for f in report.findings:
            emoji = status_emoji.get(f.status, "")
            lines.append(
                f"| {f.control.control_id} | {f.control.title} | "
                f"{emoji} {f.status.replace('_', ' ').title()} | "
                f"{f.evidence_count} items |"
            )

        # Gap recommendations
        gaps = [
            f
            for f in report.findings
            if f.status in ("gap", "partial") and f.recommendation
        ]
        if gaps:
            lines.extend(["", "## Gaps & Recommendations", ""])
            for f in gaps:
                lines.append(f"**{f.control.control_id} — {f.control.title}**")
                lines.append(f"- Gap: {f.gap_description}")
                lines.append(f"- Recommendation: {f.recommendation}")
                lines.append("")

        lines.extend(
            [
                "---",
                f"*Report generated by Cyphora-S1 Compliance Engine in "
                f"{report.evidence_collection_time_ms / 1000:.1f}s. "
                f"This automated report covers technical controls only. "
                f"Manual controls require human-reviewed policy evidence.*",
            ]
        )

        return "\n".join(lines)

    async def generate_all_frameworks(
        self, lookback_days: int = 90
    ) -> Dict[str, FrameworkReport]:
        """Generate reports for all supported frameworks in parallel."""
        import asyncio

        tasks = {
            fw: self.generate_report(fw, lookback_days)
            for fw in FRAMEWORK_CONTROLS.keys()
        }
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        output = {}
        for fw, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                logger.error(
                    "compliance_framework_failed", framework=fw, error=str(result)
                )
            else:
                output[fw] = result
        return output
