"""
Cyphora-S1 — AI-Native SIEM Platform
=====================================
Extension modules for ACDA-SDK that deliver the full Cyphora-S1
feature set on top of the ACDA consensus-agent framework.

Modules
-------
  cyphora_ingest        Production log source adapters (7 cloud/IdP/EDR sources)
  cef_parser            CEF log parser — CrowdStrike, Cortex XDR, Okta
  cef_adapters          CEF DataCollector adapters + SecurityEvent factory
  ocsf_parser           OCSF event parser — vendor-neutral, any OCSF-emitting source
  ocsf_adapters         OCSF DataCollector adapters + SecurityEvent factory
  format_normalizer     Universal CEF/JSON/proprietary -> OCSF normalization layer
  mitre_mapper          MITRE ATT&CK mapping, kill chain, incident reports
  ueba_engine           User & Entity Behavior Analytics
  nl_query_engine       Natural Language Query Interface
  compliance_engine     SOC 2 / ISO 27001 / PCI-DSS / HIPAA / NIS2 automation
  playbook_engine       Ordered response playbooks + PagerDuty integration
  schemas_cyphora_extensions  Pydantic v2 models for all new output types

Quick start (API adapters)
--------------------------
    from cyphora_s1.cyphora_ingest import register_all_adapters
    register_all_adapters()   # reads env vars, registers production adapters

Quick start (CEF log files)
---------------------------
    from cyphora_s1.cef_adapters import register_cef_adapters, SecurityEventFactory
    register_cef_adapters(mixed_file="data/sample_security_logs.cef")
    events = SecurityEventFactory.from_file("data/sample_security_logs.cef")

Version: 2.7.0
"""

from acda.utils.logging_config import configure_logging

configure_logging()

__version__ = "2.7.0"
__product__ = "Cyphora-S1"
__base_sdk__ = "ACDA-SDK v1.1"

from .cyphora_ingest import register_all_adapters, CyphoraIngestConfig
from .cef_parser import CEFParser, CEFRecord, CEFVendor, parse_cef_file, parse_cef_text
from .cef_adapters import (
    register_cef_adapters,
    SecurityEventFactory,
    CrowdStrikeCEFAdapter,
    CortexXDRCEFAdapter,
    OktaCEFAdapter,
)
from .ocsf_parser import (
    OCSFParser,
    OCSFRecord,
    OCSFCategory,
    parse_ocsf_file,
    parse_ocsf_text,
)
from .ocsf_adapters import (
    register_ocsf_adapters,
    OCSFSecurityEventFactory,
    SystemActivityOCSFAdapter,
    FindingsOCSFAdapter,
    IAMOCSFAdapter,
    NetworkActivityOCSFAdapter,
    DiscoveryOCSFAdapter,
    ApplicationActivityOCSFAdapter,
    RemediationOCSFAdapter,
)
from .format_normalizer import (
    UniversalNormalizer,
    FieldMappingProfile,
    FormatDetector,
    SourceFormat,
    CEFToOCSFConverter,
    GenericJSONToOCSFConverter,
    ingest_to_security_event_dicts,
    register_profile_globally,
)
from .mitre_mapper import ThreatInvestigator, MITREMapper, KillChainBuilder
from .ueba_engine import UEBAEngine
from .nl_query_engine import NLQueryEngine
from .compliance_engine import ComplianceEngine
from .playbook_engine import PlaybookEngine

__all__ = [
    # Ingestion
    "register_all_adapters",
    "CyphoraIngestConfig",
    # CEF
    "CEFParser",
    "CEFRecord",
    "CEFVendor",
    "parse_cef_file",
    "parse_cef_text",
    "register_cef_adapters",
    "SecurityEventFactory",
    "CrowdStrikeCEFAdapter",
    "CortexXDRCEFAdapter",
    "OktaCEFAdapter",
    # OCSF
    "OCSFParser",
    "OCSFRecord",
    "OCSFCategory",
    "parse_ocsf_file",
    "parse_ocsf_text",
    "register_ocsf_adapters",
    "OCSFSecurityEventFactory",
    "SystemActivityOCSFAdapter",
    "FindingsOCSFAdapter",
    "IAMOCSFAdapter",
    "NetworkActivityOCSFAdapter",
    "DiscoveryOCSFAdapter",
    "ApplicationActivityOCSFAdapter",
    "RemediationOCSFAdapter",
    # Universal normalization (CEF/JSON/proprietary -> OCSF)
    "UniversalNormalizer",
    "FieldMappingProfile",
    "FormatDetector",
    "SourceFormat",
    "CEFToOCSFConverter",
    "GenericJSONToOCSFConverter",
    "ingest_to_security_event_dicts",
    "register_profile_globally",
    # Engines
    "ThreatInvestigator",
    "MITREMapper",
    "KillChainBuilder",
    "UEBAEngine",
    "NLQueryEngine",
    "ComplianceEngine",
    "PlaybookEngine",
]
