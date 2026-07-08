"""
ACDA-SDK — Data Collector

Gathers security telemetry from multiple log sources with configurable
time windows and enrichment.

BUG 3 FIX (Multi-tenancy): _ADAPTER_MAP is now wrapped in a
TenantAdapterRegistry that scopes adapters per tenant_id.  The module-level
_ADAPTER_MAP is preserved as the 'default' tenant for backward compatibility.
DataCollector accepts an optional tenant_id to select the correct adapter set.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import structlog

from acda.models.schemas import CollectedData, SecurityEvent

logger = structlog.get_logger(__name__)

_TIME_WINDOW_PATTERN = re.compile(r"^(\d+)([smhd])$")


def parse_time_window(window: str, default_minutes: int = 30) -> timedelta:
    if not window or not isinstance(window, str):
        logger.warning("invalid_time_window_using_default", value=window,
                       default_minutes=default_minutes)
        return timedelta(minutes=default_minutes)
    match = _TIME_WINDOW_PATTERN.match(window.strip())
    if not match:
        logger.warning("unparseable_time_window_using_default", value=window,
                       expected_format="<int>[s|m|h|d]", default_minutes=default_minutes)
        return timedelta(minutes=default_minutes)
    value, unit = int(match.group(1)), match.group(2)
    return {"s": timedelta(seconds=value), "m": timedelta(minutes=value),
            "h": timedelta(hours=value), "d": timedelta(days=value)}[unit]


# ─────────────────────────────────────────────
# Source Adapters (Simulated defaults)
# ─────────────────────────────────────────────

class BaseSourceAdapter:
    async def query(self, event: SecurityEvent, since: datetime,
                    until: datetime, max_records: int = 10_000) -> List[Dict[str, Any]]:
        raise NotImplementedError


class SimulatedEndpointLogsAdapter(BaseSourceAdapter):
    async def query(self, event, since, until, max_records=1000):
        await asyncio.sleep(0.02)
        return [{"source": "endpoint_logs",
                 "timestamp": (since + timedelta(minutes=i)).isoformat(),
                 "host": event.source_host or "WORKSTATION-001",
                 "event_type": event.event_type,
                 "process": event.process or "explorer.exe",
                 "user": event.user or "DOMAIN\\user01",
                 "severity": event.severity,
                 "details": f"Log entry {i} for event {event.event_id}"}
                for i in range(random.randint(5, 25))][:max_records]


class SimulatedNetworkLogsAdapter(BaseSourceAdapter):
    async def query(self, event, since, until, max_records=1000):
        await asyncio.sleep(0.02)
        return [{"source": "network_logs",
                 "timestamp": (since + timedelta(minutes=i * 2)).isoformat(),
                 "src_ip": event.source_ip or "192.168.1.100",
                 "dst_ip": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                 "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                 "port": random.choice([80, 443, 445, 3389, 22, 8080]),
                 "bytes_sent": random.randint(100, 50000),
                 "action": random.choice(["allow", "allow", "allow", "block"])}
                for i in range(random.randint(3, 15))][:max_records]


class SimulatedIdentityLogsAdapter(BaseSourceAdapter):
    async def query(self, event, since, until, max_records=1000):
        await asyncio.sleep(0.01)
        return [{"source": "identity_logs",
                 "timestamp": (since + timedelta(minutes=i * 5)).isoformat(),
                 "user": event.user or "DOMAIN\\user01",
                 "action": random.choice(["login_success", "login_failure",
                                          "mfa_bypass_attempt", "privilege_use",
                                          "password_change", "token_issued"]),
                 "ip": event.source_ip or "192.168.1.100",
                 "application": random.choice(["VPN", "Office365", "Salesforce", "SSH"])}
                for i in range(random.randint(2, 10))][:max_records]


class SimulatedFileActivityAdapter(BaseSourceAdapter):
    async def query(self, event, since, until, max_records=1000):
        await asyncio.sleep(0.02)
        return [{"source": "file_activity_logs",
                 "timestamp": (since + timedelta(seconds=i * 30)).isoformat(),
                 "host": event.source_host or "WORKSTATION-001",
                 "user": event.user or "DOMAIN\\user01",
                 "action": random.choice(["read", "write", "delete", "rename", "encrypt", "copy"]),
                 "path": f"C:\\Users\\Documents\\file_{i}.docx",
                 "size_bytes": random.randint(1024, 5_000_000)}
                for i in range(random.randint(1, 20))][:max_records]


class SimulatedThreatIntelAdapter(BaseSourceAdapter):
    async def query(self, event, since, until, max_records=100):
        await asyncio.sleep(0.03)
        if event.source_ip and random.random() > 0.6:
            return [{"source": "threat_intel", "indicator": event.source_ip,
                     "type": "ip", "severity": "high",
                     "tags": ["known_bad_actor", "c2_server"],
                     "confidence": 0.9, "feed": "AlienVault OTX"}]
        return []


# ─────────────────────────────────────────────
# BUG 3 FIX: TenantAdapterRegistry
# ─────────────────────────────────────────────

_DEFAULT_TENANT = "__default__"

# Legacy module-level map preserved for backward compatibility
_ADAPTER_MAP: Dict[str, BaseSourceAdapter] = {
    "endpoint_logs":     SimulatedEndpointLogsAdapter(),
    "network_logs":      SimulatedNetworkLogsAdapter(),
    "identity_logs":     SimulatedIdentityLogsAdapter(),
    "file_activity_logs":SimulatedFileActivityAdapter(),
    "cloud_logs":        SimulatedNetworkLogsAdapter(),
    "threat_intel":      SimulatedThreatIntelAdapter(),
}


class TenantAdapterRegistry:
    """
    Per-tenant adapter registry.  Each tenant gets its own isolated set
    of source adapters with its own credentials and configuration.

    BUG 3 FIX: Previously a single global _ADAPTER_MAP meant that
    registering adapters for one tenant would overwrite another tenant's
    adapters.  This registry scopes adapter instances by tenant_id so
    multi-tenant deployments are fully isolated.

    Usage:
        registry = TenantAdapterRegistry()
        registry.register("tenant_acme", "crowdstrike", CrowdStrikeAdapter(...))
        adapter = registry.get("tenant_acme", "crowdstrike")
    """

    def __init__(self) -> None:
        # tenant_id → source_name → adapter
        self._registry: Dict[str, Dict[str, BaseSourceAdapter]] = {
            _DEFAULT_TENANT: dict(_ADAPTER_MAP)   # seed defaults
        }

    def register(self, tenant_id: str, source: str, adapter: BaseSourceAdapter) -> None:
        """Register an adapter for a specific tenant and source."""
        if tenant_id not in self._registry:
            # New tenant inherits defaults so existing sources still work
            self._registry[tenant_id] = dict(_ADAPTER_MAP)
        self._registry[tenant_id][source] = adapter
        logger.info("tenant_adapter_registered", tenant_id=tenant_id, source=source,
                    adapter_class=type(adapter).__name__)

    def get(self, source: str, tenant_id: Optional[str] = None) -> Optional[BaseSourceAdapter]:
        """Retrieve the adapter for this tenant and source, falling back to defaults."""
        tid = tenant_id or _DEFAULT_TENANT
        tenant_map = self._registry.get(tid, self._registry.get(_DEFAULT_TENANT, {}))
        adapter = tenant_map.get(source)
        if adapter is None:
            # Fall back to the live global default map.  The default-tenant
            # map was seeded with a snapshot of _ADAPTER_MAP at construction
            # time, but registration helpers (register_all_adapters /
            # register_simulated_adapters) mutate _ADAPTER_MAP afterwards.
            # Without this fallback those late-registered product adapters
            # (aws_cloudtrail, azure_ad, okta, crowdstrike, ...) are invisible
            # and every query logs unknown_data_source.
            adapter = _ADAPTER_MAP.get(source)
        return adapter

    def register_defaults(self, adapters: Dict[str, BaseSourceAdapter]) -> None:
        """Update the default adapters used by tenants that have no override."""
        self._registry[_DEFAULT_TENANT].update(adapters)
        # Also update existing tenant maps that still carry the old default
        for tid, tmap in self._registry.items():
            if tid == _DEFAULT_TENANT:
                continue
            for source, adapter in adapters.items():
                if source not in tmap or isinstance(tmap[source], (
                    SimulatedEndpointLogsAdapter, SimulatedNetworkLogsAdapter,
                    SimulatedIdentityLogsAdapter, SimulatedFileActivityAdapter,
                )):
                    tmap[source] = adapter

    def list_tenants(self) -> List[str]:
        return [t for t in self._registry if t != _DEFAULT_TENANT]

    def tenant_sources(self, tenant_id: str) -> List[str]:
        return list(self._registry.get(tenant_id, self._registry[_DEFAULT_TENANT]).keys())


# Module-level registry singleton
_TENANT_REGISTRY = TenantAdapterRegistry()


# ─────────────────────────────────────────────
# Data Collector
# ─────────────────────────────────────────────

class DataCollector:
    """
    Fetches telemetry from all configured sources concurrently.

    BUG 3 FIX: Accepts optional tenant_id parameter.  When provided,
    uses the TenantAdapterRegistry to select tenant-specific adapters
    rather than the global _ADAPTER_MAP.
    """

    def __init__(
        self,
        sources: List[str],
        time_window: str = "30m",
        max_records: int = 10_000,
        enrich_with_threat_intel: bool = True,
        tenant_id: Optional[str] = None,
    ) -> None:
        self.sources                = sources or ["endpoint_logs"]
        self.time_window            = time_window
        self.max_records            = max_records
        self.enrich_with_threat_intel = enrich_with_threat_intel
        self.tenant_id              = tenant_id   # BUG 3 FIX

    async def collect(self, event: SecurityEvent) -> CollectedData:
        now = datetime.now(tz=timezone.utc)
        window_delta = parse_time_window(self.time_window)
        since = now - window_delta

        logger.info("data_collection_start", sources=self.sources,
                    time_window=self.time_window, since=since.isoformat(),
                    tenant_id=self.tenant_id)   # BUG 3 FIX: log tenant

        query_sources = list(self.sources)
        if self.enrich_with_threat_intel and "threat_intel" not in query_sources:
            query_sources.append("threat_intel")

        tasks = {source: self._query_source(source, event, since, now)
                 for source in query_sources}

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        source_results: Dict[str, List[Dict]] = {}
        for source, result in zip(tasks.keys(), results):
            if isinstance(result, BaseException):
                logger.warning("source_query_failed", source=source, error=str(result))
                source_results[source] = []
            else:
                source_results[source] = self._normalize_records(source, result)

        all_logs: List[Dict] = []
        threat_intel: List[Dict] = []
        for source, records in source_results.items():
            if source == "threat_intel":
                threat_intel.extend(records)
            else:
                all_logs.extend(records)

        logger.info("data_collection_complete", total_logs=len(all_logs),
                    threat_intel_hits=len(threat_intel), tenant_id=self.tenant_id)
        return CollectedData(event=event, logs=all_logs, threat_intel=threat_intel)

    async def _query_source(self, source, event, since, until):
        # BUG 3 FIX: use registry with tenant_id instead of global map
        adapter = _TENANT_REGISTRY.get(source, self.tenant_id)
        if adapter is None:
            logger.warning("unknown_data_source", source=source, tenant_id=self.tenant_id)
            return []
        try:
            return await adapter.query(event, since, until, self.max_records)
        except Exception as exc:
            logger.error("source_adapter_error", source=source, error=str(exc))
            return []

    def _normalize_records(self, source, result):
        if not isinstance(result, list):
            logger.warning("source_query_invalid_shape", source=source,
                           result_type=type(result).__name__)
            return []
        return [r for r in result if isinstance(r, dict)]
