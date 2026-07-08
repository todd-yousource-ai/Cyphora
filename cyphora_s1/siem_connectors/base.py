"""
Cyphora-S1 — SIEM Connector Base

BUG 1 FIX: Defines the common interface all SIEM platform connectors
implement.  SIEMConnector is the counterpart to the inbound-side
data_collector adapters: it normalises platform-specific alert objects
into Cyphora SecurityEvents.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, AsyncIterator
from acda.models.schemas import SecurityEvent


class SIEMConnector(ABC):
    """
    Abstract SIEM platform connector.

    Subclasses implement:
      poll()            — pull latest unacknowledged alerts
      acknowledge()     — mark an alert as processed in the SIEM
      is_available()    — health-check the SIEM API connection
      normalise()       — convert a raw SIEM alert dict to SecurityEvent
    """

    @abstractmethod
    async def poll(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch the most recent unacknowledged alerts from the SIEM."""
        ...

    @abstractmethod
    async def acknowledge(self, alert_id: str) -> bool:
        """Mark an alert as processed so it is not returned again."""
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Return True if the SIEM API is reachable and credentials are valid."""
        ...

    @abstractmethod
    def normalise(self, raw_alert: Dict[str, Any]) -> SecurityEvent:
        """Convert a raw SIEM alert to a Cyphora SecurityEvent."""
        ...

    async def stream(self, poll_interval_seconds: float = 30.0,
                     limit_per_poll: int = 100) -> AsyncIterator[SecurityEvent]:
        """
        Async generator that continuously polls and yields SecurityEvents.
        Deduplicates via acknowledge() after yielding.
        """
        import asyncio
        import structlog
        log = structlog.get_logger(__name__)
        while True:
            try:
                raw_alerts = await self.poll(limit=limit_per_poll)
                for raw in raw_alerts:
                    event = self.normalise(raw)
                    yield event
                    await self.acknowledge(str(raw.get("id", event.event_id)))
            except Exception as exc:
                log.error("siem_connector_stream_error",
                          connector=type(self).__name__, error=str(exc))
            await asyncio.sleep(poll_interval_seconds)
