"""
Cyphora-S1 — Natural Language Query Interface
==============================================
Allows SOC analysts (and non-technical users) to ask plain-English
questions about their security environment — no query language required.

"Show me every privileged account that touched production S3 buckets
 after 10pm in the last 7 days."

The NLQueryEngine translates this into structured query parameters,
dispatches the query to the DataCollector, and formats the results
into a human-readable response.

Key components
──────────────
  QueryIntent      – Parsed representation of what the user is asking
  NLParser         – Uses Claude/GPT to extract structured intent from text
  QueryExecutor    – Translates intent into DataCollector parameters + runs it
  ResultFormatter  – Formats raw results into readable markdown tables
  NLQueryEngine    – Orchestrates the full pipeline
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog

from acda.models.schemas import CollectedData, SecurityEvent
from acda.runtime.data_collector import DataCollector

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Query Intent Data Model
# ─────────────────────────────────────────────────────────────


@dataclass
class QueryFilter:
    field: str
    operator: str  # eq, contains, gt, lt, in
    value: Any


@dataclass
class QueryIntent:
    """
    Structured representation of a natural language security query.
    Extracted by the NLParser from free-form text.
    """

    # What data to retrieve
    data_sources: List[str] = field(
        default_factory=lambda: ["endpoint_logs", "identity_logs"]
    )
    time_window: str = "24h"

    # Entity filters
    user_filter: Optional[str] = None
    host_filter: Optional[str] = None
    ip_filter: Optional[str] = None
    process_filter: Optional[str] = None
    action_filter: Optional[str] = None  # e.g. "login", "file_write", "privilege_use"

    # Conditions
    after_hour: Optional[int] = None  # 0–23, only events after this hour
    before_hour: Optional[int] = None  # 0–23, only events before this hour
    min_severity: Optional[str] = None
    requires_privilege: Optional[bool] = None
    application_filter: Optional[str] = None

    # Output preferences
    max_results: int = 100
    sort_by: str = "timestamp"
    sort_order: str = "desc"
    output_format: str = "table"  # table | json | summary

    # Original query preserved for context
    original_query: str = ""
    confidence: float = 0.0
    explanation: str = ""


# ─────────────────────────────────────────────────────────────
# NL Parser (LLM-powered intent extraction)
# ─────────────────────────────────────────────────────────────

PARSE_SYSTEM_PROMPT = """
You are Cyphora-S1's security query parser. Convert natural language security
questions into structured JSON query parameters.

Available data sources: endpoint_logs, network_logs, identity_logs,
file_activity_logs, cloud_logs, threat_intel, aws_cloudtrail, azure_ad,
okta, crowdstrike, palo_alto, github_audit, gcp_audit

Time window format: 30m, 1h, 24h, 7d, 30d

Respond ONLY with valid JSON matching this schema:
{
  "data_sources": ["source1", "source2"],
  "time_window": "24h",
  "user_filter": "username or null",
  "host_filter": "hostname or null",
  "ip_filter": "ip address or null",
  "process_filter": "process name or null",
  "action_filter": "action keyword or null",
  "after_hour": 22,
  "before_hour": null,
  "min_severity": "medium or null",
  "requires_privilege": true or null,
  "application_filter": "app name or null",
  "max_results": 100,
  "sort_by": "timestamp",
  "sort_order": "desc",
  "output_format": "table",
  "confidence": 0.95,
  "explanation": "What I understood from the query"
}
"""


class NLParser:
    """
    Parses natural language security queries into structured QueryIntent objects.
    Uses Claude (preferred) or GPT-4o. Falls back to regex heuristics if LLM
    is unavailable.
    """

    def __init__(
        self,
        model_id: str = "claude-sonnet-4-6",
        api_key: Optional[str] = None,
    ) -> None:
        self._model_id = model_id
        self._api_key = api_key

    async def parse(self, query_text: str) -> QueryIntent:
        """Parse a natural language query into a structured QueryIntent."""
        try:
            if self._model_id.startswith("claude-"):
                raw = await self._call_anthropic(query_text)
            elif self._model_id.startswith("gpt-"):
                raw = await self._call_openai(query_text)
            else:
                return self._regex_fallback(query_text)

            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError(
                    f"Expected JSON object from NL parser, got {type(data).__name__}"
                )
            intent = QueryIntent(
                data_sources=data.get("data_sources", ["identity_logs"]),
                time_window=data.get("time_window", "24h"),
                user_filter=data.get("user_filter"),
                host_filter=data.get("host_filter"),
                ip_filter=data.get("ip_filter"),
                process_filter=data.get("process_filter"),
                action_filter=data.get("action_filter"),
                after_hour=data.get("after_hour"),
                before_hour=data.get("before_hour"),
                min_severity=data.get("min_severity"),
                requires_privilege=data.get("requires_privilege"),
                application_filter=data.get("application_filter"),
                max_results=int(data.get("max_results", 100)),
                sort_by=data.get("sort_by", "timestamp"),
                sort_order=data.get("sort_order", "desc"),
                output_format=data.get("output_format", "table"),
                original_query=query_text,
                confidence=float(data.get("confidence", 0.8)),
                explanation=data.get("explanation", ""),
            )
            logger.info("nl_query_parsed", confidence=intent.confidence)
            return intent

        except (json.JSONDecodeError, Exception) as exc:
            logger.warning("nl_parse_failed_using_heuristics", error=str(exc))
            return self._regex_fallback(query_text)

    async def _call_anthropic(self, query: str) -> str:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self._api_key)
        response = await client.messages.create(
            model=self._model_id,
            max_tokens=1024,
            system=PARSE_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Parse this security query: {query}"}
            ],
        )
        return response.content[0].text if response.content else "{}"

    async def _call_openai(self, query: str) -> str:
        import openai

        client = openai.AsyncOpenAI(api_key=self._api_key)
        response = await client.chat.completions.create(
            model=self._model_id,
            messages=[
                {"role": "system", "content": PARSE_SYSTEM_PROMPT},
                {"role": "user", "content": f"Parse this security query: {query}"},
            ],
            response_format={"type": "json_object"},
            max_tokens=1024,
        )
        return response.choices[0].message.content or "{}"

    def _regex_fallback(self, query: str) -> QueryIntent:
        """
        Regex-based heuristic parser for when LLM is unavailable.
        Handles common patterns without requiring API access.
        """
        ql = query.lower()
        intent = QueryIntent(original_query=query, confidence=0.5)

        # Detect time windows
        time_patterns = [
            (r"\blast\s+(\d+)\s+day", lambda m: f"{m.group(1)}d"),
            (r"\blast\s+(\d+)\s+hour", lambda m: f"{m.group(1)}h"),
            (r"\blast\s+24\s+hour|yesterday", lambda _: "24h"),
            (r"\blast\s+week", lambda _: "7d"),
            (r"\blast\s+month", lambda _: "30d"),
        ]
        for pattern, formatter in time_patterns:
            match = re.search(pattern, ql)
            if match:
                intent.time_window = formatter(match)
                break

        # Detect after-hours queries
        after_match = re.search(r"after\s+(\d{1,2})\s*(?:pm|:00)", ql)
        if after_match:
            hour = int(after_match.group(1))
            if "pm" in ql[after_match.start() : after_match.end() + 3] and hour < 12:
                hour += 12
            intent.after_hour = hour

        # Detect user references
        user_match = re.search(r"user\s+([a-z0-9._@-]+)", ql)
        if user_match:
            intent.user_filter = user_match.group(1)

        # Detect privilege queries
        if any(kw in ql for kw in ["privilege", "admin", "sudo", "elevated", "root"]):
            intent.requires_privilege = True
            intent.data_sources = ["identity_logs", "endpoint_logs"]

        # Detect source types
        if any(kw in ql for kw in ["login", "sign", "auth", "mfa"]):
            intent.data_sources = ["identity_logs"]
        elif any(kw in ql for kw in ["file", "encrypt", "write", "document"]):
            intent.data_sources = ["file_activity_logs"]
        elif any(kw in ql for kw in ["network", "traffic", "connection", "dns"]):
            intent.data_sources = ["network_logs"]
        elif any(kw in ql for kw in ["aws", "s3", "cloudtrail", "lambda"]):
            intent.data_sources = ["aws_cloudtrail"]
        elif any(kw in ql for kw in ["okta", "sso"]):
            intent.data_sources = ["okta"]

        # Detect S3 / cloud resource references
        if "s3" in ql or "bucket" in ql:
            intent.data_sources = ["aws_cloudtrail"]
            intent.application_filter = "S3"

        # Detect severity
        for sev in ["critical", "high", "medium", "low"]:
            if sev in ql:
                intent.min_severity = sev
                break

        intent.explanation = f"Heuristic parse of: {query[:100]}"
        return intent


# ─────────────────────────────────────────────────────────────
# Query Executor
# ─────────────────────────────────────────────────────────────


class QueryExecutor:
    """
    Translates a QueryIntent into DataCollector calls and applies filters
    to the raw results.
    """

    async def execute(self, intent: QueryIntent) -> CollectedData:
        """Run the query against available data sources."""

        # Build a synthetic event to drive the DataCollector
        event = SecurityEvent(
            event_id=f"NLQ-{datetime.now(tz=timezone.utc).strftime('%Y%m%d%H%M%S')}",
            event_type="nl_query",
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            source_host=intent.host_filter,
            source_ip=intent.ip_filter,
            user=intent.user_filter,
            process=intent.process_filter,
            severity=intent.min_severity or "info",
        )

        collector = DataCollector(
            sources=intent.data_sources,
            time_window=intent.time_window,
            max_records=intent.max_results * 2,  # collect extra, then filter
            enrich_with_threat_intel=False,
        )
        data = await collector.collect(event)

        # Apply post-collection filters
        filtered_logs = self._filter_logs(data.logs, intent)
        data.logs = filtered_logs[: intent.max_results]
        return data

    def _filter_logs(
        self,
        logs: List[Dict[str, Any]],
        intent: QueryIntent,
    ) -> List[Dict[str, Any]]:
        """Apply client-side filters that couldn't be expressed in source queries."""
        result = []
        for log in logs:
            if not self._passes_filters(log, intent):
                continue
            result.append(log)
        return result

    def _passes_filters(self, log: Dict[str, Any], intent: QueryIntent) -> bool:
        # After-hour filter
        if intent.after_hour is not None:
            ts = (
                log.get("timestamp")
                or log.get("@timestamp")
                or log.get("createdDateTime")
            )
            if ts:
                try:
                    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                    if dt.hour < intent.after_hour:
                        return False
                except (ValueError, TypeError):
                    pass

        # Before-hour filter
        if intent.before_hour is not None:
            ts = log.get("timestamp") or log.get("@timestamp")
            if ts:
                try:
                    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                    if dt.hour >= intent.before_hour:
                        return False
                except (ValueError, TypeError):
                    pass

        # Action / keyword filter
        if intent.action_filter:
            log_text = json.dumps(log, default=str).lower()
            if intent.action_filter.lower() not in log_text:
                return False

        # Application filter
        if intent.application_filter:
            app = str(log.get("application", "") or log.get("eventSource", "")).lower()
            if intent.application_filter.lower() not in app:
                return False

        # Privilege filter
        if intent.requires_privilege is True:
            action = str(log.get("action", "")).lower()
            if not any(
                kw in action
                for kw in ["privilege", "admin", "sudo", "escalat", "elevat"]
            ):
                return False

        return True


# ─────────────────────────────────────────────────────────────
# Result Formatter
# ─────────────────────────────────────────────────────────────


class ResultFormatter:
    """Formats DataCollector results into human-readable output."""

    def format(
        self,
        data: CollectedData,
        intent: QueryIntent,
    ) -> str:
        """Format query results based on requested output format."""
        if intent.output_format == "json":
            return json.dumps(
                [log for log in data.logs],
                indent=2,
                default=str,
            )
        elif intent.output_format == "summary":
            return self._summary_format(data, intent)
        else:
            return self._table_format(data, intent)

    def _table_format(self, data: CollectedData, intent: QueryIntent) -> str:
        """Format results as a markdown table."""
        if not data.logs:
            return f"**No results found** for query: _{intent.original_query}_\n\nQuery interpreted as: {intent.explanation}"

        # Determine columns from first record
        first = data.logs[0]
        # Pick the most relevant columns
        priority_cols = [
            "timestamp",
            "@timestamp",
            "createdDateTime",
            "user",
            "action",
            "ip",
            "sourceIPAddress",
            "host",
            "application",
            "eventName",
            "process",
            "severity",
            "bytes_sent",
            "source",
        ]
        cols = [c for c in priority_cols if c in first]
        if not cols:
            cols = list(first.keys())[:6]

        # Header
        header = "| " + " | ".join(cols) + " |"
        separator = "| " + " | ".join(["---"] * len(cols)) + " |"
        rows = [header, separator]

        for log in data.logs[:50]:  # cap table rows
            row_vals = []
            for col in cols:
                val = str(log.get(col, ""))[:40]  # truncate long values
                row_vals.append(val)
            rows.append("| " + " | ".join(row_vals) + " |")

        if len(data.logs) > 50:
            rows.append(f"\n_...and {len(data.logs) - 50} more results._")

        summary = (
            f"**{len(data.logs)} result(s)** for: _{intent.original_query}_\n"
            f"Sources: {', '.join(intent.data_sources)} | "
            f"Time window: {intent.time_window} | "
            f"Parse confidence: {intent.confidence:.0%}\n\n"
        )
        return summary + "\n".join(rows)

    def _summary_format(self, data: CollectedData, intent: QueryIntent) -> str:
        """Produce a narrative summary of the query results."""
        count = len(data.logs)
        sources = ", ".join(intent.data_sources)
        users = list({log.get("user", "") for log in data.logs if log.get("user")})[:5]
        hosts = list({log.get("host", "") for log in data.logs if log.get("host")})[:5]

        return (
            f"## Query Results Summary\n\n"
            f"**Query:** {intent.original_query}\n"
            f"**Interpreted as:** {intent.explanation}\n\n"
            f"- **{count} events** found across {sources}\n"
            f"- **Time window:** {intent.time_window}\n"
            + (f"- **Users involved:** {', '.join(users)}\n" if users else "")
            + (f"- **Hosts involved:** {', '.join(hosts)}\n" if hosts else "")
            + f"\n_Parse confidence: {intent.confidence:.0%}_"
        )


# ─────────────────────────────────────────────────────────────
# NL Query Engine — Top-Level Interface
# ─────────────────────────────────────────────────────────────


@dataclass
class NLQueryResult:
    query: str
    intent: QueryIntent
    data: CollectedData
    formatted_output: str
    record_count: int
    execution_time_ms: float


class NLQueryEngine:
    """
    Cyphora-S1 Natural Language Query Interface.

    Translates plain-English questions into security data queries
    and returns formatted, human-readable results.

    Usage
    -----
        engine = NLQueryEngine(llm_model="claude-sonnet-4-6")
        result = await engine.query(
            "Show me every privileged user who accessed S3 after 10pm last week"
        )
        print(result.formatted_output)
    """

    def __init__(
        self,
        llm_model: str = "claude-sonnet-4-6",
        llm_api_key: Optional[str] = None,
    ) -> None:
        self._parser = NLParser(model_id=llm_model, api_key=llm_api_key)
        self._executor = QueryExecutor()
        self._formatter = ResultFormatter()

    async def query(self, query_text: str) -> NLQueryResult:
        """
        Execute a natural language security query.

        Parameters
        ----------
        query_text : str
            Plain-English security question, e.g.:
            "Show me all logins from new IP addresses in the last 24 hours"

        Returns
        -------
        NLQueryResult with formatted output ready to display.
        """
        import time

        start = time.perf_counter()

        logger.info("nl_query_received", query=query_text[:100])

        # 1. Parse intent
        intent = await self._parser.parse(query_text)

        # 2. Execute query
        data = await self._executor.execute(intent)

        # 3. Format results
        formatted = self._formatter.format(data, intent)

        elapsed_ms = (time.perf_counter() - start) * 1000

        logger.info(
            "nl_query_complete",
            records=len(data.logs),
            elapsed_ms=round(elapsed_ms, 1),
        )

        return NLQueryResult(
            query=query_text,
            intent=intent,
            data=data,
            formatted_output=formatted,
            record_count=len(data.logs),
            execution_time_ms=elapsed_ms,
        )

    async def interactive_session(self) -> None:
        """
        Run an interactive query session in the terminal.
        Useful for development, POC demos, and SOC analyst exploration.

        Example output:
            Cyphora-S1 > show me failed logins from external IPs last 6 hours
            > Parsing query... [0.3s]
            > Fetching from: identity_logs (6h window)
            > 47 results found
            [formatted table output]
        """
        print("\n🔷 Cyphora-S1 Natural Language Query Interface")
        print("   Type a security question in plain English. Type 'exit' to quit.\n")

        while True:
            try:
                query_text = input("Cyphora-S1 > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nSession ended.")
                break

            if not query_text:
                continue
            if query_text.lower() in ("exit", "quit", "q"):
                print("Session ended.")
                break

            result = await self.query(query_text)
            print(f"\n{result.formatted_output}")
            print(
                f"\n[{result.record_count} results in {result.execution_time_ms:.0f}ms]\n"
            )
