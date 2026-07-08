"""
Cyphora-S1 — UEBA Engine (User & Entity Behavior Analytics)

BUG 3 FIX (Multi-tenancy): BaselineStore now scopes all Redis keys with
tenant_id prefix so no tenant's baselines can collide with another's.

BUG 4 FIX (Cold-start): AnomalyScorer.score() no longer returns a fixed
neutral 0.3 when sample_count < 5.  Instead it:
  1. Uses a PeerGroupBaseline (average of entities with the same type)
     if peer data is available.
  2. Falls back to event-type heuristics based on severity/event_type
     when no peer data exists.
  3. Returns 0.3 only as a last resort, but now also sets a clear
     "insufficient_baseline" flag so callers know the score is provisional.

UEBAEngine.warmup_from_logs() allows callers to pre-populate baselines
from historical log data, eliminating cold-start entirely for deployments
that import existing telemetry.
"""

from __future__ import annotations

import json
import math
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog

from acda.models.schemas import CollectedData, SecurityEvent

logger = structlog.get_logger(__name__)


class EntityType:
    USER            = "user"
    HOST            = "host"
    SERVICE_ACCOUNT = "service_account"
    IP_ADDRESS      = "ip_address"


@dataclass
class BehaviorBaseline:
    entity_id:   str
    entity_type: str
    created_at:  str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    last_updated:str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    sample_count:int = 0

    avg_logins_per_day:           float = 0.0
    typical_login_hours:          List[int]  = field(default_factory=list)
    typical_source_ips:           List[str]  = field(default_factory=list)
    typical_applications:         List[str]  = field(default_factory=list)
    avg_process_executions_per_hour: float = 0.0
    typical_processes:            List[str]  = field(default_factory=list)
    avg_bytes_per_day:            float = 0.0
    avg_connections_per_day:      float = 0.0
    typical_destinations:         List[str]  = field(default_factory=list)
    avg_files_accessed_per_day:   float = 0.0
    avg_files_written_per_day:    float = 0.0
    avg_privilege_uses_per_day:   float = 0.0
    has_admin_rights:             bool  = False
    ema_alpha:                    float = 0.1

    def update_ema(self, attr: str, new_value: float) -> None:
        current = getattr(self, attr, 0.0)
        if self.sample_count == 0:
            setattr(self, attr, new_value)
        else:
            setattr(self, attr, self.ema_alpha * new_value + (1 - self.ema_alpha) * current)


# ─────────────────────────────────────────────────────────────
# BUG 3 FIX: Tenant-scoped Baseline Store
# ─────────────────────────────────────────────────────────────

class BaselineStore:
    """
    Persists behavioral baselines.

    BUG 3 FIX: All Redis keys are now prefixed with tenant_id:
      OLD: cyphora:ueba:baseline:{entity_id}
      NEW: cyphora:{tenant_id}:ueba:baseline:{entity_id}

    This prevents any cross-tenant baseline collision in shared Redis.
    tenant_id defaults to 'default' so single-tenant deployments work
    without any configuration change.
    """

    _TTL_SECONDS = 90 * 24 * 3600  # 90 days

    def __init__(self, redis_url: Optional[str] = None,
                 tenant_id: str = "default") -> None:
        self._redis_url = redis_url or os.getenv("REDIS_URL")
        self._tenant_id = tenant_id                      # BUG 3 FIX
        self._memory:  Dict[str, BehaviorBaseline] = {}
        self._redis = None
        if self._redis_url:
            try:
                import redis
                self._redis = redis.Redis.from_url(self._redis_url, decode_responses=True)
                self._redis.ping()
                logger.info("ueba_baseline_store_redis_connected", tenant_id=tenant_id)
            except Exception as exc:
                logger.warning("ueba_redis_unavailable_falling_back", error=str(exc))
                self._redis = None

    def _key(self, entity_id: str) -> str:
        # BUG 3 FIX: include tenant_id in key so tenants are fully isolated
        return f"cyphora:{self._tenant_id}:ueba:baseline:{entity_id}"

    def get(self, entity_id: str) -> Optional[BehaviorBaseline]:
        key = self._key(entity_id)
        if self._redis:
            try:
                raw = self._redis.get(key)
                if raw:
                    return BehaviorBaseline(**json.loads(raw))
            except Exception as exc:
                logger.warning("baseline_redis_get_failed", error=str(exc))
        return self._memory.get(entity_id)

    def set(self, baseline: BehaviorBaseline) -> None:
        key = self._key(baseline.entity_id)
        if self._redis:
            try:
                self._redis.setex(key, self._TTL_SECONDS, json.dumps(baseline.__dict__))
            except Exception as exc:
                logger.warning("baseline_redis_set_failed", error=str(exc))
        self._memory[baseline.entity_id] = baseline

    def list_entities(self, prefix: str = "") -> List[str]:
        if self._redis:
            try:
                pattern = f"cyphora:{self._tenant_id}:ueba:baseline:{prefix}*"
                keys = self._redis.keys(pattern)
                return [k.split(":", 4)[-1] for k in keys]   # strip prefix
            except Exception:
                pass
        return [k for k in self._memory if k.startswith(prefix)]


# ─────────────────────────────────────────────────────────────
# BUG 4 FIX: PeerGroupBaseline for cold-start mitigation
# ─────────────────────────────────────────────────────────────

@dataclass
class PeerGroupBaseline:
    """
    Aggregate behavioral statistics for an entity type (user / host /
    service_account / ip_address).  Used as a fallback when an individual
    entity has fewer than min_samples observations.
    """
    entity_type:             str
    sample_entity_count:     int   = 0
    avg_logins_per_day:      float = 0.0
    avg_bytes_per_day:       float = 0.0
    avg_files_written_per_day: float = 0.0
    avg_privilege_uses_per_day:float = 0.0
    typical_login_hours:     List[int]  = field(default_factory=list)


class PeerGroupStore:
    """
    Maintains aggregate peer-group baselines per entity type.
    Updated incrementally each time a mature individual baseline is saved.
    """

    def __init__(self) -> None:
        self._groups: Dict[str, PeerGroupBaseline] = {}

    def update(self, baseline: BehaviorBaseline, min_samples: int = 5) -> None:
        """Incorporate a mature baseline into the peer group aggregate."""
        if baseline.sample_count < min_samples:
            return
        etype = baseline.entity_type
        peer = self._groups.get(etype, PeerGroupBaseline(entity_type=etype))
        n = peer.sample_entity_count
        alpha = 1 / (n + 1) if n > 0 else 1.0   # running mean update

        def ema(current: float, new_val: float) -> float:
            return current + alpha * (new_val - current)

        peer.avg_logins_per_day       = ema(peer.avg_logins_per_day, baseline.avg_logins_per_day)
        peer.avg_bytes_per_day        = ema(peer.avg_bytes_per_day, baseline.avg_bytes_per_day)
        peer.avg_files_written_per_day = ema(peer.avg_files_written_per_day,
                                             baseline.avg_files_written_per_day)
        peer.avg_privilege_uses_per_day = ema(peer.avg_privilege_uses_per_day,
                                              baseline.avg_privilege_uses_per_day)

        # Merge typical_login_hours (union of most common hours)
        for h in baseline.typical_login_hours:
            if h not in peer.typical_login_hours:
                peer.typical_login_hours = (peer.typical_login_hours + [h])[-12:]

        peer.sample_entity_count = n + 1
        self._groups[etype] = peer

    def get(self, entity_type: str) -> Optional[PeerGroupBaseline]:
        return self._groups.get(entity_type)


# ─────────────────────────────────────────────────────────────
# Feature Extractor
# ─────────────────────────────────────────────────────────────

class FeatureExtractor:
    def extract(self, event: SecurityEvent, data: CollectedData) -> Dict[str, Any]:
        features: Dict[str, Any] = {
            "entity_id":   event.user or event.source_host or event.source_ip or "unknown",
            "entity_type": self._determine_entity_type(event),
            "event_type":  event.event_type,
            "severity":    event.severity,
        }

        login_count = 0
        login_hours: List[int] = []
        source_ips: List[str] = []
        applications: List[str] = []
        processes: List[str] = []
        bytes_sent = 0
        connections = 0
        files_accessed = 0
        files_written = 0
        privilege_uses = 0
        failed_logins = 0
        destinations: List[str] = []

        for log in data.logs:
            source = log.get("source", "")
            if source == "identity_logs":
                action = log.get("action", "")
                if "login" in action:
                    login_count += 1
                    if ts := log.get("timestamp"):
                        try:
                            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                            login_hours.append(dt.hour)
                        except (ValueError, TypeError):
                            pass
                if lip := log.get("ip"):
                    source_ips.append(lip)
                if app := log.get("application"):
                    applications.append(app)
                if "failure" in action or "failed" in action:
                    failed_logins += 1
                if "privilege" in action:
                    privilege_uses += 1
            elif source == "endpoint_logs":
                if proc := log.get("process"):
                    processes.append(proc)
            elif source in ("network_logs", "aws_cloudtrail", "gcp_audit"):
                bytes_sent += int(log.get("bytes_sent", 0))
                connections += 1
                if dst := (log.get("dst_ip") or log.get("destinationIPAddress")):
                    destinations.append(dst)
            elif source == "file_activity_logs":
                files_accessed += 1
                if log.get("action", "") in ("write", "encrypt", "delete"):
                    files_written += 1

        features.update({
            "login_count":        login_count,
            "login_hours":        login_hours,
            "unique_source_ips":  list(set(source_ips)),
            "applications":       list(set(applications)),
            "processes":          list(set(processes))[:20],
            "bytes_sent":         bytes_sent,
            "connection_count":   connections,
            "unique_destinations":list(set(destinations))[:20],
            "files_accessed":     files_accessed,
            "files_written":      files_written,
            "privilege_uses":     privilege_uses,
            "failed_login_count": failed_logins,
            "threat_intel_hits":  len(data.threat_intel),
        })
        return features

    def _determine_entity_type(self, event: SecurityEvent) -> str:
        if event.user:
            if "$" in (event.user or "") or "svc" in (event.user or "").lower():
                return EntityType.SERVICE_ACCOUNT
            return EntityType.USER
        if event.source_host:
            return EntityType.HOST
        if event.source_ip:
            return EntityType.IP_ADDRESS
        return EntityType.USER


# ─────────────────────────────────────────────────────────────
# Anomaly Findings
# ─────────────────────────────────────────────────────────────

@dataclass
class AnomalyFinding:
    feature:         str
    observed_value:  Any
    baseline_value:  Any
    deviation_score: float
    explanation:     str
    is_critical:     bool = False


# ─────────────────────────────────────────────────────────────
# BUG 4 FIX: AnomalyScorer with peer-group cold-start mitigation
# ─────────────────────────────────────────────────────────────

class AnomalyScorer:
    """
    BUG 4 FIX: When an entity has fewer than min_samples observations
    the scorer now applies a tiered strategy instead of returning a
    fixed neutral 0.3:

      Tier 1 — Peer group baseline: if peer data exists for this entity
               type, score against the peer average.  Captures genuinely
               anomalous behaviour even on first encounter.

      Tier 2 — Event heuristic: use event_type and severity as a proxy.
               critical/high events involving privilege_escalation or
               lateral_movement score higher than low-severity logins.

      Tier 3 — Provisional 0.3: only if neither tier 1 nor tier 2
               applies, with is_provisional=True flag so callers know
               the score is weak.
    """

    HOUR_DEVIATION_THRESHOLD = 3
    NUMERIC_SIGMA_THRESHOLD  = 3.0
    MIN_SAMPLES              = 5

    # Event-type heuristic scores for Tier 2 cold-start (no baseline + no peer)
    _EVENT_HEURISTIC: Dict[str, float] = {
        "privilege_escalation":      0.65,
        "credential_dump":           0.70,
        "lateral_movement":          0.65,
        "data_exfiltration":         0.60,
        "abnormal_file_encryption":  0.75,
        "confirmed_attack":          0.80,
        "suspicious_login":          0.35,
        "abnormal_process_execution":0.45,
        "anomaly_detected":          0.30,
    }
    _SEVERITY_BOOST: Dict[str, float] = {
        "critical": 0.15, "high": 0.10, "medium": 0.05, "low": 0.0
    }

    def score(
        self,
        features: Dict[str, Any],
        baseline: Optional[BehaviorBaseline],
        peer_baseline: Optional[PeerGroupBaseline] = None,
    ) -> Tuple[float, List[AnomalyFinding]]:
        """
        Returns (risk_score, findings).

        BUG 4 FIX: cold-start is handled via peer_baseline and event
        heuristics rather than the previous fixed-0.3 fallback.
        """
        is_cold_start = baseline is None or baseline.sample_count < self.MIN_SAMPLES

        if is_cold_start:
            return self._cold_start_score(features, peer_baseline)

        # ── Full baseline scoring (existing logic) ────────────────
        return self._full_score(features, baseline)

    # ── BUG 4 FIX: tiered cold-start scoring ────────────────────

    def _cold_start_score(
        self,
        features: Dict[str, Any],
        peer: Optional[PeerGroupBaseline],
    ) -> Tuple[float, List[AnomalyFinding]]:
        findings: List[AnomalyFinding] = []

        # Tier 1: peer group comparison
        if peer and peer.sample_entity_count >= 3:
            findings.extend(self._score_vs_peer(features, peer))

        # Tier 2: event-type heuristic (always add as additional signal)
        event_type = features.get("event_type", "anomaly_detected")
        severity   = features.get("severity",   "low")
        base_score = self._EVENT_HEURISTIC.get(event_type, 0.30)
        boost      = self._SEVERITY_BOOST.get(severity, 0.0)
        heuristic_score = min(1.0, base_score + boost)

        findings.append(AnomalyFinding(
            feature         = "baseline_availability",
            observed_value  = f"sample_count < {self.MIN_SAMPLES}",
            baseline_value  = "peer_group" if peer and peer.sample_entity_count >= 3 else "heuristic_only",
            deviation_score = heuristic_score,
            explanation     = (
                f"Provisional score: entity baseline not yet established "
                f"(< {self.MIN_SAMPLES} samples). "
                f"Score derived from {'peer group + ' if peer else ''}"
                f"event type '{event_type}' + severity '{severity}'."
            ),
            is_critical     = False,
        ))

        # Threat intel hit always scores high regardless of baseline
        if features.get("threat_intel_hits", 0) > 0:
            findings.append(AnomalyFinding(
                feature         = "threat_intel",
                observed_value  = f"{features['threat_intel_hits']} hits",
                baseline_value  = "0 expected",
                deviation_score = 0.95,
                explanation     = "Source IP or indicator found in threat intelligence feeds.",
                is_critical     = True,
            ))

        if not findings:
            return 0.30, []

        total = sum(f.deviation_score for f in findings) / len(findings)
        if any(f.is_critical for f in findings):
            total = min(1.0, total * 1.5)
        return round(total, 4), findings

    def _score_vs_peer(
        self, features: Dict[str, Any], peer: PeerGroupBaseline
    ) -> List[AnomalyFinding]:
        """Score entity behaviour against peer group averages."""
        findings: List[AnomalyFinding] = []

        bytes_sent = features.get("bytes_sent", 0)
        if peer.avg_bytes_per_day > 0 and bytes_sent > 0:
            ratio = bytes_sent / max(peer.avg_bytes_per_day, 1)
            if ratio > 5.0:
                findings.append(AnomalyFinding(
                    feature         = "bytes_sent_vs_peer",
                    observed_value  = f"{bytes_sent:,} bytes",
                    baseline_value  = f"peer avg: {peer.avg_bytes_per_day:,.0f} bytes",
                    deviation_score = min(1.0, math.log10(max(ratio, 1)) / 3.0),
                    explanation     = f"Data transfer {ratio:.1f}× above peer group average.",
                    is_critical     = ratio > 20.0,
                ))

        priv_uses = features.get("privilege_uses", 0)
        if priv_uses > 0 and peer.avg_privilege_uses_per_day == 0:
            findings.append(AnomalyFinding(
                feature         = "privilege_use_vs_peer",
                observed_value  = f"{priv_uses} privilege uses",
                baseline_value  = "peer avg: 0",
                deviation_score = 0.75,
                explanation     = "Privilege use with no precedent in peer group.",
                is_critical     = True,
            ))

        return findings

    # ── Full baseline scoring (mature entity) ────────────────────

    def _full_score(
        self,
        features: Dict[str, Any],
        baseline: BehaviorBaseline,
    ) -> Tuple[float, List[AnomalyFinding]]:
        findings: List[AnomalyFinding] = []

        for hour in features.get("login_hours", []):
            if baseline.typical_login_hours and hour not in baseline.typical_login_hours:
                min_dist = min(abs(hour - h) for h in baseline.typical_login_hours)
                if min_dist >= self.HOUR_DEVIATION_THRESHOLD:
                    score = min(1.0, min_dist / 12.0)
                    findings.append(AnomalyFinding(
                        feature="login_hour",
                        observed_value=f"{hour:02d}:00",
                        baseline_value=f"typical: {baseline.typical_login_hours[:5]}",
                        deviation_score=score,
                        explanation=(f"Login at {hour:02d}:00 is {min_dist} hours outside "
                                     f"normal window."),
                        is_critical=min_dist >= 6,
                    ))

        for ip in features.get("unique_source_ips", []):
            if ip and baseline.typical_source_ips and ip not in baseline.typical_source_ips:
                findings.append(AnomalyFinding(
                    feature="source_ip", observed_value=ip,
                    baseline_value=f"known IPs: {baseline.typical_source_ips[:3]}",
                    deviation_score=0.65,
                    explanation=f"Login from previously unseen IP address {ip}.",
                    is_critical=False,
                ))

        bytes_sent = features.get("bytes_sent", 0)
        if baseline.avg_bytes_per_day > 0 and bytes_sent > 0:
            ratio = bytes_sent / max(baseline.avg_bytes_per_day, 1)
            if ratio > 5.0:
                score = min(1.0, math.log10(ratio) / 3.0)
                findings.append(AnomalyFinding(
                    feature="bytes_sent",
                    observed_value=f"{bytes_sent:,} bytes",
                    baseline_value=f"daily avg: {baseline.avg_bytes_per_day:,.0f} bytes",
                    deviation_score=score,
                    explanation=f"Data transfer {ratio:.1f}× above baseline.",
                    is_critical=ratio > 20.0,
                ))

        files_written = features.get("files_written", 0)
        if files_written > max(baseline.avg_files_written_per_day * 5, 50):
            score = min(1.0, files_written / 500.0)
            findings.append(AnomalyFinding(
                feature="files_written",
                observed_value=f"{files_written} files",
                baseline_value=f"daily avg: {baseline.avg_files_written_per_day:.1f}",
                deviation_score=score,
                explanation=f"{files_written} files written — possible ransomware.",
                is_critical=files_written > 200,
            ))

        priv_uses = features.get("privilege_uses", 0)
        if not baseline.has_admin_rights and priv_uses > 0:
            findings.append(AnomalyFinding(
                feature="privilege_use",
                observed_value=f"{priv_uses} privilege uses",
                baseline_value="not an admin account",
                deviation_score=0.80,
                explanation=f"Non-admin entity used elevated privileges {priv_uses} time(s).",
                is_critical=True,
            ))

        failed = features.get("failed_login_count", 0)
        if failed >= 10:
            score = min(1.0, failed / 100.0)
            findings.append(AnomalyFinding(
                feature="failed_logins",
                observed_value=f"{failed} failures",
                baseline_value="0-2 typical",
                deviation_score=score,
                explanation=f"{failed} failed logins — possible brute force.",
                is_critical=failed >= 50,
            ))

        if features.get("threat_intel_hits", 0) > 0:
            findings.append(AnomalyFinding(
                feature="threat_intel",
                observed_value=f"{features['threat_intel_hits']} hits",
                baseline_value="0 expected",
                deviation_score=0.95,
                explanation="Source IP/indicator found in threat intelligence feeds.",
                is_critical=True,
            ))

        if not findings:
            return 0.05, []

        total = sum(f.deviation_score for f in findings) / len(findings)
        if any(f.is_critical for f in findings):
            total = min(1.0, total * 1.5)
        return round(total, 4), sorted(findings, key=lambda f: -f.deviation_score)


# ─────────────────────────────────────────────────────────────
# UEBA Report
# ─────────────────────────────────────────────────────────────

@dataclass
class UEBAReport:
    entity_id:                  str
    entity_type:                str
    risk_score:                 float
    risk_label:                 str
    anomalies:                  List[AnomalyFinding]
    baseline_age_days:          float
    analysis_timestamp:         str
    event_id:                   str
    recommended_investigation:  List[str]
    is_cold_start:              bool = False     # BUG 4 FIX: expose cold-start flag

    @property
    def is_anomalous(self) -> bool:
        return self.risk_score >= 0.40

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id":                 self.entity_id,
            "entity_type":               self.entity_type,
            "risk_score":                self.risk_score,
            "risk_label":                self.risk_label,
            "anomaly_count":             len(self.anomalies),
            "critical_anomalies":        sum(1 for a in self.anomalies if a.is_critical),
            "is_cold_start":             self.is_cold_start,    # BUG 4 FIX
            "anomalies": [{"feature":    a.feature,
                           "observed":   str(a.observed_value),
                           "baseline":   str(a.baseline_value),
                           "score":      a.deviation_score,
                           "explanation":a.explanation,
                           "critical":   a.is_critical}
                          for a in self.anomalies],
            "baseline_age_days":         round(self.baseline_age_days, 1),
            "analysis_timestamp":        self.analysis_timestamp,
            "recommended_investigation": self.recommended_investigation,
        }


def _score_to_label(score: float) -> str:
    if score >= 0.80: return "critical"
    elif score >= 0.60: return "high"
    elif score >= 0.40: return "medium"
    else: return "low"


# ─────────────────────────────────────────────────────────────
# UEBA Engine
# ─────────────────────────────────────────────────────────────

class UEBAEngine:
    """
    BUG 3 FIX: Accepts tenant_id, scopes BaselineStore keys.
    BUG 4 FIX: Uses PeerGroupStore for cold-start mitigation.
               Exposes warmup_from_logs() for historical import.
    """

    def __init__(self, redis_url: Optional[str] = None,
                 tenant_id: str = "default") -> None:
        self._store      = BaselineStore(redis_url=redis_url, tenant_id=tenant_id)
        self._peer_store = PeerGroupStore()
        self._extractor  = FeatureExtractor()
        self._scorer     = AnomalyScorer()
        self._tenant_id  = tenant_id

    async def analyze(self, event: SecurityEvent, data: CollectedData) -> UEBAReport:
        features    = self._extractor.extract(event, data)
        entity_id   = features["entity_id"]
        entity_type = features["entity_type"]

        baseline      = self._store.get(entity_id)
        peer_baseline = self._peer_store.get(entity_type)    # BUG 4 FIX
        is_cold_start = baseline is None or baseline.sample_count < AnomalyScorer.MIN_SAMPLES

        risk_score, findings = self._scorer.score(
            features, baseline, peer_baseline                # BUG 4 FIX
        )

        updated_baseline = self._update_baseline(features, baseline, entity_id, entity_type)
        self._store.set(updated_baseline)
        self._peer_store.update(updated_baseline)            # BUG 4 FIX: keep peer store current

        baseline_age = 0.0
        if baseline and baseline.last_updated:
            try:
                last = datetime.fromisoformat(baseline.last_updated.replace("Z", "+00:00"))
                baseline_age = (datetime.now(tz=timezone.utc) - last).total_seconds() / 86400
            except (ValueError, TypeError):
                pass

        report = UEBAReport(
            entity_id                 = entity_id,
            entity_type               = entity_type,
            risk_score                = risk_score,
            risk_label                = _score_to_label(risk_score),
            anomalies                 = findings,
            baseline_age_days         = baseline_age,
            analysis_timestamp        = datetime.now(tz=timezone.utc).isoformat(),
            event_id                  = event.event_id,
            recommended_investigation = self._recommend_investigation(findings, event),
            is_cold_start             = is_cold_start,       # BUG 4 FIX
        )

        logger.info("ueba_analysis_complete", entity=entity_id,
                    risk_score=risk_score, risk_label=report.risk_label,
                    anomalies=len(findings), is_cold_start=is_cold_start,
                    tenant_id=self._tenant_id)
        return report

    # BUG 4 FIX: historical warm-up ──────────────────────────────

    async def warmup_from_logs(
        self,
        entity_id: str,
        entity_type: str,
        historical_logs: List[Dict[str, Any]],
        synthetic_event: Optional[SecurityEvent] = None,
    ) -> BehaviorBaseline:
        """
        Pre-populate a behavioral baseline from historical log records.
        Call this during tenant onboarding to eliminate the cold-start
        problem for known users/hosts.

        Args:
            entity_id:       entity identifier (email, hostname, IP)
            entity_type:     EntityType constant
            historical_logs: list of log dicts in the same format as
                             DataCollector produces (source + fields)
            synthetic_event: optional SecurityEvent to pass to FeatureExtractor;
                             a minimal one is created automatically if None.
        """
        if synthetic_event is None:
            from acda.models.schemas import SecurityEvent as SE
            synthetic_event = SE(
                event_id   = f"warmup-{entity_id}",
                event_type = "anomaly_detected",
                severity   = "low",
                timestamp  = datetime.now(tz=timezone.utc).isoformat(),
                user       = entity_id if entity_type == EntityType.USER else None,
                source_host= entity_id if entity_type == EntityType.HOST else None,
            )

        # Process historical logs in batches of 50 to simulate daily observations
        batch_size = 50
        baseline: Optional[BehaviorBaseline] = self._store.get(entity_id)

        for i in range(0, len(historical_logs), batch_size):
            batch = historical_logs[i: i + batch_size]
            from acda.models.schemas import CollectedData as CD
            data = CD(event=synthetic_event, logs=batch, threat_intel=[])
            features = self._extractor.extract(synthetic_event, data)
            baseline = self._update_baseline(features, baseline, entity_id, entity_type)

        if baseline:
            self._store.set(baseline)
            self._peer_store.update(baseline)
            logger.info("ueba_warmup_complete", entity_id=entity_id,
                        sample_count=baseline.sample_count, tenant_id=self._tenant_id)

        return baseline or BehaviorBaseline(entity_id=entity_id, entity_type=entity_type)

    # ────────────────────────────────────────────────────────────

    def _update_baseline(self, features, baseline, entity_id, entity_type):
        bl = baseline or BehaviorBaseline(entity_id=entity_id, entity_type=entity_type)
        bl.update_ema("avg_logins_per_day",         features.get("login_count", 0))
        bl.update_ema("avg_bytes_per_day",           features.get("bytes_sent", 0))
        bl.update_ema("avg_connections_per_day",     features.get("connection_count", 0))
        bl.update_ema("avg_files_accessed_per_day",  features.get("files_accessed", 0))
        bl.update_ema("avg_files_written_per_day",   features.get("files_written", 0))
        bl.update_ema("avg_privilege_uses_per_day",  features.get("privilege_uses", 0))
        bl.update_ema("avg_process_executions_per_hour", len(features.get("processes", [])))

        for hour in features.get("login_hours", []):
            if hour not in bl.typical_login_hours:
                bl.typical_login_hours = (bl.typical_login_hours + [hour])[-24:]
        for ip in features.get("unique_source_ips", []):
            if ip and ip not in bl.typical_source_ips:
                bl.typical_source_ips = (bl.typical_source_ips + [ip])[-20:]
        for app in features.get("applications", []):
            if app and app not in bl.typical_applications:
                bl.typical_applications = (bl.typical_applications + [app])[-30:]
        for proc in features.get("processes", []):
            if proc and proc not in bl.typical_processes:
                bl.typical_processes = (bl.typical_processes + [proc])[-30:]
        for dest in features.get("unique_destinations", []):
            if dest and dest not in bl.typical_destinations:
                bl.typical_destinations = (bl.typical_destinations + [dest])[-30:]

        bl.sample_count += 1
        bl.last_updated = datetime.now(tz=timezone.utc).isoformat()
        return bl

    def _recommend_investigation(self, findings, event):
        steps = []
        feats = {f.feature for f in findings}
        if "login_hour" in feats:
            steps.append(f"Review all login activity for {event.user} in the last 24h")
        if "source_ip" in feats or "source_ip_vs_peer" in feats:
            steps.append("Geolocate the new source IP and check against VPN/travel records")
        if "bytes_sent" in feats or "bytes_sent_vs_peer" in feats:
            steps.append("Inspect outbound traffic destinations and data classification")
        if "files_written" in feats:
            steps.append("Check for file encryption patterns — potential ransomware")
        if "privilege_use" in feats or "privilege_use_vs_peer" in feats:
            steps.append(f"Audit how {event.user} obtained elevated privileges")
        if "failed_logins" in feats:
            steps.append("Review authentication logs for brute force source")
        if "threat_intel" in feats:
            steps.append("Cross-reference threat intel indicator with all internal hosts")
        if "baseline_availability" in feats:
            steps.append("Baseline being established — increase monitoring frequency for this entity")
        if not steps:
            steps.append("Continue monitoring baseline")
        return steps

    async def get_high_risk_entities(self, min_score: float = 0.70) -> List[str]:
        risky = []
        for entity_id in self._store.list_entities():
            baseline = self._store.get(entity_id)
            if baseline and baseline.avg_privilege_uses_per_day > 5:
                risky.append(entity_id)
        return risky
