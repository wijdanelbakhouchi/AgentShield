"""
logging/metrics.py
==================
AgentShield Phase 5 — Telemetry & Metrics Aggregator

Queries the persistent SQLite database to calculate real-time operational and
security metrics for the observability dashboard:
  - Total Request Volume & Throughput
  - Risk Score Distribution & Threshold Percentiles (p50, p95, p99)
  - Attack Detection Rate & Block Rate by Risk Band
  - Top Triggered Rules & Common Attack Vectors
  - Operational Latency Overhead (p50, p95, p99, average)
  - Tool Execution & Inter-Agent Handoff Summary

Uses function-level lazy database session imports to ensure clean module initialization.
"""

import json
import math
from collections import Counter
from typing import Any, Dict, List


def _calc_percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return round(float(sorted_vals[int(k)]), 2)
    return round(float(sorted_vals[int(f)] * (c - k) + sorted_vals[int(c)] * (k - f)), 2)


class MetricsCollector:
    """
    Database-driven telemetry aggregator computing operational metrics.
    """

    @classmethod
    def get_overview(cls) -> Dict[str, Any]:
        """
        Calculates high-level system overview cards:
          - Total Requests
          - Total Attacks Blocked
          - Total Attacks Sanitized
          - Average Risk Score
          - Average Gateway Latency (ms)
        """
        from sqlalchemy import func
        from storage.db import get_db_session, init_db
        from storage.models import SecurityLog

        init_db()

        with get_db_session() as session:
            total_requests = session.query(func.count(SecurityLog.id)).scalar() or 0
            blocked_count = (
                session.query(func.count(SecurityLog.id))
                .filter(SecurityLog.policy_decision == "BLOCK")
                .scalar()
                or 0
            )
            sanitized_count = (
                session.query(func.count(SecurityLog.id))
                .filter(SecurityLog.policy_decision == "SANITIZE")
                .scalar()
                or 0
            )
            avg_risk = (
                session.query(func.avg(SecurityLog.risk_score)).scalar() or 0.0
            )
            avg_latency = (
                session.query(func.avg(SecurityLog.latency_ms)).scalar() or 0.0
            )

        return {
            "total_requests": total_requests,
            "blocked_requests": blocked_count,
            "sanitized_requests": sanitized_count,
            "avg_risk_score": round(float(avg_risk), 3),
            "avg_latency_ms": round(float(avg_latency), 2),
            "block_rate_percent": (
                round((blocked_count / total_requests) * 100, 1)
                if total_requests > 0
                else 0.0
            ),
        }

    @classmethod
    def get_risk_distribution(cls) -> Dict[str, int]:
        """
        Returns counts of inbound requests categorized by Risk Level:
        LOW, MEDIUM, HIGH, CRITICAL.
        """
        from sqlalchemy import func
        from storage.db import get_db_session, init_db
        from storage.models import SecurityLog

        init_db()
        dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

        with get_db_session() as session:
            results = (
                session.query(
                    SecurityLog.risk_level, func.count(SecurityLog.id)
                )
                .group_by(SecurityLog.risk_level)
                .all()
            )
            for level, count in results:
                if level in dist:
                    dist[level] = count

        return dist

    @classmethod
    def get_risk_percentiles(cls) -> Dict[str, float]:
        """
        Calculates p50, p95, p99 risk score percentiles across all requests.
        """
        from storage.db import get_db_session, init_db
        from storage.models import SecurityLog

        init_db()

        with get_db_session() as session:
            scores = [
                row[0]
                for row in session.query(SecurityLog.risk_score).all()
                if row[0] is not None
            ]

        if not scores:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}

        return {
            "p50": _calc_percentile(scores, 50),
            "p95": _calc_percentile(scores, 95),
            "p99": _calc_percentile(scores, 99),
        }

    @classmethod
    def get_latency_percentiles(cls) -> Dict[str, float]:
        """
        Calculates p50, p95, p99 latency overhead (in ms) added by interceptors.
        """
        from storage.db import get_db_session, init_db
        from storage.models import SecurityLog

        init_db()

        with get_db_session() as session:
            latencies = [
                row[0]
                for row in session.query(SecurityLog.latency_ms).all()
                if row[0] is not None
            ]

        if not latencies:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0}

        avg_val = round(float(sum(latencies) / len(latencies)), 2)
        return {
            "p50": _calc_percentile(latencies, 50),
            "p95": _calc_percentile(latencies, 95),
            "p99": _calc_percentile(latencies, 99),
            "avg": avg_val,
        }

    @classmethod
    def get_attack_rate_by_band(cls) -> Dict[str, Dict[str, Any]]:
        """
        Computes total requests, block rate, and sanitize rate for each Risk Band.
        """
        from storage.db import get_db_session, init_db
        from storage.models import SecurityLog

        init_db()
        bands = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        stats = {
            band: {"total": 0, "blocked": 0, "sanitized": 0, "block_rate": 0.0}
            for band in bands
        }

        with get_db_session() as session:
            rows = session.query(
                SecurityLog.risk_level, SecurityLog.policy_decision
            ).all()

            for level, decision in rows:
                if level in stats:
                    stats[level]["total"] += 1
                    if decision == "BLOCK":
                        stats[level]["blocked"] += 1
                    elif decision == "SANITIZE":
                        stats[level]["sanitized"] += 1

        for band, data in stats.items():
            tot = data["total"]
            data["block_rate"] = (
                round((data["blocked"] / tot) * 100, 1) if tot > 0 else 0.0
            )

        return stats

    @classmethod
    def get_top_triggered_rules(cls, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Analyzes rule_flags from SecurityLog and HandoffLog to return top
        triggered heuristic rules and attack categories.
        """
        from storage.db import get_db_session, init_db
        from storage.models import HandoffLog, SecurityLog

        init_db()
        counter = Counter()

        with get_db_session() as session:
            sec_flags = session.query(SecurityLog.rule_flags).all()
            for (r_flags,) in sec_flags:
                if r_flags:
                    try:
                        flags_list = json.loads(r_flags)
                        for f in flags_list:
                            counter[f] += 1
                    except Exception:
                        pass

            handoff_flags = session.query(HandoffLog.detected_flags).all()
            for (h_flags,) in handoff_flags:
                if h_flags:
                    try:
                        flags_list = json.loads(h_flags)
                        for f in flags_list:
                            counter[f] += 1
                    except Exception:
                        pass

        top_rules = [
            {"rule_flag": flag, "count": count}
            for flag, count in counter.most_common(limit)
        ]
        return top_rules

    @classmethod
    def get_tool_stats(cls) -> List[Dict[str, Any]]:
        """
        Calculates tool execution metrics per tool:
        total calls, passed, blocked, sanitized.
        """
        from sqlalchemy import func
        from storage.db import get_db_session, init_db
        from storage.models import ToolLog

        init_db()

        with get_db_session() as session:
            tools = session.query(ToolLog.tool_name).distinct().all()
            results = []

            for (t_name,) in tools:
                total = (
                    session.query(func.count(ToolLog.id))
                    .filter(ToolLog.tool_name == t_name)
                    .scalar()
                    or 0
                )
                passed = (
                    session.query(func.count(ToolLog.id))
                    .filter(
                        ToolLog.tool_name == t_name, ToolLog.status == "PASSED"
                    )
                    .scalar()
                    or 0
                )
                blocked = (
                    session.query(func.count(ToolLog.id))
                    .filter(
                        ToolLog.tool_name == t_name, ToolLog.status == "BLOCKED"
                    )
                    .scalar()
                    or 0
                )
                sanitized = (
                    session.query(func.count(ToolLog.id))
                    .filter(
                        ToolLog.tool_name == t_name,
                        ToolLog.status == "SANITIZED",
                    )
                    .scalar()
                    or 0
                )

                results.append(
                    {
                        "tool_name": t_name,
                        "total_calls": total,
                        "passed": passed,
                        "blocked": blocked,
                        "sanitized": sanitized,
                    }
                )

        return results

    @classmethod
    def get_handoff_stats(cls) -> List[Dict[str, Any]]:
        """
        Calculates inter-agent handoff metrics by boundary.
        """
        from sqlalchemy import func
        from storage.db import get_db_session, init_db
        from storage.models import HandoffLog

        init_db()

        with get_db_session() as session:
            boundaries = (
                session.query(HandoffLog.from_agent, HandoffLog.to_agent)
                .distinct()
                .all()
            )
            results = []

            for from_a, to_a in boundaries:
                boundary_label = f"{from_a} → {to_a}"
                total = (
                    session.query(func.count(HandoffLog.id))
                    .filter(
                        HandoffLog.from_agent == from_a,
                        HandoffLog.to_agent == to_a,
                    )
                    .scalar()
                    or 0
                )
                avg_risk = (
                    session.query(func.avg(HandoffLog.risk_score))
                    .filter(
                        HandoffLog.from_agent == from_a,
                        HandoffLog.to_agent == to_a,
                    )
                    .scalar()
                    or 0.0
                )
                blocked = (
                    session.query(func.count(HandoffLog.id))
                    .filter(
                        HandoffLog.from_agent == from_a,
                        HandoffLog.to_agent == to_a,
                        HandoffLog.action_taken == "BLOCK",
                    )
                    .scalar()
                    or 0
                )
                sanitized = (
                    session.query(func.count(HandoffLog.id))
                    .filter(
                        HandoffLog.from_agent == from_a,
                        HandoffLog.to_agent == to_a,
                        HandoffLog.sanitized.is_(True),
                    )
                    .scalar()
                    or 0
                )

                results.append(
                    {
                        "boundary": boundary_label,
                        "total_handoffs": total,
                        "avg_risk": round(float(avg_risk), 2),
                        "blocked": blocked,
                        "sanitized": sanitized,
                    }
                )

        return results

    @classmethod
    def get_alerts_summary(cls, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieves recent security alerts ordered by timestamp descending.
        """
        from storage.db import get_db_session, init_db
        from storage.models import AlertLog

        init_db()

        with get_db_session() as session:
            alerts = (
                session.query(AlertLog)
                .order_by(AlertLog.id.desc())
                .limit(limit)
                .all()
            )

            return [
                {
                    "id": a.id,
                    "timestamp": a.timestamp,
                    "severity": a.severity,
                    "title": a.title,
                    "description": a.description,
                    "request_id": a.request_id,
                    "alert_type": a.alert_type,
                    "source_component": a.source_component,
                }
                for a in alerts
            ]
