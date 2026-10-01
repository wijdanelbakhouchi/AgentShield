"""
logging/dashboard_sync.py
=========================
AgentShield Phase 3 — Real-Time Telemetry & State Synchronization Module

Provides non-blocking, zero-latency impact telemetry logging to Streamlit/React UI event buses
and SQLite DB / Timeseries monitoring metrics.
"""

import datetime
import hashlib
import threading
from typing import Any, Dict, List, Optional

# In-memory telemetry log bus for UI state sync
ACTIVE_TELEMETRY_BUS: List[Dict[str, Any]] = []


class TelemetryLogger:
    """
    Real-Time Telemetry & State Synchronization Logger:
    Emits telemetry events asynchronously without impacting request latency.
    """

    @classmethod
    def log_telemetry_event(
        cls,
        threat_report: Dict[str, Any],
        enforcement_result: Dict[str, Any],
        normalized_payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emits telemetry events asynchronously to UI event bus and DB metrics collector.
        """
        # Run logging in background thread to guarantee zero latency impact
        thread = threading.Thread(
            target=cls._async_emit_worker,
            args=(threat_report, enforcement_result, normalized_payload),
            daemon=True,
        )
        thread.start()

    @classmethod
    def _async_emit_worker(
        cls,
        threat_report: Dict[str, Any],
        enforcement_result: Dict[str, Any],
        normalized_payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Background worker executing DB & UI event bus logging."""
        try:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            raw_input = str((normalized_payload or {}).get("raw_input", ""))
            normalized_input = str((normalized_payload or {}).get("normalized_input", raw_input))
            score = float(enforcement_result.get("risk_score", 0.0))
            action = enforcement_result.get("action", "ALLOW")
            threat_level = enforcement_result.get("threat_level", "LOW")
            latency_ms = float(threat_report.get("execution_time_ms", 0.0))

            telemetry_event = {
                "timestamp": timestamp,
                # Operational telemetry must not duplicate raw prompts.  Full
                # research traces are written by the dedicated E2E harness,
                # under an explicit experiment artifact directory.
                "input_metadata": {
                    "raw_length": len(raw_input),
                    "normalized_length": len(normalized_input),
                    "normalized_sha256": hashlib.sha256(normalized_input.encode("utf-8")).hexdigest() if normalized_input else None,
                },
                "risk_score": score,
                "threat_level": threat_level,
                "action_taken": action,
                "detected_vectors": threat_report.get("detected_threat_vectors", []),
                "latency_ms": latency_ms,
                "reason": enforcement_result.get("reason", "N/A"),
            }

            # 1. Update In-Memory UI Telemetry Bus (capped at 50 recent events)
            global ACTIVE_TELEMETRY_BUS
            ACTIVE_TELEMETRY_BUS.insert(0, telemetry_event)
            if len(ACTIVE_TELEMETRY_BUS) > 50:
                ACTIVE_TELEMETRY_BUS = ACTIVE_TELEMETRY_BUS[:50]

            # 2. Persist to SQLite Database via MetricsCollector
            try:
                from logging.metrics import MetricsCollector

                # Update in-memory metrics collector
                MetricsCollector.record_event(
                    risk_score=score,
                    risk_level=threat_level,
                    action=action,
                    rule_flags=threat_report.get("detected_threat_vectors", []),
                    latency_ms=latency_ms,
                )
            except Exception:
                pass

        except Exception:
            pass  # Ensure telemetry failures never break execution pipeline
