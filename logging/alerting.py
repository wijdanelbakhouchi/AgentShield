"""
logging/alerting.py
===================
AgentShield Phase 5 — Real-Time Alerting Engine

Evaluates security interception events across gateway, tool guard, and inter-agent
boundaries to trigger real-time alerts.

Alert Triggers:
  - CRITICAL: Blocked executions, prompt injection overrides, or severe attacks
  - HIGH    : Tool abuse attempts (SQLi, path traversal, shell commands), repeated failures
  - MEDIUM  : Sanitized inputs or neutralized indirect prompt injections

Alert Dispatch:
  - Persists AlertLog records to SQLite/DB via EventLogger
  - Formats structured Alert objects ready for Webhook / Slack / Email dispatch
"""

from typing import Any, Dict, Optional

from schema.interception import AgentHandoffEvent, ToolExecutionEvent
from state import PolicyDecision, RiskScoreResult, SecurityAnalysisResult


class AlertEngine:
    """
    Real-Time Security Event Alert Engine.
    """

    @classmethod
    def evaluate_security_event(
        cls,
        analysis_result: SecurityAnalysisResult,
        risk_metrics: RiskScoreResult,
        policy_decision: PolicyDecision,
        request_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates entry gateway results (Phases 1–3) and emits an alert if warranted.
        """
        from logging.event_logger import EventLogger

        action = policy_decision.action.value
        risk_level = risk_metrics.level.value
        score = risk_metrics.score
        flags = analysis_result.rule_flags

        # 1. CRITICAL Alert: Blocked execution or high-confidence prompt injection
        if action == "BLOCK" or risk_level == "CRITICAL" or score >= 0.85:
            severity = "CRITICAL"
            title = f"CRITICAL SECURITY BLOCK: Request {request_id}"
            description = (
                f"Entry execution BLOCKED by PolicyEngine (Risk Score: {score:.2f}, Level: {risk_level}). "
                f"Reason: {policy_decision.reason}. "
                f"Flags: {flags if flags else 'None'}."
            )
            alert_obj = {
                "request_id": request_id,
                "timestamp": analysis_result.timestamp,
                "severity": severity,
                "title": title,
                "description": description,
                "alert_type": "GATEWAY_BLOCK",
                "source_component": "PolicyEngine",
            }
            EventLogger.log_alert(**alert_obj)
            return alert_obj

        # 2. HIGH Alert: derive wording from the canonical action.  A HIGH
        # score below the calibrated block threshold may be ALLOW; it must not
        # be reported as if the payload was sanitized.
        if action == "SANITIZE" or risk_level == "HIGH" or len(flags) >= 2:
            severity = "HIGH"
            action_label = {
                "SANITIZE": "SANITIZED",
                "REVIEW": "HELD FOR REVIEW",
                "BLOCK": "BLOCKED",
                "ALLOW": "ALLOWED",
            }.get(action, action)
            title = f"HIGH THREAT {action_label}: Request {request_id}"
            description = (
                f"Entry payload action={action_label} under canonical policy "
                f"(Risk Score: {score:.2f}, Level: {risk_level}). Triggered flags: {flags}."
            )
            alert_obj = {
                "request_id": request_id,
                "timestamp": analysis_result.timestamp,
                "severity": severity,
                "title": title,
                "description": description,
                "alert_type": "GATEWAY_SANITIZE" if action == "SANITIZE" else "GATEWAY_OBSERVED",
                "source_component": "PolicyEngine",
            }
            EventLogger.log_alert(**alert_obj)
            return alert_obj

        return None

    @classmethod
    def evaluate_tool_event(
        cls,
        tool_event: ToolExecutionEvent,
        request_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates Phase 4 tool execution events and emits alerts for tool abuse.
        """
        from logging.event_logger import EventLogger

        status = tool_event.status
        pre_status = tool_event.pre_exec_status
        post_status = tool_event.post_exec_status

        # 1. CRITICAL/HIGH Alert: Tool call BLOCKED due to parameter abuse (SQLi, Path Traversal, Shell)
        if status == "BLOCKED" or pre_status == "BLOCKED":
            severity = "CRITICAL"
            title = f"TOOL ABUSE BLOCKED: '{tool_event.tool_name}' by '{tool_event.agent_caller}'"
            description = (
                f"Pre-execution ToolGuard BLOCKED execution of '{tool_event.tool_name}'. "
                f"Caller: {tool_event.agent_caller}. "
                f"Threat: {tool_event.mitigated_threat}. "
                f"Flags: {tool_event.pre_exec_flags}."
            )
            alert_obj = {
                "request_id": request_id,
                "timestamp": tool_event.timestamp,
                "severity": severity,
                "title": title,
                "description": description,
                "alert_type": "TOOL_BLOCKED",
                "source_component": "ToolGuard",
            }
            EventLogger.log_alert(**alert_obj)
            return alert_obj

        # 2. HIGH/MEDIUM Alert: Indirect prompt injection detected & sanitized in tool output
        if post_status == "SANITIZED" or tool_event.output_sanitized:
            severity = "HIGH"
            title = f"INDIRECT PROMPT INJECTION NEUTRALIZED: Tool '{tool_event.tool_name}'"
            description = (
                f"Post-execution ToolGuard detected and SANITIZED indirect prompt injection payload "
                f"returned by tool '{tool_event.tool_name}'. "
                f"Post-exec flags: {tool_event.post_exec_flags}."
            )
            alert_obj = {
                "request_id": request_id,
                "timestamp": tool_event.timestamp,
                "severity": severity,
                "title": title,
                "description": description,
                "alert_type": "INDIRECT_INJECTION_NEUTRALIZED",
                "source_component": "ToolGuard",
            }
            EventLogger.log_alert(**alert_obj)
            return alert_obj

        return None

    @classmethod
    def evaluate_handoff_event(
        cls,
        handoff_event: AgentHandoffEvent,
        request_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates Phase 4 inter-agent handoff events and emits alerts for privilege escalation.
        """
        from logging.event_logger import EventLogger

        action = handoff_event.action_taken.value
        risk_level = handoff_event.risk_level.value
        boundary = f"{handoff_event.from_agent} → {handoff_event.to_agent}"

        if action == "BLOCK" or risk_level == "CRITICAL":
            severity = "CRITICAL"
            title = f"INTER-AGENT HANDOFF BLOCKED: {boundary}"
            description = (
                f"InterAgentGuard BLOCKED state transition at boundary '{boundary}'. "
                f"Field: '{handoff_event.intercepted_field}', Risk Score: {handoff_event.risk_score:.2f}. "
                f"Reason: {handoff_event.reason}."
            )
            alert_obj = {
                "request_id": request_id,
                "timestamp": handoff_event.timestamp,
                "severity": severity,
                "title": title,
                "description": description,
                "alert_type": "HANDOFF_BLOCKED",
                "source_component": "InterAgentGuard",
            }
            EventLogger.log_alert(**alert_obj)
            return alert_obj

        if action == "SANITIZE" and handoff_event.detected_flags:
            severity = "MEDIUM"
            title = f"INTER-AGENT PAYLOAD SANITIZED: {boundary}"
            description = (
                f"InterAgentGuard SANITIZED payload at boundary '{boundary}'. "
                f"Flags: {handoff_event.detected_flags}."
            )
            alert_obj = {
                "request_id": request_id,
                "timestamp": handoff_event.timestamp,
                "severity": severity,
                "title": title,
                "description": description,
                "alert_type": "HANDOFF_SANITIZED",
                "source_component": "InterAgentGuard",
            }
            EventLogger.log_alert(**alert_obj)
            return alert_obj

        return None
