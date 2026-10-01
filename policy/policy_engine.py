from config import (
    POLICY_BLOCK_THRESHOLD,
    POLICY_CRITICAL_ACTION,
    POLICY_FLAG_OVERRIDE,
    POLICY_HIGH_ACTION,
    POLICY_MEDIUM_ACTION,
    POLICY_MODE,
)
from policy.sanitizer import InputSanitizer
from state import Decision, PolicyDecision, RiskLevel, RiskScoreResult, SecurityAnalysisResult


class PolicyEngine:
    """
    Policy Engine (Phase 2 & 3 Refactored):
    Evaluates computed RiskScoreResult and SecurityAnalysisResult against strict security threshold rules:

    STRICT HARD THRESHOLD RULES:
    1. If RISK >= POLICY_BLOCK_THRESHOLD, or a threat vector is present while
       POLICY_FLAG_OVERRIDE is enabled:
       -> Set ACTION: BLOCK.
       -> Immediately terminate downstream execution chain.
       -> Return standardized error payload: {"status": "BLOCKED", "risk_score": score, "reason": "Security Policy Violation"}.
    2. There is no separate warning action: findings are logged while the
       canonical action remains ALLOW, SANITIZE, REVIEW, or BLOCK.
    3. ALLOW ACTION: ALLOW ONLY if RISK < POLICY_BLOCK_THRESHOLD and, when
       the override is enabled, no threat vectors are detected.
    """

    CRITICAL_FLAG_PREFIXES = (
        # Explicit system-control overrides remain blocked even when an
        # optional detector is unavailable or graded policy is configured.
        "PROMPT_INJECTION:SYSTEM_OVERRIDE",
        "PROMPT_INJECTION:PRIVILEGED_ROLE_OVERRIDE",
        "PROMPT_INJECTION:SYSTEM_PROMPT_EXFILTRATION",
        "DATA_LEAKAGE:",
        "CODE_EXECUTION:SHELL_DESTRUCTIVE",
        "CODE_EXECUTION:PYTHON_EVAL",
        "CODE_EXECUTION:PYTHON_EXEC",
        "CODE_EXECUTION:SUBPROCESS_EXEC",
        "CODE_EXECUTION:MALICIOUS_DOWNLOAD_EXEC",
    )

    @classmethod
    def _critical_findings(cls, analysis_result: SecurityAnalysisResult) -> list[str]:
        """Return non-negotiable signals independent of a blended score."""
        findings = list(analysis_result.rule_flags) + list(analysis_result.context_flags)
        return [
            flag for flag in findings
            if any(str(flag).startswith(prefix) for prefix in cls.CRITICAL_FLAG_PREFIXES)
        ]

    @classmethod
    def evaluate(
        cls,
        analysis_result: SecurityAnalysisResult,
        risk_metrics: RiskScoreResult,
    ) -> PolicyDecision:
        """
        Evaluates risk metrics and issues a strict PolicyDecision.
        """
        normalized_input = analysis_result.normalized_input
        rule_flags = analysis_result.rule_flags
        context_flags = analysis_result.context_flags
        llm_class = analysis_result.llm_classification or {}
        semantic = analysis_result.semantic_similarity or {}
        score = risk_metrics.score

        critical_findings = cls._critical_findings(analysis_result)
        if critical_findings:
            return PolicyDecision(
                action=Decision.BLOCK,
                modified_input=None,
                reason=(
                    "Capability-aware policy blocked a critical security signal: "
                    + ", ".join(critical_findings)
                ),
                risk_metrics=risk_metrics,
            )

        # A detector outage is represented explicitly by RiskAnalyzer.  It is
        # never converted into a zero signal: suspicious content must not be
        # forwarded while a semantic control is degraded.
        if (
            analysis_result.raw_signals.get("security_mode") == "DEGRADED"
            and analysis_result.is_flagged
        ):
            return PolicyDecision(
                action=Decision.REVIEW,
                modified_input=None,
                reason="Security mode is DEGRADED and suspicious content requires review.",
                risk_metrics=risk_metrics,
            )

        # Phase 19 ``banded`` policy mode: map risk bands to explicit,
        # configurable actions instead of a single score threshold.  This is an
        # experimental policy variant for the propagation study; the default
        # ``score_threshold`` mode below remains byte-identical to the frozen
        # Phase 6.5 operating point.
        if POLICY_MODE == "banded":
            return cls._banded_decision(
                analysis_result, risk_metrics, normalized_input
            )

        is_malicious_llm = llm_class.get("is_malicious", False)
        semantic_flagged = bool(semantic.get("semantic_similarity_enabled") and semantic.get("flagged"))
        has_threat_flags = bool(rule_flags or context_flags or is_malicious_llm or semantic_flagged)

        # 1. BLOCK ENFORCEMENT: score boundary plus the explicitly configured
        # Phase 3 flag override.  Phase 4 evaluates both components separately.
        if score >= POLICY_BLOCK_THRESHOLD or (POLICY_FLAG_OVERRIDE and has_threat_flags):
            threat_details = []
            if rule_flags:
                threat_details.append(f"Rule Flags: {', '.join(rule_flags)}")
            if context_flags:
                threat_details.append(f"Context Flags: {', '.join(context_flags)}")
            if is_malicious_llm:
                threat_details.append(f"LLM Classification: {llm_class.get('category', 'Malicious')}")
            if semantic_flagged:
                top = semantic.get("top_match") or {}
                threat_details.append(
                    "Semantic Similarity: "
                    f"{top.get('category', 'UNKNOWN')} ({float(top.get('similarity', 0.0)):.3f})"
                )

            trigger = (
                f"risk score ({score:.2f} >= {POLICY_BLOCK_THRESHOLD:.2f} threshold)"
                if score >= POLICY_BLOCK_THRESHOLD
                else "configured detector flag override"
            )
            reason_str = (
                f"Security Policy Violation: Execution BLOCKED due to {trigger}. "
                f"Threat Vectors: {' | '.join(threat_details) if threat_details else 'High Risk Score'}"
            )

            return PolicyDecision(
                action=Decision.BLOCK,
                modified_input=None,
                reason=reason_str,
                risk_metrics=risk_metrics,
            )

        # 2. ALLOW Decision (ONLY if RISK is below the configured threshold)
        return PolicyDecision(
            action=Decision.ALLOW,
            modified_input=normalized_input,
            reason=f"Input verified safe and ALLOWED for multi-agent workflow (Risk Score: {score:.2f} < {POLICY_BLOCK_THRESHOLD:.2f}).",
            risk_metrics=risk_metrics,
        )

    @classmethod
    def _banded_decision(
        cls,
        analysis_result: SecurityAnalysisResult,
        risk_metrics: RiskScoreResult,
        normalized_input: str,
    ) -> PolicyDecision:
        """Map a risk band to a configurable action (LOW/MEDIUM/HIGH/CRITICAL).

        LOW      -> ALLOW
        MEDIUM   -> POLICY_MEDIUM_ACTION    (SANITIZE by default)
        HIGH     -> POLICY_HIGH_ACTION      (BLOCK by default)
        CRITICAL -> POLICY_CRITICAL_ACTION  (BLOCK by default)

        SANITIZE never forwards the untouched raw value: the sanitized text is
        returned as ``modified_input`` and callers fail closed if no distinct
        safe value exists.
        """
        level = risk_metrics.level
        score = risk_metrics.score
        action_for_level = {
            RiskLevel.LOW: Decision.ALLOW,
            RiskLevel.MEDIUM: Decision(POLICY_MEDIUM_ACTION),
            RiskLevel.HIGH: Decision(POLICY_HIGH_ACTION),
            RiskLevel.CRITICAL: Decision(POLICY_CRITICAL_ACTION),
        }
        action = action_for_level.get(level, Decision.BLOCK)
        modified_input: str | None = None
        if action == Decision.ALLOW:
            modified_input = normalized_input
            reason = (
                f"Banded policy: risk {score:.2f} [{level.value}] maps to ALLOW "
                "(below MEDIUM band)."
            )
        elif action == Decision.SANITIZE:
            sanitized = InputSanitizer.sanitize(normalized_input)
            modified_input = sanitized if sanitized and sanitized != normalized_input else None
            reason = (
                f"Banded policy: risk {score:.2f} [{level.value}] maps to SANITIZE; "
                "payload redacted/neutralized before forwarding."
            )
            if modified_input is None:
                # A SANITIZE that cannot produce a distinct safe value must not
                # forward the original; fall back to a review-required block.
                action = Decision.BLOCK
                modified_input = None
                reason = (
                    f"Banded policy: risk {score:.2f} [{level.value}] requested SANITIZE "
                    "but no distinct safe value was available; blocked."
                )
        else:
            reason = (
                f"Banded policy: risk {score:.2f} [{level.value}] maps to "
                f"{action.value}."
            )
        return PolicyDecision(
            action=action,
            modified_input=modified_input,
            reason=reason,
            risk_metrics=risk_metrics,
        )
