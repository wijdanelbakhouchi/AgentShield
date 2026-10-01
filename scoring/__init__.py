"""
Risk Scoring Engine module for AgentShield Phase 3.
Calculates normalized risk scores (0.0 to 1.0) and assigns threat severity levels (LOW, MEDIUM, HIGH, CRITICAL).
"""

from scoring.risk_scorer import RiskScorer

__all__ = ["RiskScorer"]
