from __future__ import annotations

from enum import Enum
from time import time
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    SANITIZE = "sanitize"
    BLOCK = "block"


class AgentMessage(BaseModel):
    content: str = Field(min_length=1)
    source: str = "user"
    target: str = "agent"
    channel: str = "chat"
    metadata: dict[str, Any] = Field(default_factory=dict)
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: float = Field(default_factory=time)


class SecuritySignal(BaseModel):
    detector: str
    category: str
    severity: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str

    @property
    def score(self) -> float:
        return max(0.0, min(1.0, self.severity * self.confidence))


class SecurityDecision(BaseModel):
    message_id: str
    decision: Decision
    risk_level: RiskLevel
    risk_score: float
    signals: list[SecuritySignal]
    sanitized_content: str | None = None
    explanation: str
    policy_reasons: list[str] = Field(default_factory=list)
    recommended_action: str
    latency_ms: float


class BatchScanRequest(BaseModel):
    messages: list[AgentMessage] = Field(min_length=1, max_length=50)


class BatchScanResponse(BaseModel):
    total: int
    decision_counts: dict[str, int]
    average_risk_score: float
    results: list[SecurityDecision]


class WorkflowRequest(BaseModel):
    task: str = Field(min_length=1)


class WorkflowStep(BaseModel):
    agent: str
    input: str
    output: str
    security: SecurityDecision


class WorkflowResponse(BaseModel):
    task: str
    final_answer: str
    blocked: bool
    steps: list[WorkflowStep]
