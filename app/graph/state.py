from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.schemas import WorkflowStep


class WorkflowState(BaseModel):
    task: str
    current_content: str
    blocked: bool = False
    steps: list[WorkflowStep] = Field(default_factory=list)

