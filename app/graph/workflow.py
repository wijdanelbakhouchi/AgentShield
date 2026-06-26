from __future__ import annotations

from app.agents.planner_agent import PlannerAgent
from app.agents.research_agent import ResearchAgent
from app.agents.reviewer_agent import ReviewerAgent
from app.agents.writer_agent import WriterAgent
from app.graph.state import WorkflowState
from app.models.schemas import AgentMessage, WorkflowResponse, WorkflowStep
from app.security.gateway import SecurityGateway


class ProtectedWorkflow:
    """Small LangGraph-style workflow implemented in plain Python for easy learning."""

    def __init__(self, gateway: SecurityGateway | None = None) -> None:
        self.gateway = gateway or SecurityGateway()
        self.agents = [ResearchAgent(), PlannerAgent(), WriterAgent(), ReviewerAgent()]

    def run(self, task: str) -> WorkflowResponse:
        state = WorkflowState(task=task, current_content=task)
        previous = "user"

        for agent in self.agents:
            message = AgentMessage(content=state.current_content, source=previous, target=agent.name)
            allowed, safe_content, security = self.gateway.guarded_content(message)

            if not allowed:
                state.blocked = True
                state.steps.append(
                    WorkflowStep(agent=agent.name, input=state.current_content, output="[blocked]", security=security)
                )
                break

            output = agent.run(safe_content)
            state.steps.append(WorkflowStep(agent=agent.name, input=safe_content, output=output, security=security))
            state.current_content = output
            previous = agent.name

        final_answer = "[blocked by AgentShield]" if state.blocked else state.current_content
        return WorkflowResponse(task=task, final_answer=final_answer, blocked=state.blocked, steps=state.steps)

