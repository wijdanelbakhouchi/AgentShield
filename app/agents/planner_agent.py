from __future__ import annotations


class PlannerAgent:
    name = "planner_agent"

    def run(self, research_notes: str) -> str:
        return (
            "Plan: 1) define the threat, 2) explain the multi-agent risk, "
            "3) describe AgentShield controls, 4) summarize expected experiments. "
            f"Context: {research_notes}"
        )

