from __future__ import annotations


class WriterAgent:
    name = "writer_agent"

    def run(self, plan: str) -> str:
        return (
            "Draft answer: AgentShield protects AI agent workflows by scanning every message before it reaches "
            "the next agent. It detects prompt injection, role hijacking, data leakage, and tool misuse. "
            f"It follows this plan: {plan}"
        )

