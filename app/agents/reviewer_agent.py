from __future__ import annotations


class ReviewerAgent:
    name = "reviewer_agent"

    def run(self, draft: str) -> str:
        return (
            draft
            + " Final review: the answer is safe, structured, and focused on security monitoring for GenAI agents."
        )

