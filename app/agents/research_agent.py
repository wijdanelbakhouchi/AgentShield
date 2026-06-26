from __future__ import annotations

from app.tools.search_tool import SearchTool


class ResearchAgent:
    name = "research_agent"

    def __init__(self) -> None:
        self.search_tool = SearchTool()

    def run(self, task: str) -> str:
        sources = self.search_tool.search(task)
        return "Research notes: " + " ".join(sources)

