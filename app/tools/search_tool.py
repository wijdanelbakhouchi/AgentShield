from __future__ import annotations


class SearchTool:
    """Offline search tool used for demos without internet access."""

    knowledge_base = {
        "prompt injection": "Prompt injection is an attack where malicious text tries to override trusted AI instructions.",
        "multi-agent": "Multi-agent systems use multiple specialized agents that communicate to solve tasks.",
        "owasp": "OWASP identifies prompt injection as a major risk for LLM applications.",
        "nist": "NIST AI RMF helps teams identify, measure, manage, and govern AI risks.",
    }

    def search(self, query: str) -> list[str]:
        query_lower = query.lower()
        results = []
        for keyword, text in self.knowledge_base.items():
            if keyword in query_lower:
                results.append(text)
        return results or ["No offline source matched. Use a real search API in production."]

