from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from statistics import mean
from threading import Lock
from typing import Any

from app.models.schemas import AgentMessage, SecurityDecision


class SecurityMonitor:
    def __init__(self, path: str = "logs/security_events.jsonl") -> None:
        self.path = Path(path)
        self.lock = Lock()

    def record(self, message: AgentMessage, decision: SecurityDecision) -> None:
        event = {
            "message": message.model_dump(),
            "decision": decision.model_dump(mode="json"),
        }
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(event, ensure_ascii=True) + "\n")

    def recent(self, limit: int = 20) -> list[dict]:
        if not self.path.exists():
            return []
        return self._read_events()[-limit:]

    def summary(self) -> dict[str, Any]:
        events = self._read_events()
        decision_counts: Counter[str] = Counter()
        risk_counts: Counter[str] = Counter()
        category_counts: Counter[str] = Counter()
        latencies: list[float] = []

        for event in events:
            decision = event.get("decision", {})
            decision_counts[str(decision.get("decision", "unknown"))] += 1
            risk_counts[str(decision.get("risk_level", "unknown"))] += 1
            latencies.append(float(decision.get("latency_ms", 0.0)))
            for signal in decision.get("signals", []):
                category_counts[str(signal.get("category", "unknown"))] += 1

        return {
            "total_events": len(events),
            "decision_counts": dict(sorted(decision_counts.items())),
            "risk_counts": dict(sorted(risk_counts.items())),
            "top_categories": dict(category_counts.most_common(8)),
            "average_latency_ms": round(mean(latencies), 3) if latencies else 0.0,
            "latest_event": events[-1] if events else None,
        }

    def _read_events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []

        events: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
