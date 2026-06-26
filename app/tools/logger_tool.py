from __future__ import annotations

from pathlib import Path


class LoggerTool:
    def __init__(self, path: str = "logs/agent_trace.log") -> None:
        self.path = Path(path)

    def write(self, message: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as file:
            file.write(message + "\n")

