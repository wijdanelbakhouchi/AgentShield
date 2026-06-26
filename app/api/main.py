from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.graph.workflow import ProtectedWorkflow
from app.models.schemas import (
    AgentMessage,
    BatchScanRequest,
    BatchScanResponse,
    SecurityDecision,
    WorkflowRequest,
    WorkflowResponse,
)
from app.security.gateway import SecurityGateway
from app.security.monitor import SecurityMonitor


monitor = SecurityMonitor()
gateway = SecurityGateway(monitor=monitor)
workflow = ProtectedWorkflow(gateway=gateway)

app = FastAPI(title="AgentShield Advanced", version="0.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "project": "AgentShield Advanced"}


@app.post("/scan", response_model=SecurityDecision)
def scan(message: AgentMessage) -> SecurityDecision:
    return gateway.inspect(message)


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(request: BatchScanRequest) -> BatchScanResponse:
    results = [gateway.inspect(message) for message in request.messages]
    decision_counts = Counter(result.decision.value for result in results)
    average_risk_score = sum(result.risk_score for result in results) / len(results)
    return BatchScanResponse(
        total=len(results),
        decision_counts=dict(sorted(decision_counts.items())),
        average_risk_score=round(average_risk_score, 4),
        results=results,
    )


@app.post("/workflow/run", response_model=WorkflowResponse)
def run_workflow(request: WorkflowRequest) -> WorkflowResponse:
    return workflow.run(request.task)


@app.get("/monitor/events")
def recent_events(limit: int = 20) -> list[dict[str, Any]]:
    return monitor.recent(limit=limit)


@app.get("/monitor/summary")
def monitor_summary() -> dict[str, Any]:
    return monitor.summary()


@app.get("/benchmark/run")
def run_benchmark() -> dict[str, Any]:
    attack_files = sorted(Path("attacks").glob("*.json"))
    rows = []
    correct = 0
    total = 0

    for attack_file in attack_files:
        cases = json.loads(attack_file.read_text(encoding="utf-8"))
        for case in cases:
            message = AgentMessage(
                content=case["content"],
                source=case.get("source", "user"),
                target=case.get("target", "agent"),
                channel=case.get("channel", "chat"),
                metadata=case.get("metadata", {}),
            )
            result = gateway.inspect(message)
            expected = case["expected_decision"]
            passed = result.decision.value == expected
            correct += int(passed)
            total += 1
            rows.append(
                {
                    "dataset": attack_file.name,
                    "name": case["name"],
                    "expected": expected,
                    "actual": result.decision.value,
                    "risk_score": result.risk_score,
                    "passed": passed,
                }
            )

    return {"accuracy": correct / total if total else 0.0, "correct": correct, "total": total, "results": rows}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.api.main:app", host="127.0.0.1", port=8000, reload=True)
