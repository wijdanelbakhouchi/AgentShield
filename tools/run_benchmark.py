from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.schemas import AgentMessage
from app.security.gateway import SecurityGateway


def main() -> None:
    gateway = SecurityGateway()
    attack_files = sorted(Path("attacks").glob("*.json"))
    correct = 0
    total = 0

    for attack_file in attack_files:
        cases = json.loads(attack_file.read_text(encoding="utf-8"))
        print(f"\nDataset: {attack_file.name}")
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
            status = "PASS" if passed else "FAIL"
            print(
                f"{status} {case['name']}: expected={expected} "
                f"actual={result.decision.value} score={result.risk_score:.3f}"
            )

    accuracy = correct / total if total else 0.0
    print(f"\nAccuracy: {accuracy:.2%} ({correct}/{total})")


if __name__ == "__main__":
    main()
